//! In-memory + on-disk audit log shared by the admin console and the proxy listeners.
//!
//! Records security-relevant events (admin logins, token/rule changes, kicks,
//! reloads, password changes) and tunnel connection events (which public IP
//! reached which proxy service).
//!
//! Every entry is appended to `<data_dir>/audit.log` (JSON Lines) and also kept
//! in a fixed-capacity in-memory ring buffer, surfaced through
//! `GET /api/audit?page=&page_size=` with pagination.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::common::crypto::now_millis;

/// Maximum number of audit entries kept in memory (ring buffer).
pub const AUDIT_LOG_CAP: usize = 500;

/// Audit log file name inside the data directory.
const AUDIT_FILE_NAME: &str = "audit.log";

/// A single audit entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Event time (ms since epoch).
    pub ts_ms: u64,
    /// Event type, e.g. `login`, `proxy_connect`, `kick`, `reload`.
    pub action: String,
    /// Human-readable detail.
    pub detail: String,
    /// Client IP that triggered the event.
    pub ip: String,
}

/// Thread-safe audit log: ring buffer + append-only JSONL file.
pub struct AuditLog {
    entries: Mutex<VecDeque<AuditEntry>>,
    /// Append handle for persistence; `None` when the file could not be opened
    /// (the log then keeps working in-memory only).
    file: Mutex<Option<File>>,
}

impl AuditLog {
    /// Creates the log, loading the tail of an existing `<data_dir>/audit.log`.
    pub fn new(data_dir: &str) -> Self {
        let _ = std::fs::create_dir_all(data_dir);
        let path = PathBuf::from(data_dir).join(AUDIT_FILE_NAME);

        // Load existing history (tail only) so the ring buffer survives restarts
        let mut entries: VecDeque<AuditEntry> = VecDeque::new();
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(e) = serde_json::from_str::<AuditEntry>(&line) {
                    if entries.len() >= AUDIT_LOG_CAP {
                        entries.pop_front();
                    }
                    entries.push_back(e);
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();

        Self {
            entries: Mutex::new(entries),
            file: Mutex::new(file),
        }
    }

    /// Appends an entry: persists it to disk and pushes into the ring buffer,
    /// dropping the oldest once the cap is reached.
    pub fn record(&self, ip: &str, action: &str, detail: &str) {
        let entry = AuditEntry {
            ts_ms: now_millis(),
            action: action.to_string(),
            detail: detail.to_string(),
            ip: ip.to_string(),
        };

        if let Some(f) = self.file.lock().unwrap().as_mut() {
            if let Ok(line) = serde_json::to_string(&entry) {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }

        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= AUDIT_LOG_CAP {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Returns all in-memory entries, newest first.
    pub fn snapshot(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().iter().rev().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot_newest_first() {
        let dir = std::env::temp_dir().join(format!("zorv-audit-test-{}", std::process::id()));
        let log = AuditLog::new(&dir.to_string_lossy());
        log.record("1.1.1.1", "login", "ok");
        log.record("2.2.2.2", "proxy_connect", "proxy=web target=127.0.0.1:80");
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].action, "proxy_connect");
        assert_eq!(snap[0].ip, "2.2.2.2");
        assert_eq!(snap[1].action, "login");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_from_disk() {
        let dir = std::env::temp_dir().join(format!("zorv-audit-reload-{}", std::process::id()));
        {
            let log = AuditLog::new(&dir.to_string_lossy());
            log.record("3.3.3.3", "kick", "client_id=x");
        }
        // A new instance must load the persisted entry
        let log = AuditLog::new(&dir.to_string_lossy());
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].action, "kick");
        std::fs::remove_dir_all(&dir).ok();
    }
}
