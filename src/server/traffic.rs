//! Client traffic statistics with disk persistence.
//!
//! Each tunnel session accumulates TCP/UDP upstream/downstream bytes in real time; on session close, [`TrafficTracker::merge`]
//! merges them into a per-`client_id` cumulative table, which is serialized to JSON and written to disk periodically ([`SAVE_INTERVAL`]);
//! after a server restart, cumulative data is restored via [`TrafficTracker::load`].
//!
//! A time-series history ([`TrafficTracker::sample`]) is also maintained: every [`SAMPLE_INTERVAL`], a snapshot of each client's
//! cumulative traffic (plus live online traffic) is recorded, keeping the most recent [`HISTORY_POINTS`] points,
//! for the admin UI to draw traffic curves.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::common::crypto::now_millis;

/// Disk save interval: 60 seconds.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(60);
/// Time-series sample interval: 30 seconds.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
/// Number of history sample points retained (about 100 minutes).
pub const HISTORY_POINTS: usize = 200;

/// Cumulative traffic of a single client (bytes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficCounter {
    /// TCP upstream (client → server → public).
    pub tcp_up: u64,
    /// TCP downstream (public → server → client).
    pub tcp_down: u64,
    /// UDP upstream (client → server → public).
    pub udp_up: u64,
    /// UDP downstream (public → server → client).
    pub udp_down: u64,
}

impl TrafficCounter {
    /// Whether all values are zero (zero deltas are not added to the cumulative table).
    pub fn is_zero(&self) -> bool {
        self.tcp_up == 0 && self.tcp_down == 0 && self.udp_up == 0 && self.udp_down == 0
    }
}

/// A single time-series sample: each client's cumulative traffic at a point in time (including live online amounts).
#[derive(Debug, Clone, Serialize)]
pub struct HistorySample {
    pub ts_ms: u64,
    pub totals: HashMap<String, TrafficCounter>,
}

/// Traffic statistics tracker: `client_id → cumulative traffic`, supporting merge, snapshot, time-series sampling, and JSON persistence.
pub struct TrafficTracker {
    totals: RwLock<HashMap<String, TrafficCounter>>,
    history: RwLock<VecDeque<HistorySample>>,
    path: PathBuf,
}

impl TrafficTracker {
    /// Loads cumulative traffic from `data_dir` (treated as empty if the file is missing).
    pub fn load(data_dir: &str) -> Self {
        let path = PathBuf::from(data_dir).join("traffic.json");
        let totals = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<HashMap<String, TrafficCounter>>(&bytes) {
                Ok(m) => {
                    info!("traffic stats loaded from {}", path.display());
                    m
                }
                Err(e) => {
                    warn!("parse traffic stats {} failed: {}", path.display(), e);
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Self {
            totals: RwLock::new(totals),
            history: RwLock::new(VecDeque::new()),
            path,
        }
    }

    /// Merges a session's traffic delta (called when the session closes).
    pub fn merge(&self, client_id: &str, delta: &TrafficCounter) {
        if delta.is_zero() {
            return;
        }
        let mut totals = self.totals.write().unwrap();
        let e = totals.entry(client_id.to_string()).or_default();
        e.tcp_up += delta.tcp_up;
        e.tcp_down += delta.tcp_down;
        e.udp_up += delta.udp_up;
        e.udp_down += delta.udp_down;
    }

    /// Cumulative traffic snapshot (excluding live deltas of online sessions; the caller overlays live amounts separately).
    pub fn snapshot(&self) -> HashMap<String, TrafficCounter> {
        self.totals.read().unwrap().clone()
    }

    /// Time-series sampling: appends a history point using the current cumulative values (plus the caller-provided live online traffic).
    /// Drops the oldest point when exceeding [`HISTORY_POINTS`].
    pub fn sample(&self, online: &HashMap<String, TrafficCounter>) {
        let mut totals = self.totals.read().unwrap().clone();
        for (cid, d) in online {
            let e = totals.entry(cid.clone()).or_default();
            e.tcp_up += d.tcp_up;
            e.tcp_down += d.tcp_down;
            e.udp_up += d.udp_up;
            e.udp_down += d.udp_down;
        }
        let mut history = self.history.write().unwrap();
        if history.len() >= HISTORY_POINTS {
            history.pop_front();
        }
        history.push_back(HistorySample {
            ts_ms: now_millis(),
            totals,
        });
    }

    /// Returns all time-series history points (in ascending time order).
    pub fn history(&self) -> Vec<HistorySample> {
        self.history.read().unwrap().iter().cloned().collect()
    }

    /// Persists to disk (JSON). Failures only log a warning and do not affect operation.
    pub fn save(&self) {
        let totals = self.totals.read().unwrap();
        let json = match serde_json::to_string_pretty(&*totals) {
            Ok(s) => s,
            Err(e) => {
                warn!("serialize traffic stats failed: {}", e);
                return;
            }
        };
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    warn!("create traffic data dir failed: {}", e);
                    return;
                }
            }
        }
        if let Err(e) = std::fs::write(&self.path, json) {
            warn!("write traffic stats {} failed: {}", self.path.display(), e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_accumulates_and_ignores_zero() {
        let tracker = TrafficTracker::load(&std::env::temp_dir().to_string_lossy());
        tracker.merge(
            "c1",
            &TrafficCounter {
                tcp_up: 100,
                tcp_down: 50,
                udp_up: 10,
                udp_down: 20,
            },
        );
        tracker.merge(
            "c1",
            &TrafficCounter {
                tcp_up: 1,
                tcp_down: 1,
                udp_up: 0,
                udp_down: 0,
            },
        );
        tracker.merge("c2", &TrafficCounter::default());

        let snap = tracker.snapshot();
        let c1 = snap.get("c1").unwrap();
        assert_eq!(c1.tcp_up, 101);
        assert_eq!(c1.tcp_down, 51);
        assert_eq!(c1.udp_up, 10);
        assert_eq!(c1.udp_down, 20);
        assert!(!snap.contains_key("c2"), "zero delta must not be recorded");
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("zorv-traffic-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tracker = TrafficTracker::load(dir.to_str().unwrap());
        tracker.merge(
            "c1",
            &TrafficCounter {
                tcp_up: 999,
                tcp_down: 888,
                udp_up: 777,
                udp_down: 666,
            },
        );
        tracker.save();

        let loaded = TrafficTracker::load(dir.to_str().unwrap());
        let c1 = loaded.snapshot().get("c1").unwrap().clone();
        assert_eq!(c1.tcp_up, 999);
        assert_eq!(c1.tcp_down, 888);
        assert_eq!(c1.udp_up, 777);
        assert_eq!(c1.udp_down, 666);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sample_appends_history_with_online_and_bounds() {
        let tracker = TrafficTracker::load(&std::env::temp_dir().to_string_lossy());
        tracker.merge(
            "c1",
            &TrafficCounter {
                tcp_up: 100,
                tcp_down: 0,
                udp_up: 0,
                udp_down: 0,
            },
        );

        // Sample (with live online traffic)
        let online = HashMap::from([(
            "c1".to_string(),
            TrafficCounter {
                tcp_up: 5,
                tcp_down: 1,
                udp_up: 0,
                udp_down: 0,
            },
        )]);
        tracker.sample(&online);
        let hist = tracker.history();
        assert_eq!(hist.len(), 1);
        let s = &hist[0];
        assert_eq!(s.totals["c1"].tcp_up, 105);
        assert_eq!(s.totals["c1"].tcp_down, 1);

        // Second sample: online delta changed
        let online = HashMap::from([(
            "c1".to_string(),
            TrafficCounter {
                tcp_up: 20,
                tcp_down: 0,
                udp_up: 0,
                udp_down: 0,
            },
        )]);
        tracker.sample(&online);
        assert_eq!(tracker.history().len(), 2);
        assert_eq!(tracker.history()[1].totals["c1"].tcp_up, 120);

        // Upper-bound trimming: once HISTORY_POINTS is full, the oldest point is dropped
        for _ in 0..HISTORY_POINTS {
            tracker.sample(&HashMap::new());
        }
        assert_eq!(tracker.history().len(), HISTORY_POINTS);
    }
}
