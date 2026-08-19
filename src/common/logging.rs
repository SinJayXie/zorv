//! Logging initialization shared by the `zorv` and `zorvd` binaries.
//!
//! Logs are written to stdout and, unless the configured output is the special
//! value `"stdout"`, also appended to a log file (e.g. `./app.log`).

use std::io::Write;
use std::sync::Mutex;

use tracing_subscriber::EnvFilter;

/// A writer that mirrors every log line to an optional file and to stdout.
struct DualWriter {
    file: Option<std::fs::File>,
}

impl DualWriter {
    fn new(output: &str) -> Self {
        let file = if output == "stdout" {
            None
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(output)
                .ok()
        };
        Self { file }
    }
}

impl Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(f) = &mut self.file {
            // A file write failure must not break the process; stdout is the
            // primary channel and still receives the log line.
            let _ = f.write(buf);
        }
        std::io::stdout().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(f) = &mut self.file {
            let _ = f.flush();
        }
        std::io::stdout().flush()
    }
}

/// Initializes the global `tracing` subscriber.
///
/// `level` is the default log level (e.g. `"info"`); `output` is `"stdout"` for
/// console-only logging or a file path such as `"./app.log"` to also persist
/// logs to disk. The `RUST_LOG` environment variable takes precedence over both.
pub fn init(level: &str, output: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(Mutex::new(DualWriter::new(output)))
        .init();
}
