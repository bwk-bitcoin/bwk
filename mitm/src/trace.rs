//! Ordered JSONL trace of every attributed wire element. Records sizes and
//! identifiers only, never request or response bodies: record and replay is
//! out of scope for this crate, and bodies would mean writing wallet data to
//! disk.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    sync::Mutex,
    time::Instant,
};

use serde::Serialize;

use crate::{
    error::Error,
    metrics::{ConnId, Direction},
};

#[derive(Debug, Clone, Serialize)]
pub struct TraceEvent {
    pub elapsed_secs: f64,
    pub conn: ConnId,
    pub dir: Direction,
    pub method: Option<String>,
    pub id: Option<String>,
    pub bytes: u64,
}

/// Shared, ordered writer for trace events. Writing locks the underlying
/// buffer only for the duration of one serialize-and-write call, so it never
/// holds a forwarder up for long.
#[derive(Debug)]
pub struct Tracer {
    writer: Mutex<BufWriter<File>>,
    start: Instant,
}

impl Tracer {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let file = File::create(path).map_err(|source| Error::TraceOpen {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            start: Instant::now(),
        })
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Serializes `event` as one JSON object followed by a newline. Logs and
    /// drops the event on a write failure rather than panicking: a broken
    /// trace file must never take the proxy down.
    pub fn write(&self, event: TraceEvent) {
        let mut writer = self.writer.lock().expect("poisoned");
        if let Err(e) = serde_json::to_writer(&mut *writer, &event) {
            log::error!("bwk-mitm: failed to write trace event: {e}");
            return;
        }
        if let Err(e) = writer.write_all(b"\n") {
            log::error!("bwk-mitm: failed to write trace event: {e}");
        }
    }

    pub fn flush(&self) {
        if let Err(e) = self.writer.lock().expect("poisoned").flush() {
            log::error!("bwk-mitm: failed to flush trace file: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, thread, time::Instant};

    use crate::{
        metrics::Direction,
        trace::{TraceEvent, Tracer},
    };

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bwk-mitm-trace-test-{name}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ))
    }

    #[test]
    fn writes_n_well_formed_jsonl_lines() {
        let path = temp_path("basic");
        let tracer = Tracer::new(&path).unwrap();
        for i in 0..5 {
            tracer.write(TraceEvent {
                elapsed_secs: i as f64,
                conn: 1,
                dir: Direction::Up,
                method: Some("server.ping".to_string()),
                id: Some(i.to_string()),
                bytes: 42,
            });
        }
        tracer.flush();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        for (i, line) in lines.iter().enumerate() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["conn"], 1);
            assert_eq!(value["dir"], "up");
            assert_eq!(value["method"], "server.ping");
            assert_eq!(value["id"], i.to_string());
            assert_eq!(value["bytes"], 42);
            assert!(value["elapsed_secs"].is_number());
        }

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn concurrent_writes_do_not_interleave() {
        let path = temp_path("concurrent");
        let tracer = Arc::new(Tracer::new(&path).unwrap());
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let tracer = tracer.clone();
                thread::spawn(move || {
                    for i in 0..20 {
                        tracer.write(TraceEvent {
                            elapsed_secs: 0.0,
                            conn: t,
                            dir: Direction::Down,
                            method: None,
                            id: None,
                            bytes: i,
                        });
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        tracer.flush();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 80);
        for line in lines {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }

        fs::remove_file(&path).unwrap();
    }
}
