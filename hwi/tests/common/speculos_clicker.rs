//! Approves every Ledger review on a Speculos started outside the test, through its
//! REST API.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::Value;

const POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Screens approved with both buttons. "Approve", "Accept" and "Register account"
/// come from the driver script; "Sign transaction" is the last review screen of app
/// 2.4.6 (`sign_steps` in `common/speculos.rs`).
const APPROVE_WORDS: [&str; 4] = ["Approve", "Accept", "Register account", "Sign transaction"];

/// Port of `clicker()` (devcheck-scripts/ledger_check.py:57-70): walks every review
/// screen right and approves the final one; stopped and joined on drop.
pub struct Clicker {
    screens: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Clicker {
    pub fn spawn(api: SocketAddr) -> Self {
        let screens = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let screens = screens.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // errors are ignored, as the script does
                    if let Some(text) = current_screen(api) {
                        let mut seen = screens.lock().expect("poisoned");
                        if !text.is_empty() && seen.last() != Some(&text) {
                            seen.push(text.clone());
                        }
                        drop(seen);
                        if APPROVE_WORDS.iter().any(|word| text.contains(word))
                            && !text.contains("Reject")
                        {
                            press(api, "both");
                        } else if !text.is_empty()
                            && !text.to_lowercase().contains("ready")
                            && !text.contains("Bitcoin Test")
                        {
                            press(api, "right");
                        }
                    }
                    thread::sleep(POLL_INTERVAL);
                }
            })
        };
        Self {
            screens,
            stop,
            thread: Some(thread),
        }
    }

    /// Every distinct screen text seen, in order.
    pub fn screens(&self) -> Vec<String> {
        self.screens.lock().expect("poisoned").clone()
    }
}

impl Drop for Clicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() && !thread::panicking() {
                panic!("Speculos clicker panicked");
            }
        }
    }
}

/// The texts of the current screen joined with " | ".
fn current_screen(api: SocketAddr) -> Option<String> {
    let body = ureq::get(format!("http://{api}/events?currentscreenonly=true"))
        .call()
        .ok()?
        .body_mut()
        .read_to_string()
        .ok()?;
    let events: Value = serde_json::from_str(&body).ok()?;
    let texts: Vec<&str> = events["events"]
        .as_array()?
        .iter()
        .filter_map(|event| event["text"].as_str())
        .collect();
    Some(texts.join(" | "))
}

fn press(api: SocketAddr, button: &str) {
    let _ = ureq::post(format!("http://{api}/button/{button}"))
        .header("Content-Type", "application/json")
        .send(r#"{"action":"press-and-release"}"#);
}
