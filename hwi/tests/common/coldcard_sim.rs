//! Starts the Coldcard simulator from a firmware checkout and approves what it shows.

use std::{
    env,
    fs::{self, File},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bwk_hwi::{
    coldcard::{api::simulator::SimulatorLink, Coldcard},
    HWI,
};

/// The `unix` directory of a Coldcard firmware checkout with the simulator built.
pub const SIM_UNIX_DIR_ENV: &str = "COLDCARD_SIM_UNIX_DIR";
/// A Python with ckcc-protocol and the simulator requirements.
pub const SIM_PYTHON_ENV: &str = "COLDCARD_SIM_PYTHON";
/// When set, each simulator writes its output to `<dir>/sim-<pid>.log`.
pub const SIM_LOG_DIR_ENV: &str = "COLDCARD_SIM_LOG_DIR";

pub const SEED_A_FINGERPRINT: &str = "73c5da0a";
/// `m/87'/1'/0'` of `SEED_A`.
pub const SEED_A_BIP87_TPUB: &str = "tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWxfTkA6bHNJ3CHUEtALQdkNeixNz4446PcAmw4WKcj3mV2vb29H7sg9EPzbyCU1y2merw";

const START_TIMEOUT: Duration = Duration::from_secs(90);
const REGISTERED_TIMEOUT: Duration = Duration::from_secs(10);
const START_POLL_INTERVAL: Duration = Duration::from_millis(500);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const APPROVER_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// The simulator answers the last sender, so a story poll landing inside a
/// multi-packet upload of the device link breaks both links. The approver waits
/// this long before its first poll, for the upload the caller starts right after
/// spawning it (enroll payload, PSBT) to finish.
const APPROVER_UPLOAD_GRACE: Duration = Duration::from_secs(1);
/// ckcc-protocol's `cap_story`, short enough for one packet.
const CAP_STORY: &str = "RV.write('\\0'.join(sim_display.story or[]).encode())";

/// A simulator this test process started; killed (process group) on drop.
pub struct SimProcess {
    child: Child,
    seed: String,
    socket: PathBuf,
}

impl SimProcess {
    /// Starts `simulator.py --eff --headless --segregate --seed <seed>` from
    /// $COLDCARD_SIM_UNIX_DIR with SDL_VIDEODRIVER=dummy, in its own process
    /// group; waits (up to 90 s) until the socket exists and a
    /// `Coldcard::connect_simulator` + `get_master_fingerprint` succeed.
    pub fn start(seed: &str) -> Self {
        let (Some(unix_dir), Some(python)) =
            (env::var_os(SIM_UNIX_DIR_ENV), env::var_os(SIM_PYTHON_ENV))
        else {
            panic!("set {SIM_UNIX_DIR_ENV} (firmware unix dir) and {SIM_PYTHON_ENV} (its python) to run the Coldcard simulator tests");
        };
        let log_dir = env::var_os(SIM_LOG_DIR_ENV).map(PathBuf::from);
        let pending_log = log_dir
            .as_ref()
            .map(|dir| dir.join(format!("sim-starting-{}.log", std::process::id())));
        let (stdout, stderr) = match &pending_log {
            Some(path) => {
                let file = File::create(path).unwrap();
                (Stdio::from(file.try_clone().unwrap()), Stdio::from(file))
            }
            None => (Stdio::null(), Stdio::null()),
        };
        let child = Command::new(python)
            .current_dir(unix_dir)
            .env("SDL_VIDEODRIVER", "dummy")
            .args([
                "simulator.py",
                "--eff",
                "--headless",
                "--segregate",
                "--seed",
                seed,
            ])
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .unwrap();
        if let (Some(dir), Some(pending)) = (&log_dir, &pending_log) {
            fs::rename(pending, dir.join(format!("sim-{}.log", child.id()))).unwrap();
        }
        let socket = PathBuf::from(format!("/tmp/ckcc-simulator-{}.sock", child.id()));
        let mut sim = Self {
            child,
            seed: seed.to_owned(),
            socket,
        };
        sim.wait_ready();
        sim
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Kills and starts again with the same seed (new pid, new socket).
    pub fn restart(&mut self) {
        self.stop();
        *self = Self::start(&self.seed);
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("Coldcard simulator exited early: {status}");
            }
            if self.socket.exists()
                && Coldcard::connect_simulator(&self.socket)
                    .and_then(|cc| cc.get_master_fingerprint())
                    .is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Coldcard simulator not ready after {START_TIMEOUT:?}"
            );
            thread::sleep(START_POLL_INTERVAL);
        }
    }

    fn stop(&mut self) {
        let group = format!("-{}", self.child.id());
        let _ = Command::new("kill")
            .args(["-TERM", &group])
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + STOP_TIMEOUT;
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        // the simulator's own children (micropython) share the group
        let _ = Command::new("kill")
            .args(["-KILL", &group])
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir_all(format!("/tmp/cc-simulators/{}", self.child.id()));
    }
}

impl Drop for SimProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Presses 'y' on every story the simulator shows while running, records each
/// (title, body) seen; stopped and joined on drop.
pub struct Approver {
    stories: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Approver {
    pub fn spawn(socket: &Path) -> Self {
        let mut link = SimulatorLink::connect(socket).unwrap();
        let stories = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stories = stories.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                thread::sleep(APPROVER_UPLOAD_GRACE);
                let mut previous = None;
                while !stop.load(Ordering::Relaxed) {
                    let story = parse_story(&link.exec(CAP_STORY).unwrap());
                    if story.is_some() && story != previous {
                        stories
                            .lock()
                            .expect("poisoned")
                            .push(story.clone().unwrap());
                        link.keypress("y").unwrap();
                    }
                    previous = story;
                    thread::sleep(APPROVER_POLL_INTERVAL);
                }
            })
        };
        Self {
            stories,
            stop,
            thread: Some(thread),
        }
    }

    pub fn stories(&self) -> Vec<(String, String)> {
        self.stories.lock().expect("poisoned").clone()
    }
}

impl Drop for Approver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() && !thread::panicking() {
                panic!("Coldcard simulator approver panicked");
            }
        }
    }
}

/// Enrolls `policy` as `name` with an approver running, waits (up to 10 s) until it
/// is listed and returns the device bound to it.
pub fn enroll(socket: &Path, coldcard: Coldcard, name: &str, policy: &str) -> Coldcard {
    let approver = Approver::spawn(socket);
    assert_eq!(coldcard.register_wallet(name, policy).unwrap(), None);
    let deadline = Instant::now() + REGISTERED_TIMEOUT;
    while !matches!(coldcard.is_wallet_registered(name, policy), Ok(true)) {
        assert!(
            Instant::now() < deadline,
            "{name} not registered after {REGISTERED_TIMEOUT:?}"
        );
        thread::sleep(Duration::from_millis(500));
    }
    let stories = approver.stories();
    println!("stories seen while enrolling: {stories:#?}");
    assert!(stories
        .iter()
        .any(|(title, body)| title.contains("miniscript") || body.contains("miniscript")));
    coldcard.with_wallet_name(name.to_owned())
}

/// `title\0body` as `cap_story` writes it; `None` when no story is shown.
fn parse_story(raw: &[u8]) -> Option<(String, String)> {
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(raw);
    let (title, body) = text.split_once('\0').unwrap_or((&text, ""));
    Some((title.to_owned(), body.to_owned()))
}
