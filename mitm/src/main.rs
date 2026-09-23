//! Command-line front end for the counting MITM proxy: binds a local port,
//! forwards to a real Electrum server, and prints a report on an interval
//! and/or on shutdown.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use bwk_mitm::{
    bind,
    error::Error,
    report::{render_json, render_table},
    trace::Tracer,
    Upstream,
};

const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(unix)]
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Table,
    Json,
}

#[derive(Debug, PartialEq)]
struct Config {
    listen: SocketAddr,
    upstream: String,
    tls: bool,
    verify_cert: bool,
    format: Format,
    report: Option<PathBuf>,
    interval: Option<Duration>,
    trace: Option<PathBuf>,
}

fn usage() -> &'static str {
    "bwk-mitm - counting MITM proxy for the Electrum protocol

USAGE:
    bwk-mitm --listen <addr:port> --upstream <host:port> [OPTIONS]

OPTIONS:
    --tls                    connect to the upstream over TLS
    --no-verify-cert         skip certificate and hostname verification (TLS only)
    --format <table|json>    output format (default: table)
    --report <path>          also write the final report here
    --interval <secs>        print a live report every N seconds
    --trace <path>           write a JSONL trace of every attributed element here
    -h, --help               print this help
"
}

/// Validates a `host:port` string without resolving it, so bad input is
/// rejected without a DNS lookup at parse time.
fn validate_host_port(s: &str) -> Result<(), String> {
    let idx = s
        .rfind(':')
        .ok_or_else(|| format!("invalid address: {s}"))?;
    let (host, port) = (&s[..idx], &s[idx + 1..]);
    if host.is_empty() {
        return Err(format!("invalid address: {s}"));
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid address: {s}"))?;
    Ok(())
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut listen: Option<SocketAddr> = None;
    let mut upstream: Option<String> = None;
    let mut tls = false;
    let mut verify_cert = true;
    let mut format = Format::Table;
    let mut report: Option<PathBuf> = None;
    let mut interval: Option<Duration> = None;
    let mut trace: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                let v = args.next().ok_or("--listen requires a value")?;
                listen = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --listen address: {v}"))?,
                );
            }
            "--upstream" => {
                let v = args.next().ok_or("--upstream requires a value")?;
                validate_host_port(&v)?;
                upstream = Some(v);
            }
            "--tls" => {
                tls = true;
            }
            "--no-verify-cert" => {
                verify_cert = false;
            }
            "--format" => {
                let v = args.next().ok_or("--format requires a value")?;
                format = match v.as_str() {
                    "table" => Format::Table,
                    "json" => Format::Json,
                    other => return Err(format!("invalid --format: {other}")),
                };
            }
            "--report" => {
                let v = args.next().ok_or("--report requires a value")?;
                report = Some(PathBuf::from(v));
            }
            "--interval" => {
                let v = args.next().ok_or("--interval requires a value")?;
                let secs: u64 = v.parse().map_err(|_| format!("invalid --interval: {v}"))?;
                interval = Some(Duration::from_secs(secs));
            }
            "--trace" => {
                let v = args.next().ok_or("--trace requires a value")?;
                trace = Some(PathBuf::from(v));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let listen = listen.ok_or("--listen is required")?;
    let upstream = upstream.ok_or("--upstream is required")?;

    Ok(Config {
        listen,
        upstream,
        tls,
        verify_cert,
        format,
        report,
        interval,
        trace,
    })
}

#[cfg(unix)]
extern "C" fn handle_sigint(_signum: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_sigint_handler() {
    unsafe {
        libc::signal(libc::SIGINT, handle_sigint as libc::sighandler_t);
    }
}

#[cfg(unix)]
fn stop_requested() -> bool {
    SIGINT_RECEIVED.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn install_sigint_handler() {}

#[cfg(not(unix))]
fn stop_requested() -> bool {
    false
}

fn run(config: Config) -> Result<(), Error> {
    let upstream = if config.tls {
        Upstream::Tls {
            target: config.upstream,
            verify_cert: config.verify_cert,
        }
    } else {
        Upstream::Plain(config.upstream)
    };
    let tracer = config
        .trace
        .as_deref()
        .map(Tracer::new)
        .transpose()?
        .map(Arc::new);
    let mitm = bind(config.listen, upstream, tracer)?;
    println!("bwk-mitm listening on {}", mitm.local_addr());

    install_sigint_handler();

    let interval_handle = config.interval.map(|interval| {
        let metrics = mitm.metrics();
        thread::spawn(move || {
            let mut elapsed = Duration::ZERO;
            while !stop_requested() {
                thread::sleep(POLL_INTERVAL);
                elapsed += POLL_INTERVAL;
                if elapsed >= interval {
                    elapsed = Duration::ZERO;
                    let snapshot = metrics.snapshot();
                    println!("{}", render_table(&snapshot));
                }
            }
        })
    });

    while !stop_requested() {
        thread::sleep(POLL_INTERVAL);
    }

    let snapshot = mitm.metrics().snapshot();
    let report = match config.format {
        Format::Table => render_table(&snapshot),
        Format::Json => render_json(&snapshot)?,
    };
    println!("{report}");
    if let Some(path) = &config.report {
        std::fs::write(path, &report)?;
    }

    mitm.shutdown();
    if let Some(handle) = interval_handle {
        let _ = handle.join();
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", usage());
        return;
    }

    let config = match parse_args(args.into_iter()) {
        Ok(config) => config,
        Err(e) => {
            eprint!("error: {e}\n\n{}", usage());
            std::process::exit(1);
        }
    };

    if let Err(e) = run(config) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{parse_args, Format};

    fn args(v: &[&str]) -> impl Iterator<Item = String> {
        v.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn full_argument_set() {
        let config = parse_args(args(&[
            "--listen",
            "127.0.0.1:50001",
            "--upstream",
            "electrum.example.org:50002",
            "--format",
            "json",
            "--report",
            "/tmp/report.txt",
            "--interval",
            "5",
            "--trace",
            "/tmp/trace.jsonl",
        ]))
        .unwrap();

        assert_eq!(config.listen, "127.0.0.1:50001".parse().unwrap());
        assert_eq!(config.upstream, "electrum.example.org:50002");
        assert_eq!(config.format, Format::Json);
        assert_eq!(config.report, Some("/tmp/report.txt".into()));
        assert_eq!(config.interval, Some(Duration::from_secs(5)));
        assert_eq!(config.trace, Some("/tmp/trace.jsonl".into()));
    }

    #[test]
    fn trace_flag_sets_path() {
        let config = parse_args(args(&[
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "127.0.0.1:50002",
            "--trace",
            "/tmp/trace.jsonl",
        ]))
        .unwrap();

        assert_eq!(config.trace, Some("/tmp/trace.jsonl".into()));
    }

    #[test]
    fn defaults_applied_when_optional_flags_absent() {
        let config = parse_args(args(&[
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "127.0.0.1:50002",
        ]))
        .unwrap();

        assert_eq!(config.format, Format::Table);
        assert_eq!(config.report, None);
        assert_eq!(config.interval, None);
        assert_eq!(config.trace, None);
        assert!(!config.tls);
        assert!(config.verify_cert);
    }

    #[test]
    fn tls_flag_enables_tls_upstream() {
        let config = parse_args(args(&[
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "electrum.example.org:50002",
            "--tls",
        ]))
        .unwrap();

        assert!(config.tls);
        assert!(config.verify_cert);
    }

    #[test]
    fn no_verify_cert_flag_disables_verification() {
        let config = parse_args(args(&[
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "electrum.example.org:50002",
            "--tls",
            "--no-verify-cert",
        ]))
        .unwrap();

        assert!(config.tls);
        assert!(!config.verify_cert);
    }

    #[test]
    fn missing_required_flag_is_an_error() {
        let err = parse_args(args(&["--upstream", "127.0.0.1:50002"])).unwrap_err();
        assert!(err.contains("--listen"));
    }

    #[test]
    fn unknown_flag_is_an_error() {
        let err = parse_args(args(&[
            "--listen",
            "127.0.0.1:50001",
            "--upstream",
            "127.0.0.1:50002",
            "--bogus",
        ]))
        .unwrap_err();
        assert!(err.contains("--bogus"));
    }

    #[test]
    fn bad_listen_address_is_an_error() {
        let err = parse_args(args(&[
            "--listen",
            "not-an-address",
            "--upstream",
            "127.0.0.1:50002",
        ]))
        .unwrap_err();
        assert!(err.contains("--listen"));
    }

    #[test]
    fn bad_upstream_address_is_an_error() {
        let err = parse_args(args(&[
            "--listen",
            "127.0.0.1:50001",
            "--upstream",
            "no-port-here",
        ]))
        .unwrap_err();
        assert!(err.contains("invalid address"));
    }

    #[test]
    fn bad_format_value_is_an_error() {
        let err = parse_args(args(&[
            "--listen",
            "127.0.0.1:50001",
            "--upstream",
            "127.0.0.1:50002",
            "--format",
            "yaml",
        ]))
        .unwrap_err();
        assert!(err.contains("--format"));
    }

    #[test]
    fn non_numeric_interval_is_an_error() {
        let err = parse_args(args(&[
            "--listen",
            "127.0.0.1:50001",
            "--upstream",
            "127.0.0.1:50002",
            "--interval",
            "soon",
        ]))
        .unwrap_err();
        assert!(err.contains("--interval"));
    }
}
