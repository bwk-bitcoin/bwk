//! Silent Payments sync throughput benchmark.
//!
//! Two builds, selected by cargo feature:
//!
//! - default (`--features bench`): drives the real `bwk_sp::account::Account` OneShot
//!   scan (the production path, zero instrumentation) and reports headline
//!   timing only (blocks scanned, elapsed, blocks/sec, ms/block) from the
//!   account's scan notifications.
//! - `--features instrumentation`: the instrumented harness that drives the
//!   local BWK-SP scan path, timing the per-block match work, the
//!   per-block data volume, the per-phase breakdown via `profiling`, and
//!   auto-saving each run to JSON for the `plot` subcommand.
//!
//! A fixed dummy watch-only key is used: sync cost is independent of whether
//! the wallet actually owns any outputs.
//!
//! Run with `--help` for usage.

#[cfg(not(feature = "instrumentation"))]
use std::time::{Duration, Instant};

use bwk_sp::bitcoin;
#[cfg(not(feature = "instrumentation"))]
use bwk_sp::bwk::bwk_electrum::notification::{Notification, SpNotification};

/// How often a progress line is printed.
const PRINT_INTERVAL_SECS: f64 = 1.0;

/// Default dust limit in sats applied when `--dust-limit` is not given.
const DEFAULT_DUST_LIMIT_SATS: u64 = 600;

/// Dummy spend public key (watch-only): the secp256k1 generator point G.
const DUMMY_SPEND_PUBKEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Format a duration in seconds as a compact `HhMMmSSs` / `MmSSs` / `SSs` string.
fn fmt_dur(secs: f64) -> String {
    let total = secs.round() as u64;
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// Minimum birthday height per network, mirroring `Config::min_birthday_height`.
fn min_birthday_for(network: bitcoin::Network) -> u32 {
    match network {
        bitcoin::Network::Bitcoin => 709_632,
        _ => 1,
    }
}

struct Args {
    url: String,
    network: bitcoin::Network,
    start: Option<u32>,
    end: Option<u32>,
    dust_limits: Vec<u64>,
}

fn parse_network(s: &str) -> Result<bitcoin::Network, String> {
    match s {
        "bitcoin" | "mainnet" => Ok(bitcoin::Network::Bitcoin),
        "signet" => Ok(bitcoin::Network::Signet),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(format!("unknown network: {other}")),
    }
}

/// Parse CLI args and environment. Returns `Ok(None)` if `--help` was given
/// (caller should exit 0).
fn parse_args() -> Result<Option<Args>, String> {
    let mut url = std::env::var("BWK_SP_BLINDBIT_URL").ok();
    let mut network_str = std::env::var("BWK_SP_NETWORK").ok();
    let mut start: Option<u32> = None;
    let mut end: Option<u32> = None;
    let mut dust_limits: Vec<u64> = vec![DEFAULT_DUST_LIMIT_SATS];

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--url" => {
                url = Some(args.next().ok_or("--url requires a value")?);
            }
            "--network" => {
                network_str = Some(args.next().ok_or("--network requires a value")?);
            }
            "--start" => {
                let v = args.next().ok_or("--start requires a value")?;
                start = Some(v.parse().map_err(|_| format!("invalid --start: {v}"))?);
            }
            "--end" => {
                let v = args.next().ok_or("--end requires a value")?;
                end = Some(v.parse().map_err(|_| format!("invalid --end: {v}"))?);
            }
            "--dust-limit" => {
                let v = args.next().ok_or("--dust-limit requires a value")?;
                dust_limits = v
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse::<u64>()
                            .map_err(|_| format!("invalid --dust-limit: {v}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if dust_limits.is_empty() {
                    return Err(format!("invalid --dust-limit: {v}"));
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let url = url.ok_or("--url (or env BWK_SP_BLINDBIT_URL) is required")?;
    let network = match network_str {
        Some(s) => parse_network(&s)?,
        None => bitcoin::Network::Bitcoin,
    };

    // The HTTP client requires a scheme; default to http:// if none given.
    let url = if url.contains("://") {
        url
    } else {
        format!("http://{url}")
    };

    Ok(Some(Args {
        url,
        network,
        start,
        end,
        dust_limits,
    }))
}

fn usage() -> String {
    let body = "sp_sync_bench - benchmark Silent Payments sync throughput

USAGE:
    sp_sync_bench [OPTIONS]

OPTIONS:
    --url <URL>              Blindbit oracle URL. REQUIRED.
                             (or env BWK_SP_BLINDBIT_URL)
    --network <NET>          bitcoin | signet | testnet | regtest.
                             Default: bitcoin. (or env BWK_SP_NETWORK)
                             Must match the network the oracle serves.
    --start <HEIGHT>         First block height to scan. Default: network birthday.
    --end <HEIGHT>           Last block height to scan. Default: chain tip.
    --dust-limit <SATS>      Comma-separated list of dust limits in sats; one
                             full bench (one saved file) is run per value, e.g.
                             --dust-limit 0,300,600. Default: 600. A value of 0
                             disables the filter for that bench.
    -h, --help               Print this help and exit.
";
    format!("{body}{}", mode_usage())
}

// ---------------------------------------------------------------------------
// Instrumented build (`--features instrumentation`)
// ---------------------------------------------------------------------------

#[cfg(feature = "instrumentation")]
mod instrumented {
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    use bwk_sp::{
        bitcoin,
        receiver::{
            error::Error as SpError, BlockData, OutputSpendStatus, OwnedOutput, SpReceiver,
            SpendKey,
        },
        scan::{scan_blocks_with_observer, ScanRuntimeConfig, ScanStores},
    };
    use plotters::prelude::*;
    use serde::{Deserialize, Serialize};

    use super::{
        fmt_dur, min_birthday_for, parse_args, usage, DUMMY_SPEND_PUBKEY, PRINT_INTERVAL_SECS,
    };

    /// Number of height buckets in the per-range tweak breakdown.
    const BUCKETS: usize = 20;

    /// Trailing window over which the instantaneous rates are averaged.
    const WINDOW_SECS: f64 = 10.0;

    /// Gitignored directory (relative to cwd) where each bench run auto-saves its
    /// data, and where `plot` reads every run back from.
    const BENCH_DIR: &str = "bench_data";

    /// Default smoothing window for `plot`, as a percentage of the x range. The plot
    /// is meant to show a trend, not an accurate per-block curve; 0 disables it.
    const DEFAULT_SMOOTH_PCT: usize = 10;

    /// A point-in-time progress snapshot, used to compute trailing-window rates.
    struct Sample {
        t: Instant,
        processed: u64,
        tweaks: u64,
    }

    /// Per-block receive-pass stats captured as block data streams through the
    /// recording backend, shared between the scan thread and the progress poller.
    #[derive(Default)]
    struct ReceiveStats {
        records: Vec<BlockRecord>,
        total_tweaks: u64,
        total_utxo_bytes: u64,
        max_tweaks: usize,
        max_tweaks_height: u32,
    }

    /// Stroke colors cycled across plotted series (blue/red/green/purple/orange/cyan).
    const PALETTE: [RGBColor; 6] = [
        RGBColor(0x1f, 0x77, 0xb4),
        RGBColor(0xd6, 0x27, 0x28),
        RGBColor(0x2c, 0xa0, 0x2c),
        RGBColor(0x94, 0x67, 0xbd),
        RGBColor(0xff, 0x7f, 0x0e),
        RGBColor(0x17, 0xbe, 0xcf),
    ];

    /// Persisted bench data auto-saved into `BENCH_DIR` and read back by `plot`.
    ///
    /// `timing` and `host` carry `#[serde(default)]` so runs saved before those
    /// fields existed still parse.
    #[derive(Serialize, Deserialize)]
    struct BenchData {
        config: BenchConfig,
        #[serde(default)]
        timing: Timing,
        #[serde(default)]
        host: HostInfo,
        blocks: Vec<BlockRecord>,
    }

    /// Wall-time breakdown of a run, in seconds.
    #[derive(Serialize, Deserialize, Default)]
    struct Timing {
        elapsed_secs: f64,
        fetch_secs: f64,
        process_secs: f64,
    }

    /// Best-effort host CPU/RAM info. Fields are `None` when unavailable (e.g. on a
    /// platform without `/proc`).
    #[derive(Serialize, Deserialize, Default)]
    struct HostInfo {
        cpu_model: Option<String>,
        cores: Option<usize>,
        ram_bytes: Option<u64>,
    }

    /// The resolved run parameters that produced a `BenchData`.
    #[derive(Serialize, Deserialize)]
    struct BenchConfig {
        network: String,
        url: String,
        start: u32,
        end: u32,
        dust_limit: Option<u64>,
        cutthrough: bool,
    }

    /// Per-block raw data volume.
    ///
    /// The two-phase receive pass no longer fetches the spent filter per block
    /// (the spend sweep fetches it separately), so `spent_bytes` is gone from the
    /// data-volume stat; only the receive-pass tweaks + new-utxo filter remain.
    #[derive(Serialize, Deserialize)]
    struct BlockRecord {
        height: u32,
        tweaks: u64,
        utxo_bytes: u64,
    }

    /// Best-effort host CPU/RAM info, read from `/proc` where available. Any field
    /// that cannot be determined is left `None`.
    fn host_info() -> HostInfo {
        let cpu_model = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        });
        let cores = std::thread::available_parallelism().ok().map(|n| n.get());
        let ram_bytes = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        });
        HostInfo {
            cpu_model,
            cores,
            ram_bytes,
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args = match parse_args() {
            Ok(Some(args)) => args,
            Ok(None) => {
                print!("{}", usage());
                return Ok(());
            }
            Err(e) => {
                eprint!("error: {e}\n\n{}", usage());
                std::process::exit(1);
            }
        };

        // Fixed dummy watch-only keys: cost is independent of ownership.
        let scan_sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32])?;
        let spend_pk = DUMMY_SPEND_PUBKEY.parse::<bitcoin::secp256k1::PublicKey>()?;
        let client = SpReceiver::new(scan_sk, SpendKey::Public(spend_pk), args.network)
            .map_err(|e| format!("SpReceiver: {e}"))?;

        let probe = bwk_sp::blindbit::agent()?;
        let info = bwk_sp::blindbit::info(&probe, &args.url).map_err(|e| format!("info: {e}"))?;
        if info.network != args.network {
            return Err(format!(
                "network mismatch: oracle serves {}, but --network is {}",
                info.network, args.network
            )
            .into());
        }
        let with_cutthrough = info.tweaks_cut_through_with_dust_filter;

        let start = args.start.unwrap_or_else(|| min_birthday_for(args.network));
        let end = match args.end {
            Some(end) => end,
            None => bwk_sp::blindbit::block_height(&probe, &args.url)
                .map_err(|e| format!("block_height: {e}"))?
                .to_consensus_u32(),
        };
        if start > end {
            println!("nothing to scan: start ({start}) > end ({end})");
            return Ok(());
        }

        // Validate every dust value up front so a late value cannot fail after
        // several benches have already run. A dust limit is only enforced server
        // side by a dust-capable index; the cut-through index always filters, the
        // full index only when built with the dust filter. Otherwise the oracle
        // silently ignores `dustLimit`, so refuse to report a limit that does not
        // apply. A dust limit of 0 disables the filter; any positive value enables it.
        let dusts: Vec<Option<bitcoin::Amount>> = args
            .dust_limits
            .iter()
            .map(|&sats| (sats > 0).then(|| bitcoin::Amount::from_sat(sats)))
            .collect();
        for (sats, dust) in args.dust_limits.iter().zip(&dusts) {
            if dust.is_some() && !with_cutthrough && !info.tweaks_full_with_dust_filter {
                return Err(format!(
                    "oracle has no dust-capable index (only tweaks_full_basic); \
                     --dust-limit {sats} would be silently ignored; \
                     rerun with --dust-limit 0 or enable a dust-filter index"
                )
                .into());
            }
        }

        // Annotate a defaulted start: on mainnet the birthday is Taproot activation
        // (the first block that can hold an SP output); elsewhere it is block 1.
        let start_note = match (args.start, args.network) {
            (Some(_), _) => "",
            (None, bitcoin::Network::Bitcoin) => " (default: Taproot activation)",
            (None, _) => " (default: network birthday)",
        };
        let params = BenchParams {
            client: &client,
            url: &args.url,
            network: args.network,
            start,
            end,
            start_note,
            with_cutthrough,
        };

        let total = dusts.len();
        for (i, dust) in dusts.into_iter().enumerate() {
            let dust_label = match dust {
                Some(amount) => amount.to_sat().to_string(),
                None => "disabled".to_string(),
            };
            println!("=== bench {}/{total}: dust={dust_label} ===", i + 1);
            run_one_bench(&params, dust)?;
        }

        Ok(())
    }

    /// Parameters shared by every per-dust bench within a single `run()`.
    struct BenchParams<'a> {
        client: &'a SpReceiver,
        url: &'a str,
        network: bitcoin::Network,
        start: u32,
        end: u32,
        /// Annotation appended to the plan's start line (e.g. defaulted birthday).
        start_note: &'static str,
        with_cutthrough: bool,
    }

    /// Run one full bench for a single dust value, print progress and auto-save
    /// the per-block data to `BENCH_DIR`.
    fn run_one_bench(
        params: &BenchParams,
        dust: Option<bitcoin::Amount>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let &BenchParams {
            client,
            url,
            network,
            start,
            end,
            start_note,
            with_cutthrough,
        } = params;
        let block_count = u64::from(end - start + 1);

        let dust_desc = match dust {
            Some(amount) => format!("{} sat", amount.to_sat()),
            None => "disabled".to_string(),
        };
        println!("plan:");
        println!("  network:      {network}");
        println!("  url:          {url}");
        println!("  start height: {start}{start_note}");
        println!("  end height:   {end}");
        println!("  blocks:       {block_count}");
        println!("  dust limit:   {dust_desc}");
        println!("  cutthrough:   {with_cutthrough}");
        println!("scanning (two-phase: receive pass, then spend sweep)...");

        // Shared per-block receive-pass stats, teed by the recording backend as
        // the two-phase driver fetches block data internally.
        let stats = Arc::new(Mutex::new(ReceiveStats {
            max_tweaks_height: start,
            ..ReceiveStats::default()
        }));
        // Counts receive blocks delivered, for the progress line and ETA.
        let downloaded = Arc::new(AtomicU64::new(0));

        let stats_for_backend = Arc::clone(&stats);
        let downloaded_for_backend = Arc::clone(&downloaded);
        let block_data_observer = Arc::new(move |bd: &BlockData| {
            let height = bd.blkheight.to_consensus_u32();
            let tweaks = bd.tweaks.len();
            let utxo_bytes = bd.new_utxo_filter.data.len() as u64;
            downloaded_for_backend.fetch_add(1, Ordering::Relaxed);
            let mut s = stats_for_backend.lock().expect("poisoned");
            s.total_tweaks += tweaks as u64;
            s.total_utxo_bytes += utxo_bytes;
            if tweaks > s.max_tweaks {
                s.max_tweaks = tweaks;
                s.max_tweaks_height = height;
            }
            s.records.push(BlockRecord {
                height,
                tweaks: tweaks as u64,
                utxo_bytes,
            });
        });

        // Attribute the single-threaded compute across the hot-path phases.
        bwk_sp::scan::profiling::reset();

        let start_height =
            bitcoin::absolute::Height::from_consensus(start).expect("valid start height");
        let end_height = bitcoin::absolute::Height::from_consensus(end).expect("valid end height");

        let t = Instant::now();

        // Run the two-phase scan on a worker thread so the main thread can poll
        // the recording-backend counters and print progress. The driver fetches
        // internally over two passes, so there is no per-block hook to time fetch
        // vs compute; the profiling breakdown below gives the compute split.
        let done = Arc::new(AtomicBool::new(false));
        let scan_done = Arc::clone(&done);
        let agent = Arc::new(bwk_sp::blindbit::agent()?);
        let stop = Arc::new(AtomicBool::new(false));
        let (_sender, receiver) = mpsc::channel();
        drop(receiver);
        let stores = ScanStores {
            coin_store: Arc::new(Mutex::new(bwk_sp::account::coin_store::SpCoinStore::new())),
            tx_store: Arc::new(Mutex::new(bwk_sp::account::tx_store::SpTxStore::new())),
            scan_state: Arc::new(Mutex::new(bwk_sp::scan::state::ScanState::new(start))),
            sender: _sender,
            header_store: bwk::bwk_electrum::header_store::HeaderStore::new_in_memory(
                params.network,
            ),
        };
        // Seed one synthetic owned outpoint at the first scanned height so the spend
        // (input) sweep always runs over every block, process_spends short-circuits on an
        // empty watchable set, which would otherwise make the spend phase a no-op. The fake
        // hash won't hit a real spent filter, so it stays watchable and the sweep walks the
        // whole range, giving the spend-phase wall-time alongside the receive scan.
        {
            use bwk_sp::bitcoin::hashes::Hash;
            stores.coin_store.lock().expect("poisoned").insert(
                bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0u8; 32]),
                    vout: 0,
                },
                OwnedOutput {
                    blockheight: start_height,
                    tweak: [0u8; 32],
                    amount: bitcoin::Amount::from_sat(1),
                    script: bitcoin::ScriptBuf::new(),
                    label: None,
                    spend_status: OutputSpendStatus::Unspent,
                },
            );
        }
        let client = client.clone();
        let scan_url = url.to_string();
        let scan_handle = thread::spawn(move || -> Result<(), SpError> {
            let res = scan_blocks_with_observer(
                agent,
                &scan_url,
                &client,
                &stores,
                &stop,
                start_height,
                end_height,
                dust,
                with_cutthrough,
                ScanRuntimeConfig::default(),
                Some(block_data_observer),
            );
            scan_done.store(true, Ordering::Relaxed);
            res
        });

        // Progress poller: print a trailing-window rate from the receive-pass
        // block counter until the scan thread signals completion.
        let mut last_print = t;
        let mut samples: std::collections::VecDeque<Sample> = std::collections::VecDeque::new();
        samples.push_back(Sample {
            t,
            processed: 0,
            tweaks: 0,
        });
        while !done.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
            if last_print.elapsed().as_secs_f64() < PRINT_INTERVAL_SECS {
                continue;
            }
            let now = Instant::now();
            let processed = downloaded.load(Ordering::Relaxed);
            let total_tweaks = stats.lock().expect("poisoned").total_tweaks;
            while samples.len() > 1
                && now
                    .duration_since(samples.front().expect("nonempty").t)
                    .as_secs_f64()
                    > WINDOW_SECS
            {
                samples.pop_front();
            }
            let base = samples.front().expect("nonempty");
            let dt = now.duration_since(base.t).as_secs_f64().max(1e-9);
            let win_blocks = processed.saturating_sub(base.processed).max(1);
            let rate = win_blocks as f64 / dt;
            let now_tw = total_tweaks.saturating_sub(base.tweaks) as f64 / win_blocks as f64;
            let eta = if rate > 0.0 {
                fmt_dur((block_count.saturating_sub(processed)) as f64 / rate)
            } else {
                "?".to_string()
            };
            let pct = processed as f64 / block_count as f64 * 100.0;
            println!(
                "  [{pct:5.1}%] {processed}/{block_count} recv  {rate:.0} blk/s  ETA {eta}  now {now_tw:.0} tw/blk"
            );
            samples.push_back(Sample {
                t: now,
                processed,
                tweaks: total_tweaks,
            });
            last_print = now;
        }

        scan_handle
            .join()
            .map_err(|_| "scan thread panicked")?
            .map_err(|e| format!("scan: {e}"))?;
        let secs = t.elapsed().as_secs_f64();

        // Move the captured per-block stats out of the shared cell.
        let ReceiveStats {
            records,
            total_tweaks,
            total_utxo_bytes,
            max_tweaks,
            max_tweaks_height,
        } = std::mem::take(&mut *stats.lock().expect("poisoned"));
        let processed = records.len() as u64;

        let (blocks_per_sec, ms_per_block) = if secs > 0.0 && processed > 0 {
            (processed as f64 / secs, (secs * 1000.0) / processed as f64)
        } else {
            (f64::INFINITY, 0.0)
        };
        let denom = processed.max(1) as f64;
        // Receive-pass bytes only (33 B per tweak + new-utxo filter); the spend
        // sweep's separately fetched spent filters are not counted here.
        let est_download_mb = (total_tweaks * 33 + total_utxo_bytes) as f64 / 1_000_000.0;

        let proc_s = bwk_sp::scan::profiling::snapshot_secs()
            .iter()
            .map(|(_, s)| s)
            .sum::<f64>();

        // Re-derive the tweaks-per-range buckets from the captured records.
        let width = block_count as f64 / BUCKETS as f64;
        let mut buckets = vec![(0u64, 0u64); BUCKETS]; // (block_count, tweak_count)
        for r in &records {
            let b = (f64::from(r.height.saturating_sub(start)) / width) as usize;
            let b = b.min(BUCKETS - 1);
            buckets[b].0 += 1;
            buckets[b].1 += r.tweaks;
        }

        println!("summary:");
        println!("  blocks scanned:   {processed}");
        println!("  elapsed:          {secs:.3} s");
        println!("  blocks/sec:       {blocks_per_sec:.2}");
        println!("  ms/block:         {ms_per_block:.3}");
        {
            let phases = bwk_sp::scan::profiling::snapshot_secs();
            let pct = |s: f64| s / proc_s.max(1e-9) * 100.0;
            println!("compute breakdown (single-thread wall, summed across cores):");
            for (name, s) in phases {
                println!("  {name:<14} {s:8.1} s ({:.0}%)", pct(s));
            }
        }
        {
            let [(rn, rs), (sn, ss)] = bwk_sp::scan::profiling::phase_wall_secs();
            println!("phase wall-time (fetch + process):");
            println!("  {rn:<14} {rs:8.3} s   (receive scan)");
            println!("  {sn:<14} {ss:8.3} s   (spend sweep)");
        }
        println!("data per block:");
        println!("  total tweaks:     {total_tweaks}");
        println!("  avg tweaks/block: {:.1}", total_tweaks as f64 / denom);
        println!("  max tweaks/block: {max_tweaks} (height {max_tweaks_height})");
        println!(
            "  avg utxo filter:  {:.0} B",
            total_utxo_bytes as f64 / denom
        );
        println!("  est. download:    {est_download_mb:.1} MB (tweaks 33B each + new-utxo filter)");
        println!("tweaks/block by range ({BUCKETS} buckets):");
        for (b, (count, tw)) in buckets.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let lo = start + (b as f64 * width) as u32;
            let hi = (start + ((b + 1) as f64 * width) as u32)
                .saturating_sub(1)
                .min(end);
            let avg = *tw as f64 / *count as f64;
            println!("  {lo:>8}-{hi:<8} {avg:8.1}");
        }

        let data = BenchData {
            config: BenchConfig {
                network: network.to_string(),
                url: url.to_string(),
                start,
                end,
                dust_limit: dust.map(|amount| amount.to_sat()),
                cutthrough: with_cutthrough,
            },
            timing: Timing {
                elapsed_secs: secs,
                // Two-phase fetches internally over two passes, so a clean fetch
                // wall-time split is not available; record only compute.
                fetch_secs: 0.0,
                process_secs: proc_s,
            },
            host: host_info(),
            blocks: records,
        };
        std::fs::create_dir_all(BENCH_DIR)?;
        let path = unique_bench_path(&data.config);
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&path, json)?;
        println!("saved bench data to {}", path.display());

        Ok(())
    }

    /// Build a unique, descriptive path under `BENCH_DIR` for a run's data.
    ///
    /// The base name encodes the run config plus a unix timestamp. If a file with
    /// that name already exists, `-2`, `-3`, ... is appended until a free name is
    /// found, so an existing bench file is never overwritten.
    fn unique_bench_path(config: &BenchConfig) -> std::path::PathBuf {
        let dust = match config.dust_limit {
            Some(sats) => format!("dust{sats}"),
            None => "nodust".into(),
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let base = format!(
            "{network}_{start}-{end}_{dust}_{ts}",
            network = config.network,
            start = config.start,
            end = config.end,
        );
        let dir = std::path::Path::new(BENCH_DIR);
        let mut path = dir.join(format!("{base}.json"));
        let mut n = 2;
        while path.exists() {
            path = dir.join(format!("{base}-{n}.json"));
            n += 1;
        }
        path
    }

    /// PNG canvas size.
    const CANVAS_W: u32 = 1280;
    const CANVAS_H: u32 = 720;

    /// A downsampled series ready to plot, plus its legend label and color.
    struct Series {
        label: String,
        color: RGBColor,
        points: Vec<(u32, f64)>,
    }

    /// Parse `plot` args: an optional `--out <PATH>` for the PNG and an optional
    /// `--smooth <PERCENT>` smoothing window. The bench data is always read from
    /// `BENCH_DIR`. Defaults the output to `BENCH_DIR/graph.png`.
    fn parse_plot_args() -> Result<(String, usize), String> {
        let mut out: Option<String> = None;
        let mut smooth_pct: usize = DEFAULT_SMOOTH_PCT;
        let mut args = std::env::args().skip(2);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--out" => out = Some(args.next().ok_or("--out requires a value")?),
                "--smooth" => {
                    let v = args.next().ok_or("--smooth requires a value")?;
                    smooth_pct = v.parse().map_err(|_| format!("invalid --smooth: {v}"))?;
                }
                other => return Err(format!("plot: unknown argument: {other}")),
            }
        }
        let out = out.unwrap_or_else(|| {
            std::path::Path::new(BENCH_DIR)
                .join("graph.png")
                .to_string_lossy()
                .into_owned()
        });
        Ok((out, smooth_pct))
    }

    /// Average `tweaks` per equal-width column over the shared x domain, so series
    /// from different runs line up. Empty columns are dropped.
    fn downsample(
        blocks: &[BlockRecord],
        x_min: u32,
        x_max: u32,
        columns: usize,
    ) -> Vec<(u32, f64)> {
        let span = f64::from(x_max - x_min).max(1.0);
        let mut sums = vec![(0u64, 0.0f64); columns]; // (count, tweak_sum)
        for r in blocks {
            let frac = f64::from(r.height - x_min) / span;
            let col = ((frac * columns as f64) as usize).min(columns - 1);
            sums[col].0 += 1;
            sums[col].1 += r.tweaks as f64;
        }
        let mut points = Vec::new();
        for (col, (count, sum)) in sums.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let x = x_min + ((col as f64 + 0.5) / columns as f64 * span) as u32;
            points.push((x, sum / *count as f64));
        }
        points
    }

    /// Centered moving average over the y values, so the plot shows a trend rather
    /// than the granular per-column curve. `window` is the number of points in the
    /// averaging window; a window of 0 or 1 returns the points unchanged.
    fn smooth(points: &[(u32, f64)], window: usize) -> Vec<(u32, f64)> {
        if window <= 1 {
            return points.to_vec();
        }
        let half = window / 2;
        points
            .iter()
            .enumerate()
            .map(|(i, &(x, _))| {
                let lo = i.saturating_sub(half);
                let hi = (i + half + 1).min(points.len());
                let avg = points[lo..hi].iter().map(|&(_, v)| v).sum::<f64>() / (hi - lo) as f64;
                (x, avg)
            })
            .collect()
    }

    /// Render all series into one overlapped PNG line chart.
    fn render_png(
        out: &str,
        series: &[Series],
        x_min: u32,
        x_max: u32,
        y_max: f64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = BitMapBackend::new(out, (CANVAS_W, CANVAS_H)).into_drawing_area();
        root.fill(&WHITE).map_err(|e| format!("plot: {e}"))?;

        // A little headroom above the tallest plotted value, with a sane floor.
        let y_top = (y_max * 1.05).max(1.0);

        let mut chart = ChartBuilder::on(&root)
            .caption(
                "SP sync cost: tweaks per block vs height",
                ("sans-serif", 28),
            )
            .margin(20)
            .x_label_area_size(50)
            .y_label_area_size(70)
            .build_cartesian_2d(x_min..x_max.max(x_min + 1), 0f64..y_top)
            .map_err(|e| format!("plot: {e}"))?;

        chart
            .configure_mesh()
            .x_desc("block height")
            .y_desc("tweaks per block")
            .x_label_formatter(&|h| format!("{h}"))
            .y_label_formatter(&|v| format!("{}", v.round() as i64))
            .draw()
            .map_err(|e| format!("plot: {e}"))?;

        for ser in series {
            let color = ser.color;
            chart
                .draw_series(LineSeries::new(
                    ser.points.iter().map(|(h, v)| (*h, *v)),
                    color.stroke_width(2),
                ))
                .map_err(|e| format!("plot: {e}"))?
                .label(ser.label.clone())
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color));
        }

        chart
            .configure_series_labels()
            .position(SeriesLabelPosition::UpperLeft)
            .background_style(WHITE.mix(0.8))
            .border_style(BLACK)
            .draw()
            .map_err(|e| format!("plot: {e}"))?;

        root.present().map_err(|e| format!("plot: {e}"))?;
        Ok(())
    }

    /// Collect every `*.json` file under `BENCH_DIR`, sorted by name for
    /// deterministic color/draw order.
    fn discover_bench_files() -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
        let dir = std::path::Path::new(BENCH_DIR);
        if !dir.is_dir() {
            return Err(
                format!("plot: {BENCH_DIR} directory does not exist; run a bench first").into(),
            );
        }
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("read {BENCH_DIR}: {e}"))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        if files.is_empty() {
            return Err(format!("plot: no .json bench files in {BENCH_DIR}").into());
        }
        files.sort();
        Ok(files)
    }

    pub fn run_plot() -> Result<(), Box<dyn std::error::Error>> {
        let (out, smooth_pct) = match parse_plot_args() {
            Ok(parsed) => parsed,
            Err(e) => {
                eprint!("error: {e}\n\n{}", usage());
                std::process::exit(1);
            }
        };

        let mut loaded: Vec<(String, BenchData)> = Vec::new();
        for path in discover_bench_files()? {
            let name = path.to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).map_err(|e| format!("read {name}: {e}"))?;
            let data: BenchData =
                serde_json::from_str(&text).map_err(|e| format!("parse {name}: {e}"))?;
            loaded.push((name, data));
        }

        // Legend/series order: group by cutthrough, then ascending dust limit
        // (smallest on top; a disabled filter counts as 0).
        loaded.sort_by_key(|(_, d)| (d.config.cutthrough, d.config.dust_limit.unwrap_or(0)));

        // Shared x domain across all non-empty series.
        let mut x_min = u32::MAX;
        let mut x_max = u32::MIN;
        for (path, data) in &loaded {
            if data.blocks.is_empty() {
                eprintln!("warning: {path} has zero blocks, skipping");
                continue;
            }
            for r in &data.blocks {
                x_min = x_min.min(r.height);
                x_max = x_max.max(r.height);
            }
        }
        if x_min > x_max {
            return Err("plot: all input series are empty".into());
        }

        // Downsample each non-empty series over the shared domain, into roughly one
        // column per horizontal pixel of the plot canvas, then smooth into a trend.
        let plot_width_px = CANVAS_W as usize;
        let window = plot_width_px * smooth_pct.min(100) / 100;
        let mut series: Vec<Series> = Vec::new();
        let mut y_max = 0.0f64;
        for (_, data) in &loaded {
            if data.blocks.is_empty() {
                continue;
            }
            let points = smooth(
                &downsample(&data.blocks, x_min, x_max, plot_width_px),
                window,
            );
            for (_, v) in &points {
                y_max = y_max.max(*v);
            }
            let dust = match data.config.dust_limit {
                Some(sats) => format!("dust={sats}"),
                None => "dust=none".to_string(),
            };
            series.push(Series {
                label: format!("cutthrough={}, {dust}", data.config.cutthrough),
                color: PALETTE[series.len() % PALETTE.len()],
                points,
            });
        }

        render_png(&out, &series, x_min, x_max, y_max)?;
        println!("wrote graph with {} series to {out}", series.len());
        Ok(())
    }

    /// Remove the whole `BENCH_DIR` (every saved run plus any rendered graph).
    pub fn run_clean() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::path::Path::new(BENCH_DIR);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
            println!("removed {BENCH_DIR}");
        } else {
            println!("nothing to clean ({BENCH_DIR} does not exist)");
        }
        Ok(())
    }
}

#[cfg(feature = "instrumentation")]
fn mode_usage() -> String {
    "
Runs the instrumented harness fully in-RAM (no persistence):
every run rescans the full range and measures CPU + network. Always reports the
per-block data volume. Each run auto-saves its per-block data to the bench_data/
directory (gitignored, unique filename per run, never overwritten).

PLOT:
    sp_sync_bench plot [--out <graph.png>] [--smooth <PERCENT>]

Overlaps the tweaks-per-block curves of every run stored in bench_data/ into a
single PNG (X = block height, Y = tweaks per block). Writes to bench_data/graph.png
by default, override with --out. The curves are smoothed into a trend with a
moving average spanning <PERCENT> of the x range (default 10, 0 disables).

CLEAN:
    sp_sync_bench clean

Removes the bench_data/ directory (every saved run and any rendered graph).
"
    .to_string()
}

#[cfg(feature = "instrumentation")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("plot") => instrumented::run_plot(),
        Some("clean") => instrumented::run_clean(),
        _ => instrumented::run(),
    }
}

// ---------------------------------------------------------------------------
// Default build (`--features bench`): drive the real Account scan.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "instrumentation"))]
fn mode_usage() -> String {
    "
Drives the real bwk_sp::account::Account OneShot scan and reports headline timing only.
The Account always scans from the start height to the current chain tip, so
--end is ignored in this build (honored only with --features instrumentation).
Persistence is disabled and a temporary data dir is used.
"
    .to_string()
}

#[cfg(not(feature = "instrumentation"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            print!("{}", usage());
            return Ok(());
        }
        Err(e) => {
            eprint!("error: {e}\n\n{}", usage());
            std::process::exit(1);
        }
    };

    if args.end.is_some() {
        println!("note: --end is ignored in the default build; the Account always scans to the chain tip (use --features instrumentation to bound the range)");
    }

    let start = args.start.unwrap_or_else(|| min_birthday_for(args.network));
    let scan_sk_hex = hex::encode([1u8; 32]);
    // Real mode runs a single scan; the dust *list* is an instrumented-only feature.
    let dust = args.dust_limits[0];
    if args.dust_limits.len() > 1 {
        println!(
            "note: multiple --dust-limit values only apply with --features instrumentation; using {dust}"
        );
    }

    // Watch-only: from_keys reads the 66-hex spend key as SpendKey::Public.
    // Persist enabled with a fresh per-run temp dir = production conditions (real
    // store + throttled scan-state writes) while still a full rescan each run.
    let data_dir = std::env::temp_dir().join(format!("sp_sync_bench_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).ok();
    let mut config = bwk_sp::account::config::Config::from_keys(
        "sp_sync_bench".to_string(),
        args.network,
        scan_sk_hex,
        DUMMY_SPEND_PUBKEY.to_string(),
        args.url.clone(),
        data_dir.clone(),
    )?
    .with_persistence(Some(bwk::persist::PersistenceKind::Json));
    // Match the instrumented path: 0 means "disabled" (no dust filter).
    config.set_dust_limit(if dust == 0 { None } else { Some(dust) });
    config.set_birthday_height(Some(start));

    let mut account = bwk_sp::account::Account::new(config)?;
    // Force the spend (input) sweep to run over every scanned block so the bench
    // measures both phases, without an owned coin it short-circuits to a no-op.
    account.seed_synthetic_owned_coin();
    let rx = account.receiver().take().expect("receiver");

    account.start_scan(bwk_sp::account::ScanMode::OneShot, None)?;

    let mut scan_start: Option<Instant> = None;
    let mut block_count: u64 = 0;
    let mut last_print = Instant::now();
    let mut elapsed = Duration::ZERO;

    let report_progress = |phase: &str,
                           current: u32,
                           end: u32,
                           scan_start: Option<Instant>,
                           block_count: u64,
                           last_print: &mut Instant| {
        let Some(t0) = scan_start else { return };
        if last_print.elapsed().as_secs_f64() < PRINT_INTERVAL_SECS {
            return;
        }
        *last_print = Instant::now();
        let start = end + 1 - block_count as u32;
        let processed = u64::from(current.saturating_sub(start)) + 1;
        let secs = t0.elapsed().as_secs_f64().max(1e-9);
        let rate = processed as f64 / secs;
        let pct = processed as f64 / block_count.max(1) as f64 * 100.0;
        let eta = if rate > 0.0 {
            fmt_dur((block_count.saturating_sub(processed)) as f64 / rate)
        } else {
            "?".to_string()
        };
        println!("  {phase} [{pct:5.1}%] {processed}/{block_count}  {rate:.0} blk/s  ETA {eta}");
    };

    while let Ok(notif) = rx.recv() {
        match notif {
            Notification::Sp(SpNotification::ScanStarted { start, end }) => {
                block_count = u64::from(end - start + 1);
                scan_start = Some(Instant::now());
                last_print = Instant::now();
                println!("plan:");
                println!("  network:      {}", args.network);
                println!("  url:          {}", args.url);
                println!("  start height: {start}");
                println!("  end height:   {end}");
                println!("  blocks:       {block_count}");
                println!("  dust limit:   {dust} sat");
                println!("scanning (real Account, OneShot)...");
            }
            Notification::Sp(SpNotification::ScanReceiveProgress { current, end }) => {
                report_progress(
                    "recv ",
                    current,
                    end,
                    scan_start,
                    block_count,
                    &mut last_print,
                )
            }
            Notification::Sp(SpNotification::ScanSpendProgress { current, end }) => {
                report_progress(
                    "spend",
                    current,
                    end,
                    scan_start,
                    block_count,
                    &mut last_print,
                )
            }
            Notification::Sp(SpNotification::ScanCompleted) => {
                if let Some(t0) = scan_start {
                    elapsed = t0.elapsed();
                }
                break;
            }
            Notification::Sp(SpNotification::FailStartScanning { message })
            | Notification::Sp(SpNotification::FailScan { message }) => {
                return Err(format!("scan failed: {message}").into());
            }
            _ => {}
        }
    }

    let secs = elapsed.as_secs_f64();
    let (blocks_per_sec, ms_per_block) = if secs > 0.0 && block_count > 0 {
        (
            block_count as f64 / secs,
            (secs * 1000.0) / block_count as f64,
        )
    } else {
        (f64::INFINITY, 0.0)
    };
    println!("summary:");
    println!("  blocks scanned:   {block_count}");
    println!("  elapsed:          {secs:.3} s");
    println!("  blocks/sec:       {blocks_per_sec:.2}");
    println!("  ms/block:         {ms_per_block:.3}");
    {
        let [(rn, rs), (sn, ss)] = bwk_sp::scan::profiling::phase_wall_secs();
        println!("phase wall-time (fetch + process):");
        println!("  {rn:<14} {rs:8.3} s   (receive scan)");
        println!("  {sn:<14} {ss:8.3} s   (spend sweep)");
    }

    // Drop the throwaway store dir (account/scan thread is done after join).
    let _ = std::fs::remove_dir_all(&data_dir);

    Ok(())
}

#[cfg(not(feature = "instrumentation"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}
