//! Renders a `Snapshot` as an ASCII table for humans or JSON for machines.

use std::collections::BTreeMap;

use crate::{
    error::Error,
    metrics::{ConnSnapshot, ErrorBucket, MethodStats, Phase, Side, Snapshot},
};

enum Align {
    Left,
    Right,
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Discovery => "discovery",
        Phase::TxFetch => "tx_fetch",
        Phase::Proofs => "proofs",
        Phase::Headers => "headers",
        Phase::Other => "other",
    }
}

fn side_label(side: Side) -> &'static str {
    match side {
        Side::Client => "client",
        Side::Server => "server",
    }
}

/// Formats `n` with `_` thousands separators, e.g. `1240000` -> `1_240_000`.
fn fmt_num(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            out.push('_');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn pad(out: &mut String, cell: &str, width: usize, align: &Align) {
    let fill = width.saturating_sub(cell.len());
    match align {
        Align::Left => {
            out.push_str(cell);
            out.extend(std::iter::repeat_n(' ', fill));
        }
        Align::Right => {
            out.extend(std::iter::repeat_n(' ', fill));
            out.push_str(cell);
        }
    }
}

/// Renders a header row plus data rows as a padded ASCII table, with column
/// widths computed from the widest cell (header or data) in each column.
fn render_rows(headers: &[&str], rows: &[Vec<String>], aligns: &[Align]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let push_row = |out: &mut String, cells: &[String]| {
        out.push_str("  ");
        for (i, cell) in cells.iter().enumerate() {
            pad(out, cell, widths[i], &aligns[i]);
            if i + 1 < cells.len() {
                out.push_str("  ");
            }
        }
        out.push('\n');
    };

    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    push_row(&mut out, &header_cells);
    for row in rows {
        push_row(&mut out, row);
    }
    out
}

/// Sums a connection's calls, bytes up and bytes down across its attributed
/// methods plus its unattributed bucket.
fn conn_totals(conn: &ConnSnapshot) -> (u64, u64, u64) {
    let mut calls = conn.unattributed.calls;
    let mut bytes_up = conn.unattributed.bytes_up;
    let mut bytes_down = conn.unattributed.bytes_down;
    for stats in conn.methods.values() {
        calls += stats.calls;
        bytes_up += stats.bytes_up;
        bytes_down += stats.bytes_down;
    }
    (calls, bytes_up, bytes_down)
}

fn render_method_section(snapshot: &Snapshot) -> String {
    let mut method_rows: Vec<(Phase, &String, &MethodStats)> = snapshot
        .totals
        .methods
        .iter()
        .map(|(method, stats)| (Phase::of(method), method, stats))
        .collect();
    method_rows.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| {
                let a_bytes = a.2.bytes_up + a.2.bytes_down;
                let b_bytes = b.2.bytes_up + b.2.bytes_down;
                b_bytes.cmp(&a_bytes)
            })
            .then_with(|| a.1.cmp(b.1))
    });

    let mut total_calls = 0u64;
    let mut total_up = 0u64;
    let mut total_down = 0u64;
    let mut rows = Vec::with_capacity(method_rows.len() + 1);
    for (phase, method, stats) in &method_rows {
        total_calls += stats.calls;
        total_up += stats.bytes_up;
        total_down += stats.bytes_down;
        rows.push(vec![
            phase_label(*phase).to_string(),
            method.to_string(),
            fmt_num(stats.calls),
            fmt_num(stats.bytes_up),
            fmt_num(stats.bytes_down),
        ]);
    }
    rows.push(vec![
        "TOTAL".to_string(),
        String::new(),
        fmt_num(total_calls),
        fmt_num(total_up),
        fmt_num(total_down),
    ]);

    render_rows(
        &["phase", "method", "calls", "bytes_up", "bytes_down"],
        &rows,
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
    )
}

/// Returns the rendered per-connection table (or a placeholder line when
/// there are no connections) plus the total framing bytes across all of them.
fn render_conn_section(conns: &[&ConnSnapshot]) -> (String, u64) {
    let mut total_framing = 0u64;
    if conns.is_empty() {
        return ("  no connections recorded\n".to_string(), total_framing);
    }

    let mut rows = Vec::with_capacity(conns.len());
    for conn in conns {
        let (calls, bytes_up, bytes_down) = conn_totals(conn);
        total_framing += conn.framing_bytes_up + conn.framing_bytes_down;
        let closed = conn
            .closed_at
            .map(|secs| format!("{secs:.2}s"))
            .unwrap_or_else(|| "-".to_string());
        let closed_by = conn
            .close
            .as_ref()
            .map(|close| side_label(close.closed_by))
            .unwrap_or("-");
        rows.push(vec![
            conn.id.to_string(),
            fmt_num(calls),
            fmt_num(conn.round_trips),
            fmt_num(bytes_up),
            fmt_num(bytes_down),
            format!("{:.2}s", conn.opened_at),
            closed,
            closed_by.to_string(),
            fmt_num(conn.largest_request_line),
            fmt_num(conn.largest_response_line),
            format!("{:.1}s", conn.max_idle_gap_secs),
        ]);
    }

    let table = render_rows(
        &[
            "conn",
            "calls",
            "rtt",
            "bytes_up",
            "bytes_down",
            "opened",
            "closed",
            "closed_by",
            "max_req",
            "max_resp",
            "max_idle",
        ],
        &rows,
        &[
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
    );
    (table, total_framing)
}

/// Warns loudly when traffic could not be attributed to a method: this is a
/// bug in attribution, not a benign statistic, so it must never be quiet.
fn render_unattributed_warning(conns: &[&ConnSnapshot]) -> Option<String> {
    let mut calls = 0u64;
    let mut bytes = 0u64;
    for conn in conns {
        calls += conn.unattributed.calls + conn.unattributed.responses;
        bytes += conn.unattributed.bytes_up + conn.unattributed.bytes_down;
    }
    if calls == 0 && bytes == 0 {
        return None;
    }
    Some(format!(
        "\nWARNING: {} unattributed bytes across {} calls, not matched to any method (attribution bug)\n",
        fmt_num(bytes),
        fmt_num(calls)
    ))
}

fn render_error_section(conns: &[&ConnSnapshot]) -> Option<String> {
    let mut errors: BTreeMap<(String, i64), ErrorBucket> = BTreeMap::new();
    for conn in conns {
        for bucket in conn.errors.values() {
            let key = (bucket.method.clone(), bucket.code);
            let entry = errors.entry(key).or_insert_with(|| ErrorBucket {
                method: bucket.method.clone(),
                code: bucket.code,
                count: 0,
                sample: bucket.sample.clone(),
            });
            entry.count += bucket.count;
        }
    }
    if errors.is_empty() {
        return None;
    }

    let rows: Vec<Vec<String>> = errors
        .values()
        .map(|bucket| {
            vec![
                bucket.method.clone(),
                bucket.code.to_string(),
                fmt_num(bucket.count),
                bucket.sample.clone(),
            ]
        })
        .collect();
    let table = render_rows(
        &["method", "code", "count", "sample"],
        &rows,
        &[Align::Left, Align::Right, Align::Right, Align::Left],
    );
    Some(format!("\nerrors:\n{table}"))
}

fn render_order_section(conns: &[&ConnSnapshot]) -> Option<String> {
    let mut out_of_order = 0u64;
    let mut max_displacement = 0u64;
    for conn in conns {
        out_of_order += conn.order.out_of_order;
        max_displacement = max_displacement.max(conn.order.max_displacement);
    }
    if out_of_order == 0 {
        return None;
    }
    Some(format!(
        "\nout-of-order responses: {} (max displacement {max_displacement})\n",
        fmt_num(out_of_order)
    ))
}

pub fn render_table(snapshot: &Snapshot) -> String {
    let mut conns: Vec<&ConnSnapshot> = snapshot.connections.iter().collect();
    conns.sort_by_key(|conn| conn.id);

    let mut out = render_method_section(snapshot);
    out.push('\n');

    let (conn_table, total_framing) = render_conn_section(&conns);
    out.push_str(&conn_table);
    out.push('\n');

    out.push_str(&format!(
        "  connections: {}   wall: {:.2}s   framing: {} bytes\n",
        conns.len(),
        snapshot.wall_secs,
        fmt_num(total_framing)
    ));

    if let Some(warning) = render_unattributed_warning(&conns) {
        out.push_str(&warning);
    }
    if let Some(errors) = render_error_section(&conns) {
        out.push_str(&errors);
    }
    if let Some(order) = render_order_section(&conns) {
        out.push_str(&order);
    }

    out
}

pub fn render_json(snapshot: &Snapshot) -> Result<String, Error> {
    Ok(serde_json::to_string_pretty(snapshot)?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        metrics::{
            CloseInfo, ConnSnapshot, ErrorBucket, MethodStats, OrderStats, Side, Snapshot, Totals,
            TtfbStats,
        },
        report::{fmt_num, render_json, render_table},
    };

    fn method_stats(calls: u64, responses: u64, bytes_up: u64, bytes_down: u64) -> MethodStats {
        MethodStats {
            calls,
            responses,
            bytes_up,
            bytes_down,
            ttfb: TtfbStats::default(),
        }
    }

    fn empty_conn(id: u64) -> ConnSnapshot {
        ConnSnapshot {
            id,
            opened_at: 0.0,
            closed_at: None,
            close: None,
            round_trips: 0,
            methods: HashMap::new(),
            unattributed: MethodStats::default(),
            framing_bytes_up: 0,
            framing_bytes_down: 0,
            max_idle_gap_secs: 0.0,
            largest_request_line: 0,
            largest_response_line: 0,
            errors: HashMap::new(),
            order: OrderStats::default(),
        }
    }

    fn sample_snapshot() -> Snapshot {
        let mut conn0 = empty_conn(0);
        conn0.opened_at = 0.0;
        conn0.closed_at = Some(2.1);
        conn0.close = Some(CloseInfo {
            closed_by: Side::Server,
            clean: true,
            error: None,
            idle_before_close: Some(0.5),
        });
        conn0.round_trips = 201;
        conn0.methods.insert(
            "blockchain.scripthash.get_history".to_string(),
            method_stats(200, 200, 18_400, 1_240_000),
        );
        conn0.methods.insert(
            "blockchain.headers.subscribe".to_string(),
            method_stats(1, 1, 62, 180),
        );
        conn0.framing_bytes_up = 900;
        conn0.framing_bytes_down = 200;
        conn0.largest_request_line = 400;
        conn0.largest_response_line = 16_500;
        conn0.max_idle_gap_secs = 612.4;

        let mut conn1 = empty_conn(1);
        conn1.opened_at = 0.1;
        conn1.methods.insert(
            "blockchain.block.headers".to_string(),
            method_stats(1, 1, 88, 16_240),
        );
        conn1.unattributed = method_stats(1, 0, 40, 0);
        conn1.framing_bytes_up = 200;
        conn1.framing_bytes_down = 118;
        conn1.errors.insert(
            "blockchain.transaction.get:-1".to_string(),
            ErrorBucket {
                method: "blockchain.transaction.get".to_string(),
                code: -1,
                count: 2,
                sample: "missing transaction".to_string(),
            },
        );
        conn1.order = OrderStats {
            out_of_order: 3,
            max_displacement: 5,
        };

        let mut totals = Totals::default();
        for conn in [&conn0, &conn1] {
            for (method, stats) in &conn.methods {
                let entry = totals.methods.entry(method.clone()).or_default();
                entry.calls += stats.calls;
                entry.responses += stats.responses;
                entry.bytes_up += stats.bytes_up;
                entry.bytes_down += stats.bytes_down;
            }
        }

        Snapshot {
            wall_secs: 2.10,
            connections: vec![conn0, conn1],
            totals,
        }
    }

    #[test]
    fn table_contains_expected_rows_and_totals() {
        let snapshot = sample_snapshot();
        let table = render_table(&snapshot);

        assert!(table.contains("discovery"));
        assert!(table.contains("blockchain.scripthash.get_history"));
        assert!(table.contains("headers"));
        assert!(table.contains("blockchain.headers.subscribe"));
        assert!(table.contains("blockchain.block.headers"));
        assert!(table.contains("TOTAL"));
        assert!(table.contains("18_550"));
        assert!(table.contains("1_256_420"));
        assert!(table.contains("connections: 2"));
    }

    #[test]
    fn totals_agree_with_method_rows_plus_framing() {
        let snapshot = sample_snapshot();

        let total_calls: u64 = snapshot.totals.methods.values().map(|s| s.calls).sum();
        let total_bytes_up: u64 = snapshot.totals.methods.values().map(|s| s.bytes_up).sum();
        let total_bytes_down: u64 = snapshot.totals.methods.values().map(|s| s.bytes_down).sum();

        let table = render_table(&snapshot);
        let total_line = table
            .lines()
            .find(|line| line.trim_start().starts_with("TOTAL"))
            .expect("TOTAL row must be present in rendered table");
        let fields: Vec<&str> = total_line.split_whitespace().collect();
        assert_eq!(
            fields,
            [
                "TOTAL",
                fmt_num(total_calls).as_str(),
                fmt_num(total_bytes_up).as_str(),
                fmt_num(total_bytes_down).as_str(),
            ]
        );

        let framing: u64 = snapshot
            .connections
            .iter()
            .map(|c| c.framing_bytes_up + c.framing_bytes_down)
            .sum();
        assert!(table.contains(&fmt_num(framing)));
    }

    #[test]
    fn empty_snapshot_renders_without_panicking() {
        let snapshot = Snapshot {
            wall_secs: 0.0,
            connections: Vec::new(),
            totals: Totals::default(),
        };
        let table = render_table(&snapshot);
        assert!(table.contains("TOTAL"));
        assert!(table.contains("no connections recorded"));
        assert!(table.contains("connections: 0"));
    }

    #[test]
    fn nonzero_unattributed_produces_warning() {
        let snapshot = sample_snapshot();
        let table = render_table(&snapshot);
        assert!(table.contains("WARNING"));
        assert!(table.contains("unattributed"));
    }

    #[test]
    fn zero_unattributed_has_no_warning() {
        let mut snapshot = sample_snapshot();
        for conn in &mut snapshot.connections {
            conn.unattributed = MethodStats::default();
        }
        let table = render_table(&snapshot);
        assert!(!table.contains("WARNING"));
    }

    #[test]
    fn error_and_order_sections_are_rendered() {
        let snapshot = sample_snapshot();
        let table = render_table(&snapshot);
        assert!(table.contains("errors:"));
        assert!(table.contains("blockchain.transaction.get"));
        assert!(table.contains("missing transaction"));
        assert!(table.contains("out-of-order responses: 3 (max displacement 5)"));
    }

    #[test]
    fn json_round_trips_into_equal_snapshot() {
        let snapshot = sample_snapshot();
        let json = render_json(&snapshot).unwrap();
        let parsed: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn fmt_num_inserts_thousands_separators() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(42), "42");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1_000), "1_000");
        assert_eq!(fmt_num(1_240_000), "1_240_000");
    }
}
