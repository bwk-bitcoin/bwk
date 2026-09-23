# bwk-mitm

**Experimental. Do not use in production or with real coins. API will break.**

A counting MITM proxy for the Electrum protocol. It sits between a wallet and
an Electrum server, forwards every byte verbatim in both directions, and
reports per-method call counts, bandwidth, round-trips and timing. Nothing on
the wire is altered, delayed, or held back: accounting happens on a parallel
copy of the bytes, never on the copy actually being forwarded.

## Usage

```
bwk-mitm --listen <addr:port> --upstream <host:port> [OPTIONS]

OPTIONS:
    --tls                    connect to the upstream over TLS
    --no-verify-cert         skip certificate and hostname verification (TLS only)
    --format <table|json>    output format (default: table)
    --report <path>          also write the final report here
    --interval <secs>        print a live report every N seconds
    --trace <path>           write a JSONL trace of every attributed element here
    -h, --help               print this help
```

The proxy runs until interrupted (Ctrl-C), then prints a report and exits.
The wallet-facing side is always plaintext; only the upstream connection can
be TLS-wrapped.

### Regtest example

Point a wallet at the proxy instead of directly at a local, plaintext
`electrs` or `Fulcrum`:

```
bwk-mitm --listen 127.0.0.1:60001 --upstream 127.0.0.1:50001 \
    --report run.txt --trace run.jsonl
```

### Real server example

Against a public server over TLS, with certificate verification on:

```
bwk-mitm --listen 127.0.0.1:60001 --upstream electrum.example.org:50002 \
    --tls --format json --interval 10
```

## What is measured

Per method, per connection: calls, responses, bytes up, bytes down, and a
time-to-first-byte distribution (count, min, max, mean).

Per connection: the above rolled up, plus round-trips, when it opened and
closed, which side closed it, whether the close was clean, the largest
request and response lines seen, and the longest idle gap between bytes in
either direction.

Per run: totals across every method and every connection, plus wall time.

```
+---------------+--------+--------+----------+------------+
| phase         | method | calls  | bytes_up | bytes_down |
+---------------+--------+--------+----------+------------+
| discovery     | ...    |    200 |   18,400 |  1,240,000 |
| headers       | ...    |      1 |       62 |        180 |
+---------------+--------+--------+----------+------------+
| TOTAL         |        |    201 |   18,462 |  1,240,180 |
+---------------+--------+--------+----------+------------+
```

## How to read the numbers

**Calls and round-trips are different metrics.** Two clients batch
differently: `bwk-electrum` sends one JSON array on a line, while
`electrum-client` (used by `bdk_electrum`) pipelines separate
newline-delimited requests in one write. A 42-element batch is 42 calls and 1
round-trip either way, regardless of which framing produced it.

**The round-trip definition is a choice, not a measurement.** A TCP read
boundary is not a write boundary: the kernel may coalesce or split writes, so
counting socket writes from a proxy sitting in the middle is unsound. Instead
a round-trip is counted, per connection, as an up-going element seen after at
least one down-going element (or at the very start of the connection). That
is the number of request bursts, which is the number that actually matters
for perceived latency.

**Framing bytes are accounted separately.** Per-method bytes plus framing
bytes equals the exact byte count on the wire. Brackets, commas and the
trailing newline belong to no single request or response element, so they
are tracked as their own per-connection counter rather than folded into (or
dropped from) whichever method happened to be adjacent.

**A non-zero unattributed bucket is a bug, not a curiosity.** Every line
bwk-mitm sees should parse as JSON-RPC and match either a method (for
requests and notifications) or an outstanding request id (for responses). A
non-zero `unattributed` count means a line didn't, and the report prints a
loud warning when that happens. It is worth investigating, not ignoring.

**One wallet can open several connections.** `bwk-electrum` opens two
connections per account: a header worker and a tx listener. Aggregate totals
can hide this; the per-connection breakdown is where it becomes visible.

## Trace file

With `--trace <path>`, bwk-mitm writes one JSON object per line for every
attributed JSON-RPC element, in the order it was seen on the wire. A batch of
42 elements produces 42 trace lines, matching the `calls` metric. Each line
has:

```
elapsed_secs   seconds since the proxy started
conn           connection id
dir            "up" or "down"
method         method name, or null for unattributed traffic
id             request/response id, or null for notifications and
               unattributed traffic
bytes          size of this element, excluding framing
```

The trace contains sizes and identifiers only. It never contains request or
response bodies: record and replay is out of scope for this crate, and
writing bodies would mean writing wallet data to disk. With no `--trace`
path given, nothing is written and the per-line check compiles down to a
single `Option` test.

## Caveats

The proxy adds a hop and a small amount of latency, so wall time and
time-to-first-byte are indicative of relative differences (between servers,
between clients), not absolute numbers for the server alone. On a TLS upstream
the two workers share one `TlsStream`, so its socket is put in non-blocking mode
right after the handshake: each worker holds the mutex for a single attempt and
backs off with the lock released, yielding first and then sleeping up to one
millisecond. Only an idle connection reaches that ceiling, since any completed
read or write resets the backoff, so a busy connection pays nothing; a response
arriving on a quiet connection can still sit up to a millisecond before the
proxy sees it. Plaintext upstreams have no such bias.

All upstream connections appear to originate from the proxy's single source
IP. This matters against servers that enforce per-IP session limits, such as
ElectrumX and Fulcrum: running many proxied wallets against the same server
can hit those limits sooner than running them directly.

Numbers are only comparable against the same server version. Record which
server (and version) you measured against alongside any report.

## Out of scope

Record and replay of traffic, non-Electrum protocols, and TLS termination on
the wallet-facing side (the wallet always sees plaintext).
