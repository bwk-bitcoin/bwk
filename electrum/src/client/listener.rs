use crate::{
    client::PING_INTERVAL,
    electrum::{request::Request, response::Response},
    raw_client,
};
use bwk_backoff::Backoff;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::mpsc,
    time::{Duration, Instant},
};

use super::Client;

/// Resend a pending batch the server never answered after this long.
const STALL_RESEND_AFTER: Duration = Duration::from_secs(2);

/// Outcome of dispatching one consumer request.
pub(super) enum Dispatch {
    /// Batch was sent; track it as the pending request until fully answered.
    Sent(Vec<Request>),
    /// Nothing to send (e.g. an empty batch); keep going.
    Empty,
    /// Stop the listener (a Stop request, or the consumer channel closed).
    Terminate,
}

/// Whether the listener should keep running after handling responses.
pub(super) enum Flow {
    Continue,
    Terminate,
}

/// Shared loop for the tx and header listeners. It owns the consumer drain, the
/// pending-request gate + stall-resend, the answered-id tracking and the
/// backoff; the per-listener request dispatch and response handling are passed
/// as closures.
///
/// A transport read error terminates the listener: the connection is dead, so
/// it emits the error once and returns instead of looping and re-emitting.
/// Recovery is the consumer's responsibility (e.g. `HeaderStore::restart()`).
/// The connection is pinged every [`PING_INTERVAL`]; pongs never reach the
/// consumer.
pub(super) fn run_listener<RQ, RS, Req, S>(
    mut client: Client,
    send: mpsc::Sender<RS>,
    recv: mpsc::Receiver<RQ>,
    mut state: S,
    mut dispatch: impl FnMut(&mut Client, &mut S, Req, &mpsc::Sender<RS>) -> Dispatch,
    mut handle: impl FnMut(&mut Client, &mut S, Vec<Response>, &mpsc::Sender<RS>) -> Flow,
    transport_err: impl Fn(raw_client::Error) -> RS,
) where
    RQ: Into<Req>,
{
    // The batch of requests still awaiting a response. electrs streams batch
    // responses across multiple reads, so answered ids are dropped as they
    // arrive and the next consumer request is pulled only once the batch is
    // fully answered. `last_sent` drives a resend if it stalls.
    let mut last_request: Option<Vec<Request>> = None;
    let mut last_sent = Instant::now();
    let mut backoff = Backoff::new_ms(50);
    let mut inbox: VecDeque<Req> = VecDeque::new();
    let mut last_ping = Instant::now();

    loop {
        let mut received = false;

        if last_ping.elapsed() >= PING_INTERVAL {
            let mut ping = Request::ping();
            client.register(&mut ping);
            if let Err(e) = client.inner.try_send_batch(vec![&ping]) {
                let _ = send.send(transport_err(e));
                return;
            }
            last_ping = Instant::now();
        }

        // A pending batch unanswered too long means electrs likely dropped a
        // request (empty response while busy); resend so the batch can complete.
        if let Some(reqs) = &last_request {
            if last_sent.elapsed() > STALL_RESEND_AFTER {
                let _ = client.inner.try_send_batch(reqs.iter().collect());
                last_sent = Instant::now();
            }
        }

        // Drain the consumer channel every iteration so a disconnect is always
        // seen; processing stays gated on an empty pending batch below.
        loop {
            match recv.try_recv() {
                Ok(rq) => inbox.push_back(rq.into()),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // Only send the next request once the previous batch is fully answered.
        if last_request.is_none() {
            if let Some(rq) = inbox.pop_front() {
                received = true;
                match dispatch(&mut client, &mut state, rq, &send) {
                    Dispatch::Sent(batch) => {
                        last_request = Some(batch);
                        last_sent = Instant::now();
                    }
                    Dispatch::Empty => {}
                    Dispatch::Terminate => return,
                }
            }
        }

        match client.inner.try_recv(&client.index) {
            Ok(Some(responses)) => {
                if let Some(reqs) = &mut last_request {
                    let answered: BTreeSet<usize> =
                        responses.iter().filter_map(|resp| resp.id()).collect();
                    let before = reqs.len();
                    reqs.retain(|rq| !answered.contains(&rq.id));
                    if reqs.is_empty() {
                        last_request = None;
                    } else if reqs.len() != before {
                        last_sent = Instant::now();
                    }
                }
                received = true;
                if let Flow::Terminate = handle(&mut client, &mut state, responses, &send) {
                    return;
                }
            }
            Ok(None) => {}
            Err(e) => {
                let _ = send.send(transport_err(e));
                return;
            }
        }

        if received {
            backoff.reset();
            continue;
        }
        backoff.snooze();
    }
}
