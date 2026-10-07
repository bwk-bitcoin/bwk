use crate::electrum::{
    request::Request,
    response::{
        BatchHeaderNotif, Header, HeaderNotification, Headers, HeadersResponse, Response,
        SingleHeaderNotif,
    },
};
use hex_conservative::FromHex;
use miniscript::bitcoin::block::Header as BlockHeader;
use std::{collections::BTreeMap, fmt::Debug, sync::mpsc};

use super::{
    listener::{run_listener, Dispatch, Flow},
    Client, DecodeError, HeaderError, HeaderRequest, HeaderResponse,
};

#[derive(Default)]
struct HeaderState {
    subscribe_id: Option<usize /* request id*/>,
    get_headers_starts: BTreeMap<usize /*request id*/, u32 /*start height*/>,
}

fn decode_header_hex(hex: &str) -> Result<[u8; BlockHeader::SIZE], DecodeError> {
    let bytes = Vec::<u8>::from_hex(hex).map_err(DecodeError::HeaderHex)?;
    if bytes.len() != BlockHeader::SIZE {
        return Err(DecodeError::HeaderLength(bytes.len()));
    }
    let mut raw = [0u8; BlockHeader::SIZE];
    raw.copy_from_slice(&bytes);
    Ok(raw)
}

fn chunk_raw_headers(hex: &str) -> Result<Vec<[u8; BlockHeader::SIZE]>, DecodeError> {
    let bytes = Vec::<u8>::from_hex(hex).map_err(DecodeError::HeadersHex)?;
    if bytes.len() % BlockHeader::SIZE != 0 {
        return Err(DecodeError::HeadersAlignment(bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / BlockHeader::SIZE);
    for chunk in bytes.chunks_exact(BlockHeader::SIZE) {
        let mut raw = [0u8; BlockHeader::SIZE];
        raw.copy_from_slice(chunk);
        out.push(raw);
    }
    Ok(out)
}

fn handle_header_response(
    state: &mut HeaderState,
    r: Response,
    sender: &mut impl FnMut(HeaderResponse),
) {
    match r {
        Response::HeaderNotif(HeaderNotification::Single(SingleHeaderNotif { id, header })) => {
            let Header { height, raw_header } = header;
            match decode_header_hex(&raw_header) {
                Ok(raw) => {
                    let height = height as u32;
                    // Subscription response returns us the tip header
                    if state.subscribe_id == Some(id) {
                        sender(HeaderResponse::Tip { height, raw });
                    } else {
                        sender(HeaderResponse::Header { height, raw });
                    }
                }
                Err(e) => sender(HeaderResponse::Error(e.into())),
            }
        }
        Response::HeaderNotif(HeaderNotification::Batch(BatchHeaderNotif { headers, .. }))
        | Response::BatchHeaderNotif(BatchHeaderNotif { headers, .. }) => {
            // Each notified header carries its own height; a batch is not
            // necessarily a contiguous run from headers[0]. Emit one Header
            // per entry at its own height rather than assuming contiguity.
            for h in &headers {
                match decode_header_hex(&h.raw_header) {
                    Ok(raw) => sender(HeaderResponse::Header {
                        height: h.height as u32,
                        raw,
                    }),
                    Err(e) => {
                        sender(HeaderResponse::Error(e.into()));
                        return;
                    }
                }
            }
        }
        Response::Headers(HeadersResponse {
            id,
            headers: Headers { raw_headers, .. },
        }) => {
            let Some(start) = state.get_headers_starts.remove(&id) else {
                log::warn!("Client::listen_headers() Headers: unknown id {id}");
                return;
            };
            match chunk_raw_headers(&raw_headers) {
                Ok(raws) => sender(HeaderResponse::Batch { start, raws }),
                Err(source) => sender(HeaderResponse::Error(HeaderError::GetHeadersDecode {
                    start,
                    source,
                })),
            }
        }
        Response::Error(e) => {
            if let Some(start) = state.get_headers_starts.remove(&e.id) {
                sender(HeaderResponse::Error(HeaderError::GetHeaders {
                    start,
                    error: e,
                }));
            } else {
                sender(HeaderResponse::Error(HeaderError::Server(e)));
            }
        }
        Response::Ping(_) => {}
        r => {
            log::error!("handle_header_response: unexpected {r:?}");
        }
    }
}

fn dispatch_header<RS>(
    client: &mut Client,
    state: &mut HeaderState,
    rq: HeaderRequest,
    send: &mpsc::Sender<RS>,
) -> Dispatch
where
    RS: From<HeaderResponse>,
{
    log::debug!("Client::listen_headers() recv request: {rq:?}");
    match rq {
        HeaderRequest::Subscribe => {
            if state.subscribe_id.is_some() {
                log::error!("Client::listen_headers() already subscribed to headers notifs");
                return Dispatch::Empty;
            }
            let mut req = Request::subscribe_headers();
            let id = client.register(&mut req);
            state.subscribe_id = Some(id);
            // Subscribe is fire-and-forget: its notification response carries no
            // request id and so cannot gate the pending batch. Only GetHeaders is
            // tracked below.
            if client.send_with_retry(std::slice::from_ref(&req), send, |e| {
                HeaderResponse::Error(HeaderError::SendSubscribe(e)).into()
            }) {
                Dispatch::Empty
            } else {
                Dispatch::Terminate
            }
        }
        HeaderRequest::GetHeaders { start, count } => {
            let mut req = Request::headers(start as usize, count as usize);
            let id = client.register(&mut req);
            state.get_headers_starts.insert(id, start);
            if client.send_with_retry(std::slice::from_ref(&req), send, |e| {
                HeaderResponse::Error(HeaderError::SendGetHeaders(e)).into()
            }) {
                Dispatch::Sent(vec![req])
            } else {
                Dispatch::Terminate
            }
        }
        HeaderRequest::Stop => {
            let _ = send.send(HeaderResponse::Stopped.into());
            Dispatch::Terminate
        }
    }
}

fn handle_header_responses<RS>(
    state: &mut HeaderState,
    responses: Vec<Response>,
    send: &mpsc::Sender<RS>,
) -> Flow
where
    RS: From<HeaderResponse>,
{
    for r in responses {
        let mut out: Vec<HeaderResponse> = Vec::new();
        handle_header_response(state, r, &mut |hr| out.push(hr));
        for hr in out {
            if send.send(hr.into()).is_err() {
                return Flow::Terminate;
            }
        }
    }
    Flow::Continue
}

pub fn listen_headers<RQ, RS>(client: Client, send: mpsc::Sender<RS>, recv: mpsc::Receiver<RQ>)
where
    RQ: Into<HeaderRequest> + Debug + Send + 'static,
    RS: From<HeaderResponse> + Debug + Send + 'static,
{
    log::debug!("Client::listen_headers()");
    run_listener(
        client,
        send,
        recv,
        HeaderState::default(),
        dispatch_header,
        |_client, state, responses, send| handle_header_responses(state, responses, send),
        |e| HeaderResponse::Error(HeaderError::Transport(e)).into(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::method::Method;

    const GENESIS_HEX_LEN: usize = 160;

    fn sample_header_hex() -> String {
        // Known regtest header from response.rs tests.
        "00000020835fdbdeeadd23463fad98b4e21aaa8519afde89eecd0eb224001317421cbb5f\
         5e636df02303e51280b586bc596ee9326bc849bbb5993e121a8cab7e6b60e8ab593fe166\
         ffff7f2000000000"
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    #[test]
    fn decode_header_hex_ok() {
        let hex = sample_header_hex();
        assert_eq!(hex.len(), GENESIS_HEX_LEN);
        let raw = decode_header_hex(&hex).unwrap();
        assert_eq!(raw.len(), 80);
        // sanity: round-trip
        let round = hex_conservative::DisplayHex::to_lower_hex_string(&raw[..]);
        assert_eq!(round, hex);
    }

    #[test]
    fn decode_header_hex_wrong_length() {
        // 78 bytes (156 hex chars).
        let hex: String = "ab".repeat(78);
        let err = decode_header_hex(&hex).unwrap_err();
        match err {
            DecodeError::HeaderLength(got) => assert_eq!(got, 78),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn chunk_raw_headers_three() {
        let a: String = "11".repeat(80);
        let b: String = "22".repeat(80);
        let c: String = "33".repeat(80);
        let concat = format!("{a}{b}{c}");
        let raws = chunk_raw_headers(&concat).unwrap();
        assert_eq!(raws.len(), 3);
        assert_eq!(raws[0][0], 0x11);
        assert_eq!(raws[1][0], 0x22);
        assert_eq!(raws[2][0], 0x33);
        assert!(raws[0].iter().all(|b| *b == 0x11));
        assert!(raws[1].iter().all(|b| *b == 0x22));
        assert!(raws[2].iter().all(|b| *b == 0x33));
    }

    #[test]
    fn chunk_raw_headers_bad_length() {
        // 80 + 40 bytes, not a multiple of 80.
        let hex: String = "ab".repeat(120);
        let err = chunk_raw_headers(&hex).unwrap_err();
        match err {
            DecodeError::HeadersAlignment(len) => assert_eq!(len, 120),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn dispatch_batch_header_notif_singleton_emits_notif() {
        let hex = sample_header_hex();
        let notif = BatchHeaderNotif {
            method: Method::HeadersSubscribe,
            headers: vec![Header {
                height: 119_367,
                raw_header: hex.clone(),
            }],
        };
        let mut state = HeaderState::default();
        let mut out = Vec::new();
        handle_header_response(&mut state, Response::BatchHeaderNotif(notif), &mut |hr| {
            out.push(hr)
        });
        assert_eq!(out.len(), 1);
        match &out[0] {
            HeaderResponse::Header { height, raw } => {
                assert_eq!(*height, 119_367);
                assert_eq!(&raw[..], &decode_header_hex(&hex).unwrap()[..]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn dispatch_batch_header_notif_emits_one_per_height() {
        let hex = sample_header_hex();
        let notif = BatchHeaderNotif {
            method: Method::HeadersSubscribe,
            headers: vec![
                Header {
                    height: 100,
                    raw_header: hex.clone(),
                },
                Header {
                    height: 101,
                    raw_header: hex.clone(),
                },
                Header {
                    height: 102,
                    raw_header: hex.clone(),
                },
            ],
        };
        let mut state = HeaderState::default();
        let mut out = Vec::new();
        handle_header_response(&mut state, Response::BatchHeaderNotif(notif), &mut |hr| {
            out.push(hr)
        });
        // Each notified header is emitted individually at its own height,
        // not collapsed into a contiguous Batch.
        assert_eq!(out.len(), 3);
        for (i, hr) in out.iter().enumerate() {
            match hr {
                HeaderResponse::Header { height, .. } => assert_eq!(*height, 100 + i as u32),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    #[test]
    fn dispatch_subscribe_reply_emits_tip() {
        let hex = sample_header_hex();
        let mut state = HeaderState {
            subscribe_id: Some(1),
            get_headers_starts: BTreeMap::new(),
        };

        // The id-matched single header is the subscription reply: the tip.
        // Ongoing new-block notifications arrive via the batch path
        // (see `dispatch_batch_header_notif_singleton_emits_notif`).
        let r1 = Response::HeaderNotif(HeaderNotification::Single(SingleHeaderNotif {
            id: 1,
            header: Header {
                height: 119_367,
                raw_header: hex.clone(),
            },
        }));
        let mut out = Vec::new();
        handle_header_response(&mut state, r1, &mut |hr| out.push(hr));
        assert_eq!(out.len(), 1);
        match &out[0] {
            HeaderResponse::Tip { height, .. } => assert_eq!(*height, 119_367),
            other => panic!("expected Tip, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_headers_response_uses_tracked_start() {
        let a: String = "11".repeat(80);
        let b: String = "22".repeat(80);
        let raw_headers = format!("{a}{b}");
        let mut state = HeaderState::default();
        state.get_headers_starts.insert(42, 1_000);

        let r = Response::Headers(HeadersResponse {
            id: 42,
            headers: Headers {
                count: 2,
                raw_headers,
                max: 2016,
            },
        });
        let mut out = Vec::new();
        handle_header_response(&mut state, r, &mut |hr| out.push(hr));
        assert_eq!(out.len(), 1);
        match &out[0] {
            HeaderResponse::Batch { start, raws } => {
                assert_eq!(*start, 1_000);
                assert_eq!(raws.len(), 2);
                assert_eq!(raws[0][0], 0x11);
                assert_eq!(raws[1][0], 0x22);
            }
            other => panic!("expected Batch, got {other:?}"),
        }
        // start tracking should have been consumed.
        assert!(state.get_headers_starts.is_empty());
    }

    #[test]
    fn dispatch_headers_decode_error_uses_tracked_start() {
        let mut state = HeaderState::default();
        state.get_headers_starts.insert(42, 1_000);
        let response = Response::Headers(HeadersResponse {
            id: 42,
            headers: Headers {
                count: 1,
                raw_headers: "11".to_string(),
                max: 2016,
            },
        });
        let mut out = Vec::new();

        handle_header_response(&mut state, response, &mut |hr| out.push(hr));

        assert!(matches!(
            &out[0],
            HeaderResponse::Error(HeaderError::GetHeadersDecode {
                start: 1_000,
                source: DecodeError::HeadersAlignment(1),
            })
        ));
        assert!(state.get_headers_starts.is_empty());
    }

    #[test]
    fn dispatch_error_response_tags_get_headers_failure() {
        use crate::electrum::response::{ErrorResponse, ErrorResult};

        let mut state = HeaderState::default();
        state.get_headers_starts.insert(7, 500);

        let r = Response::Error(ErrorResponse {
            id: 7,
            error: ErrorResult {
                code: 1,
                message: "boom".to_string(),
            },
        });
        let mut out = Vec::new();
        handle_header_response(&mut state, r, &mut |hr| out.push(hr));
        assert_eq!(out.len(), 1);
        match &out[0] {
            HeaderResponse::Error(HeaderError::GetHeaders { start, error }) => {
                assert_eq!(*start, 500);
                assert_eq!(error.error.message, "boom");
            }
            other => panic!("expected GetHeaders error, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_error_response_prunes_get_headers_starts() {
        use crate::electrum::response::{ErrorResponse, ErrorResult};

        let mut state = HeaderState::default();
        state.get_headers_starts.insert(7, 500);

        let r = Response::Error(ErrorResponse {
            id: 7,
            error: ErrorResult {
                code: 1,
                message: "boom".to_string(),
            },
        });
        let mut out = Vec::new();
        handle_header_response(&mut state, r, &mut |hr| out.push(hr));
        assert!(!state.get_headers_starts.contains_key(&7));
    }
}
