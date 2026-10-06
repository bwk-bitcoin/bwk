use crate::electrum::{
    request::Request,
    response::{
        GetMerkleResult, HeaderResponse, HistoryResult, Response, SHGetHistoryResponse,
        SHNotification, SHSubscribeResponse, TxGetMerkleResponse, TxGetResponse, TxGetResult,
    },
    types::ScriptHash,
};
use miniscript::bitcoin::{block::Header, consensus, ScriptBuf, Transaction, Txid};
use std::{collections::BTreeMap, fmt::Debug, sync::mpsc};

use super::{
    decode_tx_merkle_branch,
    listener::{run_listener, Dispatch, Flow},
    Client, CoinError, CoinRequest, CoinResponse,
};

/// Request-id and script-hash tracking shared by the request and response
/// halves of the listener.
#[derive(Default)]
struct TxState {
    req_id_spk: BTreeMap<usize /* request_id */, ScriptBuf>,
    req_id_tx_merkle: BTreeMap<usize /* request_id */, (Txid, u32 /* height */)>,
    req_id_header: BTreeMap<usize /* request_id */, u32 /* height */>,
    watched_spks_sh: BTreeMap<usize /* request_id */, ScriptHash>,
    sh_spk: BTreeMap<ScriptHash, ScriptBuf>,
}

/// One read's worth of folded responses, grouped for batched emission.
#[derive(Default)]
struct TxBatch {
    statuses: BTreeMap<ScriptBuf, Option<String>>,
    txs: Vec<Transaction>,
    histories: BTreeMap<ScriptBuf, Vec<(Txid, Option<u64> /* height */)>>,
    headers: BTreeMap<u32 /* height */, Header>,
    /// TxMerkle results and errors, emitted after the grouped responses.
    trailing: Vec<CoinResponse>,
}

fn handle_tx_response(state: &mut TxState, batch: &mut TxBatch, r: Response) {
    match r {
        Response::SHSubscribe(SHSubscribeResponse { result: status, id }) => {
            let Some(sh) = state.watched_spks_sh.get(&id) else {
                log::warn!("Client::listen_txs() SHSubscribe: unknown id {id}");
                return;
            };
            let Some(spk) = state.sh_spk.get(sh) else {
                log::warn!("Client::listen_txs() SHSubscribe: unknown sh {sh}");
                return;
            };
            batch.statuses.insert(spk.clone(), status);
        }
        Response::SHNotification(SHNotification {
            status: (sh, status),
            ..
        }) => {
            let Some(spk) = state.sh_spk.get(&sh) else {
                log::warn!("Client::listen_txs() SHNotification: unknown sh {sh}");
                return;
            };
            batch.statuses.insert(spk.clone(), status);
        }
        Response::SHGetHistory(SHGetHistoryResponse { history, id }) => {
            let Some(spk) = state.req_id_spk.remove(&id) else {
                log::warn!("Client::listen_txs() SHGetHistory: unknown id {id}");
                return;
            };
            let mut spk_hist = vec![];
            for tx in history {
                let HistoryResult { txid, height, .. } = tx;
                let height = if height < 1 {
                    None
                } else {
                    Some(height as u64)
                };
                spk_hist.push((txid, height));
            }
            batch.histories.insert(spk, spk_hist);
        }
        Response::TxGet(TxGetResponse {
            result: TxGetResult::Raw(raw_tx),
            ..
        }) => match consensus::encode::deserialize_hex::<Transaction>(&raw_tx) {
            Ok(tx) => batch.txs.push(tx),
            Err(source) => batch
                .trailing
                .push(CoinResponse::Error(CoinError::TxDecode(source))),
        },
        Response::TxGetMerkle(TxGetMerkleResponse { id, result }) => {
            let Some((txid, height)) = state.req_id_tx_merkle.remove(&id) else {
                log::warn!("Client::listen_txs() TxGetMerkle: unknown id {id}");
                return;
            };
            let GetMerkleResult { merkle, tx_pos, .. } = result;
            let pos = tx_pos as u32;
            match decode_tx_merkle_branch(&merkle) {
                Ok(branch) => batch.trailing.push(CoinResponse::TxMerkle {
                    txid,
                    height,
                    branch,
                    pos,
                }),
                Err(source) => batch
                    .trailing
                    .push(CoinResponse::Error(CoinError::MerkleDecode {
                        txid,
                        height,
                        source,
                    })),
            }
        }
        Response::Header(HeaderResponse { id, raw_header }) => {
            let Some(height) = state.req_id_header.remove(&id) else {
                log::warn!("Client::listen_txs() Header: unknown id {id}");
                return;
            };
            match consensus::encode::deserialize_hex::<Header>(&raw_header) {
                Ok(header) => {
                    batch.headers.insert(height, header);
                }
                Err(source) => batch
                    .trailing
                    .push(CoinResponse::Error(CoinError::HeaderDecode {
                        height,
                        source,
                    })),
            }
        }
        Response::Error(e) => {
            if let Some((txid, height)) = state.req_id_tx_merkle.remove(&e.id) {
                batch
                    .trailing
                    .push(CoinResponse::Error(CoinError::MerkleFetch {
                        txid,
                        height,
                        error: e,
                    }));
            } else if let Some(height) = state.req_id_header.remove(&e.id) {
                batch
                    .trailing
                    .push(CoinResponse::Error(CoinError::HeaderFetch {
                        height,
                        error: e,
                    }));
            } else {
                batch
                    .trailing
                    .push(CoinResponse::Error(CoinError::Server(e)));
            }
        }
        _ => {}
    }
}

/// Emission order: History, Status, Txs, Headers, then the trailing
/// merkle/error responses.
fn drain_batch(batch: TxBatch) -> Vec<CoinResponse> {
    let TxBatch {
        statuses,
        txs,
        histories,
        headers,
        trailing,
    } = batch;
    let mut out = Vec::new();
    if !histories.is_empty() {
        out.push(CoinResponse::History(histories));
    }
    if !statuses.is_empty() {
        out.push(CoinResponse::Status(statuses));
    }
    if !txs.is_empty() {
        out.push(CoinResponse::Txs(txs));
    }
    if !headers.is_empty() {
        out.push(CoinResponse::Headers(headers));
    }
    out.extend(trailing);
    out
}

fn send_batch<RS>(client: &mut Client, batch: Vec<Request>, send: &mpsc::Sender<RS>) -> Dispatch
where
    RS: From<CoinResponse>,
{
    if batch.is_empty() {
        return Dispatch::Empty;
    }
    log::debug!("Client::listen_txs() last_request = {}", batch.len());
    if client.send_with_retry(&batch, send, |e| {
        CoinResponse::Error(CoinError::Send(e)).into()
    }) {
        Dispatch::Sent(batch)
    } else {
        Dispatch::Terminate
    }
}

fn dispatch_tx<RS>(
    client: &mut Client,
    state: &mut TxState,
    rq: CoinRequest,
    send: &mpsc::Sender<RS>,
) -> Dispatch
where
    RS: From<CoinResponse>,
{
    log::debug!("Client::listen_txs() recv request: {}", rq.summary());
    match rq {
        CoinRequest::Subscribe(spks) => {
            let mut batch = vec![];
            for spk in spks {
                let mut sub = Request::subscribe_sh(&spk);
                let id = client.register(&mut sub);
                let sh = ScriptHash::new(&spk);
                state.watched_spks_sh.insert(id, sh);
                state.sh_spk.insert(sh, spk);
                batch.push(sub);
            }
            send_batch(client, batch, send)
        }
        CoinRequest::History(sbfs) => {
            let mut batch = vec![];
            for spk in sbfs {
                let mut history = Request::sh_get_history(&spk);
                let id = client.register(&mut history);
                state.req_id_spk.insert(id, spk);
                batch.push(history);
            }
            send_batch(client, batch, send)
        }
        CoinRequest::Txs(txids) => {
            let mut batch = vec![];
            for txid in txids {
                let mut tx = Request::tx_get(txid);
                client.register(&mut tx);
                batch.push(tx);
            }
            send_batch(client, batch, send)
        }
        CoinRequest::GetTxMerkle { txid, height } => {
            let mut req = Request::tx_get_merkle(txid, height as usize);
            let id = client.register(&mut req);
            log::debug!("Client::listen_txs() tx_get_merkle request: {req:?}");
            state.req_id_tx_merkle.insert(id, (txid, height));
            send_batch(client, vec![req], send)
        }
        CoinRequest::Headers(heights) => {
            let mut batch = vec![];
            for height in heights {
                let mut header = Request::header(height as usize);
                let id = client.register(&mut header);
                state.req_id_header.insert(id, height);
                batch.push(header);
            }
            send_batch(client, batch, send)
        }
        CoinRequest::Stop => {
            let _ = send.send(CoinResponse::Stopped.into());
            Dispatch::Terminate
        }
    }
}

fn handle_tx_responses<RS>(
    state: &mut TxState,
    responses: Vec<Response>,
    send: &mpsc::Sender<RS>,
) -> Flow
where
    RS: From<CoinResponse>,
{
    let mut batch = TxBatch::default();
    for r in responses {
        handle_tx_response(state, &mut batch, r);
    }
    for rsp in drain_batch(batch) {
        log::debug!("Client::listen_txs() send response: {}", rsp.summary());
        if send.send(rsp.into()).is_err() {
            return Flow::Terminate;
        }
    }
    Flow::Continue
}

pub fn listen_txs<RQ, RS>(client: Client, send: mpsc::Sender<RS>, recv: mpsc::Receiver<RQ>)
where
    RQ: Into<CoinRequest> + Debug + Send + 'static,
    RS: From<CoinResponse> + Debug + Send + 'static,
{
    log::debug!("Client::listen_txs()");
    run_listener(
        client,
        send,
        recv,
        TxState::default(),
        dispatch_tx,
        |_client, state, responses, send| handle_tx_responses(state, responses, send),
        |e| CoinResponse::Error(CoinError::Transport(e)).into(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::{
        method::Method,
        response::{ErrorResponse, ErrorResult},
    };
    use std::str::FromStr;

    // Minimal legacy tx: one all-zero input, one empty output.
    fn raw_tx_hex() -> String {
        use miniscript::bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, TxIn, TxOut,
            Witness,
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        consensus::encode::serialize_hex(&tx)
    }

    fn sample_spk() -> ScriptBuf {
        ScriptBuf::from_hex("0014000102030405060708090a0b0c0d0e0f10111213").unwrap()
    }

    fn sample_txid() -> Txid {
        Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap()
    }

    fn state_with_merkle(id: usize, height: u32) -> TxState {
        let mut state = TxState::default();
        state.req_id_tx_merkle.insert(id, (sample_txid(), height));
        state
    }

    #[test]
    fn sh_subscribe_maps_id_to_spk() {
        let spk = sample_spk();
        let sh = ScriptHash::new(&spk);
        let mut state = TxState::default();
        state.watched_spks_sh.insert(3, sh);
        state.sh_spk.insert(sh, spk.clone());

        let mut batch = TxBatch::default();
        let r = Response::SHSubscribe(SHSubscribeResponse {
            id: 3,
            result: Some("abcd".to_string()),
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.statuses.len(), 1);
        assert_eq!(batch.statuses.get(&spk), Some(&Some("abcd".to_string())));
    }

    #[test]
    fn sh_subscribe_unknown_id_ignored() {
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::SHSubscribe(SHSubscribeResponse {
            id: 99,
            result: None,
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert!(batch.statuses.is_empty());
        assert!(batch.trailing.is_empty());
    }

    #[test]
    fn sh_notification_unknown_sh_ignored() {
        let spk = sample_spk();
        let sh = ScriptHash::new(&spk);
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::SHNotification(SHNotification {
            method: Method::ScriptHashSubscribe,
            status: (sh, Some("abcd".to_string())),
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert!(batch.statuses.is_empty());
    }

    #[test]
    fn sh_get_history_height_mapping() {
        let spk = sample_spk();
        let mut state = TxState::default();
        state.req_id_spk.insert(5, spk.clone());

        let mut batch = TxBatch::default();
        let r = Response::SHGetHistory(SHGetHistoryResponse {
            id: 5,
            history: vec![
                HistoryResult {
                    height: -1,
                    txid: sample_txid(),
                    fee: None,
                },
                HistoryResult {
                    height: 0,
                    txid: sample_txid(),
                    fee: None,
                },
                HistoryResult {
                    height: 1234,
                    txid: sample_txid(),
                    fee: None,
                },
            ],
        });
        handle_tx_response(&mut state, &mut batch, r);
        let hist = batch.histories.get(&spk).unwrap();
        assert_eq!(hist.len(), 3);
        assert_eq!(hist[0].1, None);
        assert_eq!(hist[1].1, None);
        assert_eq!(hist[2].1, Some(1234));
        assert!(state.req_id_spk.is_empty());
    }

    #[test]
    fn tx_get_decodes_raw_tx() {
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::TxGet(TxGetResponse {
            id: 7,
            result: TxGetResult::Raw(raw_tx_hex()),
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.txs.len(), 1);
        assert!(batch.trailing.is_empty());
    }

    #[test]
    fn tx_get_bad_hex_yields_tx_decode_error() {
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::TxGet(TxGetResponse {
            id: 7,
            result: TxGetResult::Raw("zzzz".to_string()),
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert!(batch.txs.is_empty());
        assert_eq!(batch.trailing.len(), 1);
        match &batch.trailing[0] {
            CoinResponse::Error(CoinError::TxDecode(_)) => {}
            other => panic!("expected TxDecode error, got {other:?}"),
        }
    }

    #[test]
    fn tx_get_merkle_known_id_emits_merkle() {
        let mut state = state_with_merkle(9, 1234);
        let mut batch = TxBatch::default();
        let r = Response::TxGetMerkle(TxGetMerkleResponse {
            id: 9,
            result: GetMerkleResult {
                merkle: vec!["ab".repeat(32), "cd".repeat(32)],
                block_height: 1234,
                tx_pos: 2,
            },
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.trailing.len(), 1);
        match &batch.trailing[0] {
            CoinResponse::TxMerkle {
                txid,
                height,
                branch,
                pos,
            } => {
                assert_eq!(*txid, sample_txid());
                assert_eq!(*height, 1234);
                assert_eq!(branch.len(), 2);
                assert_eq!(*pos, 2);
            }
            other => panic!("expected TxMerkle, got {other:?}"),
        }
        assert!(state.req_id_tx_merkle.is_empty());
    }

    #[test]
    fn tx_get_merkle_unknown_id_ignored() {
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::TxGetMerkle(TxGetMerkleResponse {
            id: 9,
            result: GetMerkleResult {
                merkle: vec![],
                block_height: 1234,
                tx_pos: 0,
            },
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert!(batch.trailing.is_empty());
    }

    #[test]
    fn tx_get_merkle_bad_hash_yields_merkle_decode_error() {
        let mut state = state_with_merkle(9, 1234);
        let mut batch = TxBatch::default();
        let r = Response::TxGetMerkle(TxGetMerkleResponse {
            id: 9,
            result: GetMerkleResult {
                merkle: vec!["ab".to_string()],
                block_height: 1234,
                tx_pos: 0,
            },
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.trailing.len(), 1);
        match &batch.trailing[0] {
            CoinResponse::Error(CoinError::MerkleDecode { txid, height, .. }) => {
                assert_eq!(*txid, sample_txid());
                assert_eq!(*height, 1234);
            }
            other => panic!("expected MerkleDecode error, got {other:?}"),
        }
    }

    #[test]
    fn error_with_merkle_id_yields_merkle_fetch() {
        let mut state = state_with_merkle(11, 4321);
        let mut batch = TxBatch::default();
        let r = Response::Error(ErrorResponse {
            id: 11,
            error: ErrorResult {
                code: 1,
                message: "boom".to_string(),
            },
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.trailing.len(), 1);
        match &batch.trailing[0] {
            CoinResponse::Error(CoinError::MerkleFetch {
                txid,
                height,
                error,
            }) => {
                assert_eq!(*txid, sample_txid());
                assert_eq!(*height, 4321);
                assert_eq!(error.error.message, "boom");
            }
            other => panic!("expected MerkleFetch error, got {other:?}"),
        }
        assert!(state.req_id_tx_merkle.is_empty());
    }

    #[test]
    fn error_without_merkle_id_yields_server_error() {
        let mut state = TxState::default();
        let mut batch = TxBatch::default();
        let r = Response::Error(ErrorResponse {
            id: 11,
            error: ErrorResult {
                code: 1,
                message: "boom".to_string(),
            },
        });
        handle_tx_response(&mut state, &mut batch, r);
        assert_eq!(batch.trailing.len(), 1);
        match &batch.trailing[0] {
            CoinResponse::Error(CoinError::Server(e)) => {
                assert_eq!(e.error.message, "boom");
            }
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[test]
    fn drain_batch_orders_history_status_txs_trailing() {
        let spk = sample_spk();
        let sh = ScriptHash::new(&spk);
        let mut state = TxState::default();
        state.watched_spks_sh.insert(1, sh);
        state.sh_spk.insert(sh, spk.clone());
        state.req_id_spk.insert(2, spk.clone());
        state.req_id_tx_merkle.insert(3, (sample_txid(), 1234));

        let mut batch = TxBatch::default();
        handle_tx_response(
            &mut state,
            &mut batch,
            Response::TxGetMerkle(TxGetMerkleResponse {
                id: 3,
                result: GetMerkleResult {
                    merkle: vec!["ab".repeat(32)],
                    block_height: 1234,
                    tx_pos: 0,
                },
            }),
        );
        handle_tx_response(
            &mut state,
            &mut batch,
            Response::TxGet(TxGetResponse {
                id: 4,
                result: TxGetResult::Raw(raw_tx_hex()),
            }),
        );
        handle_tx_response(
            &mut state,
            &mut batch,
            Response::SHSubscribe(SHSubscribeResponse {
                id: 1,
                result: Some("abcd".to_string()),
            }),
        );
        handle_tx_response(
            &mut state,
            &mut batch,
            Response::SHGetHistory(SHGetHistoryResponse {
                id: 2,
                history: vec![HistoryResult {
                    height: 1234,
                    txid: sample_txid(),
                    fee: None,
                }],
            }),
        );

        let out = drain_batch(batch);
        assert_eq!(out.len(), 4);
        assert!(matches!(&out[0], CoinResponse::History(m) if m.len() == 1));
        assert!(matches!(&out[1], CoinResponse::Status(m) if m.len() == 1));
        assert!(matches!(&out[2], CoinResponse::Txs(v) if v.len() == 1));
        assert!(matches!(&out[3], CoinResponse::TxMerkle { pos: 0, .. }));
    }
}
