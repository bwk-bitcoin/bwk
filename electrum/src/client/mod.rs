pub mod header_listener;
mod listener;
pub mod tx_listener;
use crate::{
    electrum::{
        request::Request,
        response::{
            ErrorResponse, ErrorResult, Response, SHGetHistoryResponse, TxBroadcastResponse,
            TxGetResponse, TxGetResult,
        },
        types::ScriptHash,
    },
    raw_client::{self, Client as RawClient},
};
use bwk_utils::short_string;
use header_listener::listen_headers;
use hex_conservative::{FromHex, HexToBytesError};
use miniscript::bitcoin::{
    block::Header,
    consensus::{self, encode::serialize_hex, Decodable},
    OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    sync::mpsc,
    thread::{self},
    time::{Duration, Instant},
};
use tx_listener::listen_txs;

const SEND_MAX_RETRIES: usize = 3;
const SEND_RETRY_DELAY: Duration = Duration::from_millis(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Length of one merkle branch sibling.
pub const MERKLE_HASH_BYTES: usize = 32;
const SHORT_HEX_BYTES: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("transport error: {0}")]
    Transport(#[from] raw_client::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("failed to parse the transaction")]
    TxParsing,
    #[error("wrong response from electrum server")]
    WrongResponse,
    #[error("requested outpoint did not exist")]
    WrongOutPoint,
    #[error("requested transaction did not exist")]
    TxDoesNotExists,
    #[error("server rejected transaction: {0}")]
    Rejected(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid header hex: {0}")]
    HeaderHex(#[source] HexToBytesError),
    #[error("invalid header length: expected {expected}, got {0}", expected = Header::SIZE)]
    HeaderLength(usize),
    #[error("invalid headers hex: {0}")]
    HeadersHex(#[source] HexToBytesError),
    #[error("headers length {0} is not a multiple of {size}", size = Header::SIZE)]
    HeadersAlignment(usize),
    #[error("invalid merkle hex at index {index}: {source}")]
    MerkleHex {
        index: usize,
        #[source]
        source: HexToBytesError,
    },
    #[error("invalid merkle hash length at index {index}: expected {expected}, got {got}", expected = MERKLE_HASH_BYTES)]
    MerkleHashLength { index: usize, got: usize },
}

pub fn short_hash(s: &ScriptBuf) -> String {
    let s = ScriptHash::new(s).to_string();
    short_string(s, 10)
}

#[derive(Clone)]
pub enum CoinRequest {
    Subscribe(Vec<ScriptBuf>),
    History(Vec<ScriptBuf>),
    Txs(Vec<Txid>),
    GetTxMerkle { txid: Txid, height: u32 },
    Stop,
}

impl Debug for CoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subscribe(vec) => {
                let hashes: Vec<_> = vec.iter().map(short_hash).collect();
                f.debug_tuple("Subscribe").field(&hashes).finish()
            }
            Self::History(vec) => {
                let hashes: Vec<_> = vec.iter().map(short_hash).collect();
                f.debug_tuple("History").field(&hashes).finish()
            }
            Self::Txs(arg0) => f.debug_tuple("Txs").field(arg0).finish(),
            Self::GetTxMerkle { txid, height } => f
                .debug_struct("GetTxMerkle")
                .field("txid", &short_string(txid.to_string(), 10))
                .field("height", height)
                .finish(),
            Self::Stop => write!(f, "Stop"),
        }
    }
}

impl CoinRequest {
    /// Compact one-line description (counts only) for hot-path logging.
    pub fn summary(&self) -> String {
        match self {
            Self::Subscribe(v) => format!("Subscribe({})", v.len()),
            Self::History(v) => format!("History({})", v.len()),
            Self::Txs(v) => format!("Txs({})", v.len()),
            Self::GetTxMerkle { .. } => "GetTxMerkle".to_string(),
            Self::Stop => "Stop".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoinError {
    #[error("failed to send batch request: {0}")]
    Send(#[source] raw_client::Error),
    #[error("failed to decode transaction: {0}")]
    TxDecode(consensus::encode::FromHexError),
    #[error("merkle decode failed for {txid}@{height}: {source}")]
    MerkleDecode {
        txid: Txid,
        height: u32,
        source: DecodeError,
    },
    #[error("merkle fetch failed for {txid}@{height}: {error}")]
    MerkleFetch {
        txid: Txid,
        height: u32,
        error: ErrorResponse,
    },
    #[error("server error: {0}")]
    Server(ErrorResponse),
    #[error("transport error: {0}")]
    Transport(#[source] raw_client::Error),
}

pub enum CoinResponse {
    Status(BTreeMap<ScriptBuf, Option<String>>),
    History(BTreeMap<ScriptBuf, Vec<(Txid, Option<u64> /* height */)>>),
    Txs(Vec<Transaction>),
    TxMerkle {
        txid: Txid,
        height: u32,
        branch: Vec<[u8; MERKLE_HASH_BYTES]>,
        pos: u32,
    },
    Stopped,
    Error(CoinError),
}

impl Debug for CoinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Txs(vec) => {
                let txids: Vec<_> = vec.iter().map(|tx| tx.compute_txid()).collect();
                f.debug_tuple("Txs").field(&txids).finish()
            }
            Self::Status(map) => {
                let statuses: Vec<_> = map
                    .iter()
                    .map(|(spk, status)| {
                        format!(
                            "{} => {:?}",
                            short_hash(spk),
                            status.as_ref().map(|st| short_string(st.to_string(), 10))
                        )
                    })
                    .collect();
                f.debug_tuple("Status").field(&statuses).finish()
            }
            Self::History(map) => {
                let map: Vec<_> = map
                    .iter()
                    .map(|(spk, v)| {
                        let conf: Vec<_> =
                            v.iter().filter(|(_, height)| height.is_some()).collect();
                        format!(
                            "{} => conf: {}, total: {}",
                            short_hash(spk),
                            conf.len(),
                            v.len()
                        )
                    })
                    .collect();
                f.debug_tuple("History").field(&map).finish()
            }
            Self::TxMerkle { txid, height, .. } => f
                .debug_struct("TxMerkle")
                .field("txid", &short_string(txid.to_string(), 10))
                .field("height", height)
                .finish(),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error(e) => write!(f, "Error({e})"),
        }
    }
}

impl CoinResponse {
    /// Compact one-line description (counts only) for hot-path logging.
    pub fn summary(&self) -> String {
        match self {
            Self::Status(m) => format!("Status({})", m.len()),
            Self::History(m) => format!("History({} scripts)", m.len()),
            Self::Txs(v) => format!("Txs({})", v.len()),
            Self::TxMerkle { .. } => "TxMerkle".to_string(),
            Self::Stopped => "Stopped".to_string(),
            Self::Error(e) => format!("Error({e})"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum HeaderRequest {
    Subscribe,
    GetHeaders { start: u32, count: u32 },
    Stop,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("failed to send subscribe: {0}")]
    SendSubscribe(#[source] raw_client::Error),
    #[error("failed to send get_headers: {0}")]
    SendGetHeaders(#[source] raw_client::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("server error: {0}")]
    Server(ErrorResponse),
    #[error("get_headers starting at {start} failed: {error}")]
    GetHeaders { start: u32, error: ErrorResponse },
    #[error("failed to decode get_headers response starting at {start}: {source}")]
    GetHeadersDecode { start: u32, source: DecodeError },
    #[error("transport error: {0}")]
    Transport(#[source] raw_client::Error),
}

pub enum HeaderResponse {
    Tip {
        height: u32,
        raw: [u8; Header::SIZE],
    },
    Header {
        height: u32,
        raw: [u8; Header::SIZE],
    },
    Batch {
        start: u32,
        raws: Vec<[u8; Header::SIZE]>,
    },
    Stopped,
    Error(HeaderError),
}

fn short_hex(raw: &[u8; Header::SIZE]) -> String {
    hex_conservative::DisplayHex::to_lower_hex_string(&raw[..SHORT_HEX_BYTES])
}

// We manually impl Debug in order to show only short hashes
impl Debug for HeaderResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tip { height, raw } => f
                .debug_struct("Tip")
                .field("height", height)
                .field("raw", &short_hex(raw))
                .finish(),
            Self::Header { height, raw } => f
                .debug_struct("Header")
                .field("height", height)
                .field("raw", &short_hex(raw))
                .finish(),
            Self::Batch { start, raws } => f
                .debug_struct("Batch")
                .field("start", start)
                .field("count", &raws.len())
                .finish(),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error(e) => write!(f, "Error({e})"),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    inner: RawClient,
    index: HashMap<usize, Request>,
    last_id: usize,
    url: String,
    port: u16,
}

impl Client {
    /// Create a new electrum client.
    ///
    /// # Arguments
    /// * `address` - url/ip of the electrum server as String
    /// * `port` - port of the electrum server
    pub fn new(address: &str, port: u16) -> Result<Self, Error> {
        let ssl = address.starts_with("ssl://");
        let address = address.to_string().replace("ssl://", "");
        let mut inner = RawClient::new_ssl_maybe(&address, port, ssl);
        inner.try_connect(Some(CONNECT_TIMEOUT))?;
        Ok(Client {
            inner,
            index: HashMap::new(),
            last_id: 0,
            url: address,
            port,
        })
    }

    /// Create a new local electrum client: SSL certificate validation is disabled in
    ///   order to be used with self-signed certificates.
    ///
    /// # Arguments
    /// * `address` - url/ip of the electrum server as String
    /// * `port` - port of the electrum server
    pub fn new_local(address: &str, port: u16) -> Result<Self, Error> {
        let ssl = address.starts_with("ssl://");
        let address = address.to_string().replace("ssl://", "");
        let mut inner = RawClient::new_ssl_maybe(&address, port, ssl).verif_certificate(false);
        inner.try_connect(None)?;
        Ok(Client {
            inner,
            index: HashMap::new(),
            last_id: 0,
            url: address,
            port,
        })
    }

    /// Generate a new request id
    fn id(&mut self) -> usize {
        self.last_id = self.last_id.wrapping_add(1);
        self.last_id
    }

    fn register(&mut self, req: &mut Request) -> usize {
        let id = self.id();
        req.id = id;
        self.index.insert(req.id, req.clone());
        id
    }

    /// Send `batch`, retrying a bounded number of times on transport error.
    /// On give-up the error is reported to `send` via `make_err`. Returns
    /// `false` when the consumer channel is closed, so the caller can stop.
    fn send_with_retry<RS>(
        &mut self,
        batch: &[Request],
        send: &mpsc::Sender<RS>,
        make_err: impl Fn(raw_client::Error) -> RS,
    ) -> bool {
        let mut retry = 0usize;
        while let Err(e) = self.inner.try_send_batch(batch.iter().collect()) {
            retry += 1;
            if retry > SEND_MAX_RETRIES {
                return send.send(make_err(e)).is_ok();
            }
            thread::sleep(SEND_RETRY_DELAY);
        }
        true
    }

    /// Spawn the tx listener on a background thread. `RQ`/`RS` are generic
    /// so this listener can be used standalone, outside a bwk/bwk-sp
    /// `Account`, with the consumer's own wrapper request/response types
    /// instead of `CoinRequest`/`CoinResponse` directly.
    pub fn listen_txs<RQ, RS>(self) -> (mpsc::Sender<RQ>, mpsc::Receiver<RS>)
    where
        RQ: Into<CoinRequest> + Debug + Send + 'static,
        RS: From<CoinResponse> + Debug + Send + 'static,
    {
        let (sender, request) = mpsc::channel();
        let (response, receiver) = mpsc::channel();
        thread::spawn(move || listen_txs(self, response, request));

        (sender, receiver)
    }

    /// Spawn the header listener on a background thread. `RQ`/`RS` are
    /// generic so this listener can be used standalone, outside a bwk/bwk-sp
    /// `Account`, with the consumer's own wrapper request/response types
    /// instead of `HeaderRequest`/`HeaderResponse` directly.
    pub fn listen_headers<RQ, RS>(self) -> (mpsc::Sender<RQ>, mpsc::Receiver<RS>)
    where
        RQ: Into<HeaderRequest> + Debug + Send + 'static,
        RS: From<HeaderResponse> + Debug + Send + 'static,
    {
        let (sender, request) = mpsc::channel();
        let (response, receiver) = mpsc::channel();
        thread::spawn(move || listen_headers(self, response, request));

        (sender, receiver)
    }

    /// Try to get a transaction by its txid
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail to send the request
    ///   - parsing response fails
    ///   - the response is not of expected type
    ///   - the transaction does not exist
    pub fn get_tx(&mut self, txid: Txid) -> Result<Transaction, Error> {
        let request = Request::tx_get(txid).id(self.id());
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        for r in resp {
            if let Response::TxGet(TxGetResponse {
                id,
                result: TxGetResult::Raw(res),
            }) = r
            {
                if req_id == id {
                    self.index.remove(&req_id);
                    let raw_tx = match Vec::<u8>::from_hex(&res) {
                        Ok(raw) => raw,
                        Err(_) => {
                            return Err(Error::TxParsing);
                        }
                    };
                    let tx: Result<Transaction, _> =
                        Decodable::consensus_decode(&mut raw_tx.as_slice());
                    return tx.map_err(|_| Error::TxParsing);
                }
            } else if let Response::Error(ErrorResponse { id, .. }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    // NOTE: it's very likely if we receive an error response from the server
                    // it's because the txid does not match any Transaction, but maybe we can
                    // do a better handling of the error case (for this we need check if responses
                    // from all electrum server implementations are consistant).
                    return Err(Error::TxDoesNotExists);
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Get coins that pay to the given spk and their related transaction.
    /// This method will make several calls to the electrum server:
    ///   - it will first request a list of all transactions txid that have
    ///     an output paying to the spk.
    ///   - it will then fetch all txs, store them and extract all the coins
    ///     that pay to the given spk.
    ///   - it will return a list of (TxOut, OutPoint) and a map of transactions.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - a call to the electrum server fail
    #[allow(clippy::type_complexity)]
    pub fn get_coins_at(
        &mut self,
        script: &Script,
    ) -> Result<(Vec<(TxOut, OutPoint)>, HashMap<Txid, Transaction>), Error> {
        let mut txouts = Vec::new();
        let mut transactions = HashMap::new();
        let txs = self.get_coins_tx_at(script)?;
        for txid in txs {
            let tx = self.get_tx(txid)?;
            for (i, txout) in tx.output.iter().enumerate() {
                if *txout.script_pubkey == *script {
                    let outpoint = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    txouts.push((txout.clone(), outpoint));
                }
            }
            transactions.insert(txid, tx);
        }
        Ok((txouts, transactions))
    }

    /// Get a list of txid of all transaction that have an output paying to the
    ///   given spk
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail sending the request
    ///   - receive a wrong response
    pub fn get_coins_tx_at(&mut self, script: &Script) -> Result<Vec<Txid>, Error> {
        let request = Request::sh_get_history(script).id(self.id());
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        for r in resp {
            if let Response::SHGetHistory(SHGetHistoryResponse { id, history }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    let history: Vec<_> = history.into_iter().map(|r| r.txid).collect();
                    return Ok(history);
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Broadcast the given transaction.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail to send the request
    ///   - get a wrong response
    pub fn broadcast(&mut self, tx: &Transaction) -> Result<(), Error> {
        let raw_tx = serialize_hex(tx);
        log::debug!("electrum::Client().broadcast(): {raw_tx:?}");
        let request = Request::tx_broadcast(raw_tx);
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        log::debug!("electrum::Client().broadcast(): receive response: {resp:?}");
        for r in resp {
            if let Response::TxBroadcast(TxBroadcastResponse { id, .. }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    return Ok(());
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Broadcast a fully signed transaction and return its txid on success.
    ///
    /// Unlike [`Client::broadcast`], a server rejection (`Response::Error`) is
    /// surfaced as [`Error::Rejected`] with the server's message instead of
    /// the opaque [`Error::WrongResponse`].
    pub fn broadcast_tx(&mut self, tx: &Transaction) -> Result<Txid, Error> {
        let raw_tx = serialize_hex(tx);
        let request = Request::tx_broadcast(raw_tx);
        let req_id = request.id;
        self.inner.try_send(&request)?;
        self.index.insert(req_id, request);
        // electrs may answer with an empty response while it is still busy with a
        // prior request, which surfaces as a parse error rather than our answer.
        // Re-read until the response carrying our id arrives (or we give up),
        // instead of failing on the transient empty line.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let resp = match self.inner.recv(&self.index) {
                Ok(r) => r,
                Err(_) if Instant::now() < deadline => continue,
                Err(e) => {
                    self.index.remove(&req_id);
                    return Err(e.into());
                }
            };
            for r in resp {
                match r {
                    Response::TxBroadcast(TxBroadcastResponse { id, .. }) if id == req_id => {
                        self.index.remove(&req_id);
                        return Ok(tx.compute_txid());
                    }
                    Response::Error(ErrorResponse {
                        id,
                        error: ErrorResult { message, .. },
                    }) if id == req_id => {
                        self.index.remove(&req_id);
                        return Err(Error::Rejected(message));
                    }
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                self.index.remove(&req_id);
                return Err(Error::WrongResponse);
            }
        }
    }

    /// Returns the URL of the electrum client.
    ///
    /// # Returns
    /// A `String` containing the URL of the electrum server.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Returns the port of the electrum client.
    ///
    /// # Returns
    /// A `u16` containing the port of the electrum server.
    pub fn port(&self) -> u16 {
        self.port
    }
}

fn decode_tx_merkle_branch(merkle: &[String]) -> Result<Vec<[u8; MERKLE_HASH_BYTES]>, DecodeError> {
    let mut out = Vec::with_capacity(merkle.len());
    for (idx, hex) in merkle.iter().enumerate() {
        let bytes = Vec::<u8>::from_hex(hex)
            .map_err(|source| DecodeError::MerkleHex { index: idx, source })?;
        if bytes.len() != MERKLE_HASH_BYTES {
            return Err(DecodeError::MerkleHashLength {
                index: idx,
                got: bytes.len(),
            });
        }
        let mut raw = [0u8; MERKLE_HASH_BYTES];
        raw.copy_from_slice(&bytes);
        // Electrum reports siblings as display-order (big-endian) hex.
        // Reverse to internal (little-endian) order here, so consumers feed
        // the branch straight into merkle verification.
        raw.reverse();
        out.push(raw);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::response::TxGetMerkleResponse;

    #[test]
    fn decode_tx_merkle_branch_sample() {
        // Sample from electrum/src/electrum/response.rs::tests::tx_get_merkle.
        let response = r#"{"jsonrpc": "2.0", "result": {"block_height": 200000, "merkle": ["ffa0267c8f2af736858894d6f3e5081a05e2ec16dc98f78a80f376ce35077491", "d0039b6be844e631698f57fa02bbfbfb5e8b680f3ebb17646631e6ec9f91f6e6", "bbe3063ce3d04c2e3f18e494a287867f81ad1182b62a1ecb3e1ea2686edcea20", "1d15a2423f52d4aa281a2ac389c0a5a601ed08bdf814494ddf7697196860b801", "b63e58ec9f5ee2e268f1540af8bb0e5b8fd0ce7cd6877a174e6178c676d6b574", "7407724b98c77cdbf070f3fe297839de2bef50fead98b452883f0f3a4643cde2", "d029f17725e71e3c025bd7d0505006dc859af5450d0b6dd092ee88c0d98f9a25", "e4df974d81ab4fdf35f635024a01f20aa88af9f520215708b339dbc5bceddf63", "20f4202f18666483306f175e1c9c521741845afcf2710f0b0d42602ac72c5fd6"], "pos": 2}, "id": 0}"#;
        let resp: TxGetMerkleResponse = serde_json::from_str(response).unwrap();
        let merkle = resp.result.merkle;
        assert_eq!(merkle.len(), 9);
        let branch = decode_tx_merkle_branch(&merkle).unwrap();
        assert_eq!(branch.len(), 9);
        for h in &branch {
            assert_eq!(h.len(), 32);
        }
        // The decoder returns internal (little-endian) order: each sibling is
        // the byte-reverse of its display-order hex above.
        let first_hex = hex_conservative::DisplayHex::to_lower_hex_string(&branch[0][..]);
        assert_eq!(
            first_hex,
            "91740735ce76f3808af798dc16ece2051a08e5f3d694888536f72a8f7c26a0ff"
        );
        let last_hex = hex_conservative::DisplayHex::to_lower_hex_string(&branch[8][..]);
        assert_eq!(
            last_hex,
            "d65f2cc72a60420d0b0f71f2fc5a844117529c1c5e176f30836466182f20f420"
        );
    }

    #[test]
    fn decode_tx_merkle_branch_bad_length() {
        // 30 bytes (60 hex chars) instead of 32.
        let merkle = vec!["ab".repeat(30)];
        let err = decode_tx_merkle_branch(&merkle).unwrap_err();
        match err {
            DecodeError::MerkleHashLength { index, got } => {
                assert_eq!(index, 0);
                assert_eq!(got, 30);
            }
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn decode_tx_merkle_branch_bad_hex() {
        let merkle = vec!["zz".repeat(32)];
        let err = decode_tx_merkle_branch(&merkle).unwrap_err();
        match err {
            DecodeError::MerkleHex { index, .. } => assert_eq!(index, 0),
            e => panic!("unexpected error: {e:?}"),
        }
    }
}
