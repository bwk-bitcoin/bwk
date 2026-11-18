//! Wire vocabulary a manager and its back end speak: [`Request`], [`Response`],
//! and the [`RequestId`] correlating them. A remote back end is a channel pair
//! carrying exactly these two enums, so a consumer never needs to implement a
//! Rust trait to act as an out-of-tree signer.

use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use miniscript::bitcoin::bip32::DerivationPath;

use bwk_descriptor::descriptor::Descriptor;
use bwk_keys::keys::OXpub;

use crate::{
    identity::{SignerId, SignerInfo},
    signer::SignerNotif,
};

/// Correlates a manager call with the notification answering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Mints unique, monotonically increasing [`RequestId`]s. Starts at 1 so a
/// `RequestId(0)` never appears and a zero id in a log is visibly wrong.
///
/// `Sync`, so a manager can mint ids from a `&self` method, which is what the
/// [`crate::manager::SigningManager`] trait's `&self` signatures require.
pub struct RequestIdSource(AtomicU64);

impl RequestIdSource {
    pub fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    pub fn next(&self) -> RequestId {
        RequestId(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for RequestIdSource {
    fn default() -> Self {
        Self::new()
    }
}

/// A call from a manager's consumer to its back end.
///
/// Every variant carries its own [`RequestId`] explicitly: the remote back
/// end has to echo it, so it must travel on the wire rather than living in a
/// caller-side map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    ListSigners {
        request: RequestId,
    },
    SetPolling {
        request: RequestId,
        enabled: bool,
    },
    Init {
        request: RequestId,
        signer: SignerId,
    },
    Info {
        request: RequestId,
        signer: SignerId,
    },
    GetXpub {
        request: RequestId,
        signer: SignerId,
        path: DerivationPath,
        display: bool,
    },
    IsDescriptorRegistered {
        request: RequestId,
        signer: SignerId,
        descriptor: Descriptor,
    },
    RegisterDescriptor {
        request: RequestId,
        signer: SignerId,
        descriptor: Descriptor,
    },
    Sign {
        request: RequestId,
        signer: SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    },
    Raw {
        request: RequestId,
        signer: SignerId,
        payload: Vec<u8>,
    },
}

impl Request {
    pub fn request_id(&self) -> RequestId {
        match self {
            Request::ListSigners { request }
            | Request::SetPolling { request, .. }
            | Request::Init { request, .. }
            | Request::Info { request, .. }
            | Request::GetXpub { request, .. }
            | Request::IsDescriptorRegistered { request, .. }
            | Request::RegisterDescriptor { request, .. }
            | Request::Sign { request, .. }
            | Request::Raw { request, .. } => *request,
        }
    }

    /// `None` for the host-level operations, `ListSigners` and `SetPolling`,
    /// which do not target one signer.
    pub fn signer(&self) -> Option<&SignerId> {
        match self {
            Request::ListSigners { .. } | Request::SetPolling { .. } => None,
            Request::Init { signer, .. }
            | Request::Info { signer, .. }
            | Request::GetXpub { signer, .. }
            | Request::IsDescriptorRegistered { signer, .. }
            | Request::RegisterDescriptor { signer, .. }
            | Request::Sign { signer, .. }
            | Request::Raw { signer, .. } => Some(signer),
        }
    }
}

/// An answer from a manager's back end to its consumer.
///
/// `SignersChanged` and `Error` are the two unsolicited variants: device
/// discovery can change the signer list without any request asking for it,
/// and a back end can fail (a device unplugged, a remote link dropped)
/// without any request having caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Signers {
        request: RequestId,
        signers: Vec<SignerInfo>,
    },
    SignersChanged {
        signers: Vec<SignerInfo>,
    },
    Initialized {
        request: RequestId,
        signer: SignerId,
    },
    Info {
        request: RequestId,
        signer: SignerId,
        info: BTreeMap<String, String>,
    },
    Xpub {
        request: RequestId,
        signer: SignerId,
        xpub: OXpub,
    },
    DescriptorIsRegistered {
        request: RequestId,
        signer: SignerId,
        registered: bool,
    },
    DescriptorRegistered {
        request: RequestId,
        signer: SignerId,
        registered: bool,
    },
    Signed {
        request: RequestId,
        signer: SignerId,
        psbt: Vec<u8>,
    },
    Raw {
        request: RequestId,
        signer: SignerId,
        payload: Vec<u8>,
    },
    Error {
        request: Option<RequestId>,
        signer: Option<SignerId>,
        message: String,
    },
}

impl Response {
    /// `None` for `SignersChanged`, which is unsolicited by construction, and
    /// for an `Error` that no request caused.
    pub fn request_id(&self) -> Option<RequestId> {
        match self {
            Response::Signers { request, .. }
            | Response::Initialized { request, .. }
            | Response::Info { request, .. }
            | Response::Xpub { request, .. }
            | Response::DescriptorIsRegistered { request, .. }
            | Response::DescriptorRegistered { request, .. }
            | Response::Signed { request, .. }
            | Response::Raw { request, .. } => Some(*request),
            Response::SignersChanged { .. } => None,
            Response::Error { request, .. } => *request,
        }
    }

    pub fn signer(&self) -> Option<&SignerId> {
        match self {
            Response::Signers { .. } | Response::SignersChanged { .. } => None,
            Response::Initialized { signer, .. }
            | Response::Info { signer, .. }
            | Response::Xpub { signer, .. }
            | Response::DescriptorIsRegistered { signer, .. }
            | Response::DescriptorRegistered { signer, .. }
            | Response::Signed { signer, .. }
            | Response::Raw { signer, .. } => Some(signer),
            Response::Error { signer, .. } => signer.as_ref(),
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Response::Error { .. })
    }

    pub fn error(request: RequestId, signer: SignerId, message: impl Into<String>) -> Self {
        Response::Error {
            request: Some(request),
            signer: Some(signer),
            message: message.into(),
        }
    }

    pub fn unsolicited_error(message: impl Into<String>) -> Self {
        Response::Error {
            request: None,
            signer: None,
            message: message.into(),
        }
    }
}

/// Bridges the in-tree [`SignerNotif`] channel onto the protocol. This is a
/// free function rather than a `From` impl because the conversion needs the
/// request id and signer id that `SignerNotif` does not carry.
pub fn from_signer_notif(notif: SignerNotif, request: RequestId, signer: SignerId) -> Response {
    match notif {
        SignerNotif::Info(_, value) => Response::Info {
            request,
            signer,
            info: info_map(value),
        },
        SignerNotif::Xpub(_, xpub) => Response::Xpub {
            request,
            signer,
            xpub,
        },
        SignerNotif::DescriptorRegistered(_, _, registered) => Response::DescriptorRegistered {
            request,
            signer,
            registered,
        },
        SignerNotif::Signed(_, psbt) => Response::Signed {
            request,
            signer,
            psbt: psbt.serialize(),
        },
        SignerNotif::Error(_, e) => Response::error(request, signer, e.to_string()),
        SignerNotif::Manager(e) => Response::error(request, signer, format!("{e:?}")),
        SignerNotif::Descriptor(..) => {
            Response::unsolicited_error("SignerNotif::Descriptor has no protocol equivalent")
        }
    }
}

pub fn info_map(value: serde_json::Value) -> BTreeMap<String, String> {
    match value {
        serde_json::Value::Object(map) => map
            .into_iter()
            .map(|(key, value)| (key, json_value_to_string(value)))
            .collect(),
        other => BTreeMap::from([("info".to_string(), json_value_to_string(other))]),
    }
}

fn json_value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr, thread};

    use miniscript::bitcoin::{
        self,
        bip32::{self, DerivationPath},
        secp256k1::Secp256k1,
    };

    use bwk_descriptor::descriptor::Descriptor;

    use crate::{
        error::Error as SignError,
        identity::SignerId,
        protocol::{from_signer_notif, Request, RequestId, RequestIdSource, Response},
        signer::SignerNotif,
    };

    fn signer_id() -> SignerId {
        SignerId::new("test")
    }

    fn descriptor() -> Descriptor {
        let secp = Secp256k1::new();
        let xpriv = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x13; 64]).unwrap();
        let xpub = bip32::Xpub::from_priv(&secp, &xpriv);
        let s = format!("wpkh([deadbeef/84h/1h/0h]{xpub}/<0;1>/*)");
        Descriptor::from_str(&s).unwrap()
    }

    #[test]
    fn request_ids_are_unique_and_monotonic() {
        let source = RequestIdSource::new();
        let ids: Vec<RequestId> = (0..1000).map(|_| source.next()).collect();
        for pair in ids.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        let unique: BTreeSet<RequestId> = ids.iter().copied().collect();
        assert_eq!(unique.len(), 1000);
    }

    #[test]
    fn request_ids_are_unique_across_threads() {
        let source = RequestIdSource::new();
        let ids: BTreeSet<RequestId> = thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| (0..1000).map(|_| source.next()).collect::<Vec<_>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(ids.len(), 8000);
    }

    #[test]
    fn request_ids_start_at_one() {
        let source = RequestIdSource::new();
        assert_eq!(source.next(), RequestId::new(1));
    }

    #[test]
    fn every_request_carries_its_id() {
        let request = RequestId::new(42);
        let signer = signer_id();
        let requests = vec![
            Request::ListSigners { request },
            Request::SetPolling {
                request,
                enabled: true,
            },
            Request::Init {
                request,
                signer: signer.clone(),
            },
            Request::Info {
                request,
                signer: signer.clone(),
            },
            Request::GetXpub {
                request,
                signer: signer.clone(),
                path: DerivationPath::master(),
                display: false,
            },
            Request::IsDescriptorRegistered {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
            },
            Request::RegisterDescriptor {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
            },
            Request::Sign {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
                psbt: vec![1, 2, 3],
            },
            Request::Raw {
                request,
                signer: signer.clone(),
                payload: vec![4, 5, 6],
            },
        ];
        for req in requests {
            assert_eq!(req.request_id(), request);
        }
    }

    #[test]
    fn request_signer_is_none_for_host_operations() {
        let request = RequestId::new(1);
        assert_eq!(Request::ListSigners { request }.signer(), None);
        assert_eq!(
            Request::SetPolling {
                request,
                enabled: false
            }
            .signer(),
            None
        );

        let signer = signer_id();
        assert_eq!(
            Request::Init {
                request,
                signer: signer.clone()
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::Info {
                request,
                signer: signer.clone()
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::GetXpub {
                request,
                signer: signer.clone(),
                path: DerivationPath::master(),
                display: false,
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::IsDescriptorRegistered {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::RegisterDescriptor {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::Sign {
                request,
                signer: signer.clone(),
                descriptor: descriptor(),
                psbt: vec![],
            }
            .signer(),
            Some(&signer)
        );
        assert_eq!(
            Request::Raw {
                request,
                signer: signer.clone(),
                payload: vec![],
            }
            .signer(),
            Some(&signer)
        );
    }

    #[test]
    fn response_request_id_is_optional() {
        let request = RequestId::new(1);
        let signer = signer_id();

        assert_eq!(
            Response::SignersChanged { signers: vec![] }.request_id(),
            None
        );
        assert_eq!(Response::unsolicited_error("boom").request_id(), None);

        assert_eq!(
            Response::Signers {
                request,
                signers: vec![]
            }
            .request_id(),
            Some(request)
        );
        assert_eq!(
            Response::Initialized {
                request,
                signer: signer.clone()
            }
            .request_id(),
            Some(request)
        );
        assert_eq!(
            Response::error(request, signer, "boom").request_id(),
            Some(request)
        );
    }

    #[test]
    fn unsolicited_error_has_no_ids() {
        let response = Response::unsolicited_error("boom");
        match &response {
            Response::Error {
                request, signer, ..
            } => {
                assert!(request.is_none());
                assert!(signer.is_none());
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(response.is_error());
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn protocol_types_are_send() {
        assert_send::<Request>();
        assert_send::<Response>();
    }

    #[test]
    fn signer_notif_signed_becomes_bytes() {
        let fg = bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]);
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = bitcoin::Psbt::from_unsigned_tx(tx).unwrap();
        let expected = psbt.serialize();

        let response = from_signer_notif(
            SignerNotif::Signed(fg, psbt),
            RequestId::new(1),
            signer_id(),
        );
        match response {
            Response::Signed { psbt, .. } => assert_eq!(psbt, expected),
            other => panic!("expected Signed, got {other:?}"),
        }
    }

    #[test]
    fn signer_notif_error_carries_the_request_id() {
        let fg = bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]);
        let request = RequestId::new(7);
        let signer = signer_id();

        let response = from_signer_notif(
            SignerNotif::Error(fg, SignError::SpkNotMatch),
            request,
            signer.clone(),
        );
        match response {
            Response::Error {
                request: req,
                signer: sid,
                message,
            } => {
                assert_eq!(req, Some(request));
                assert_eq!(sid, Some(signer));
                assert!(message.contains(&SignError::SpkNotMatch.to_string()));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
