//! The nonce cache session PSBT field (bip-nonce-cache/BIP-DRAFT.md).
//!
//! ```text
//! +------+---------+--------------------------------+
//! | type | keydata | value                          |
//! +------+---------+--------------------------------+
//! | 0x09 | none    | session_id (4) session_ref (4) |
//! +------+---------+--------------------------------+
//! ```

use std::collections::BTreeMap;

use bitcoin::{psbt::raw, Psbt};

use crate::PsbtV2;

pub const PSBT_GLOBAL_NONCE_CACHE_SESSION: u8 = 0x09;
const ID_LEN: usize = 4;
const VALUE_LEN: usize = 2 * ID_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid nonce cache session field value")]
    InvalidValue,
}

/// The signer session a PSBT is signed with, and the reference the signer returned
/// when it issued the nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceCacheSession {
    pub session_id: [u8; ID_LEN],
    pub session_ref: [u8; ID_LEN],
}

fn key() -> raw::Key {
    raw::Key {
        type_value: PSBT_GLOBAL_NONCE_CACHE_SESSION,
        key: Vec::new(),
    }
}

fn set_session(unknown: &mut BTreeMap<raw::Key, Vec<u8>>, session: NonceCacheSession) {
    let mut value = Vec::with_capacity(VALUE_LEN);
    value.extend_from_slice(&session.session_id);
    value.extend_from_slice(&session.session_ref);
    unknown.insert(key(), value);
}

fn get_session(unknown: &BTreeMap<raw::Key, Vec<u8>>) -> Result<Option<NonceCacheSession>, Error> {
    let Some(value) = unknown.get(&key()) else {
        return Ok(None);
    };
    if value.len() != VALUE_LEN {
        return Err(Error::InvalidValue);
    }
    let (session_id, session_ref) = value.split_at(ID_LEN);
    Ok(Some(NonceCacheSession {
        session_id: session_id.try_into().map_err(|_| Error::InvalidValue)?,
        session_ref: session_ref.try_into().map_err(|_| Error::InvalidValue)?,
    }))
}

pub fn set_nonce_cache_session(psbt: &mut Psbt, session: NonceCacheSession) {
    set_session(&mut psbt.unknown, session);
}

pub fn set_nonce_cache_session_v2(psbt: &mut PsbtV2, session: NonceCacheSession) {
    set_session(&mut psbt.unknown, session);
}

pub fn nonce_cache_session(psbt: &Psbt) -> Result<Option<NonceCacheSession>, Error> {
    get_session(&psbt.unknown)
}

pub fn nonce_cache_session_v2(psbt: &PsbtV2) -> Result<Option<NonceCacheSession>, Error> {
    get_session(&psbt.unknown)
}

#[cfg(test)]
mod tests {
    use bitcoin::{hex::DisplayHex, Psbt};

    use crate::{
        nonce_cache::{
            key, nonce_cache_session, set_nonce_cache_session, Error, NonceCacheSession,
        },
        test_utils::psbt_spending,
    };

    fn id(vector: &serde_json::Value, field: &str) -> [u8; 4] {
        hex::decode(vector[field].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    // The key and the value as BIP-174 serializes them, each after its compact size
    // length.
    fn serialized_pair(psbt: &Psbt) -> (String, String) {
        let value = &psbt.unknown[&key()];
        let serialized_key = [1, key().type_value];
        let mut serialized_value = vec![value.len() as u8];
        serialized_value.extend_from_slice(value);
        (
            serialized_key.to_lower_hex_string(),
            serialized_value.to_lower_hex_string(),
        )
    }

    #[test]
    fn bip_vectors() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../bip-nonce-cache/test_vectors/psbt_field.json"
        ))
        .unwrap();
        for vector in vectors {
            let session = NonceCacheSession {
                session_id: id(&vector, "session_id"),
                session_ref: id(&vector, "ref"),
            };
            let mut psbt = psbt_spending(Vec::new());
            set_nonce_cache_session(&mut psbt, session);
            assert_eq!(
                serialized_pair(&psbt),
                (
                    vector["key"].as_str().unwrap().to_string(),
                    vector["value"].as_str().unwrap().to_string()
                )
            );
            let parsed = Psbt::deserialize(&psbt.serialize()).unwrap();
            assert_eq!(nonce_cache_session(&parsed), Ok(Some(session)));
        }
    }

    #[test]
    fn absent_and_invalid_values() {
        let mut psbt = psbt_spending(Vec::new());
        assert_eq!(nonce_cache_session(&psbt), Ok(None));
        psbt.unknown.insert(key(), vec![0; 7]);
        assert_eq!(nonce_cache_session(&psbt), Err(Error::InvalidValue));
        psbt.unknown.insert(key(), vec![0; 9]);
        assert_eq!(nonce_cache_session(&psbt), Err(Error::InvalidValue));
    }
}
