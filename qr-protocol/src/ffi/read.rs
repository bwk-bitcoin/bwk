//! Reads the C view of a response back into the Rust types. Nothing is retained:
//! the caller's memory is borrowed for the duration of the call only.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::{c_char, CStr};

use crate::{
    ffi::{types, Error},
    musig, request, response,
    types::{ExtendedKey, Fingerprint, PublicKey, TAP_LEAF_HASH_LEN},
    MessageType, RequestId, Response, SignResponseKind, MAX_VEC,
};

/// # Safety
/// `view` must be a fully initialized response whose pointers are valid for reading.
pub unsafe fn response(view: &types::Response) -> Result<Response, Error> {
    let message_type = MessageType::try_from(view.message_type).map_err(|_| Error::UnknownTag)?;
    let body = if view.is_error {
        response::Body::Error(error_body(message_type, &view.body.error)?)
    } else {
        match message_type {
            MessageType::GetKeys => response::Body::Keys(keys(&view.body.keys)?),
            MessageType::RegisterDescriptor => {
                response::Body::Registration(registration(&view.body.registration)?)
            }
            MessageType::AddressVerification => response::Body::AddressUri(response::AddressUri {
                uri: optional_string(view.body.address_uri.uri)?,
            }),
            MessageType::Signing => response::Body::Signed(signed(&view.body.signed)?),
            MessageType::MusigPreparation => {
                response::Body::MusigPrepared(musig_prepared(&view.body.musig_prepared)?)
            }
            MessageType::MusigSigning => {
                response::Body::MusigSigned(musig_signed(&view.body.musig_signed)?)
            }
        }
    };
    Ok(Response {
        id: RequestId(view.id),
        body,
    })
}

unsafe fn musig_prepared(view: &types::MusigPrepared) -> Result<response::MusigPrepared, Error> {
    musig::validate_input_coverage(view.max_inputs).map_err(Error::Musig)?;
    if view.nonces.len == 0 || view.nonces.len > MAX_VEC {
        return Err(Error::Musig(musig::Error::NonceCount));
    }
    if view.nonces.is_absent() {
        return Err(Error::NullPointer);
    }
    let mut nonces = Vec::new();
    for nonce in view.nonces.as_slice() {
        nonces.push(response::MusigNonce {
            derivation: request::MusigDerivation {
                keychain: nonce.derivation.keychain,
                index: nonce.derivation.index,
            },
            input_index: nonce.input_index,
            expression_index: nonce.expression_index,
            participant: PublicKey(nonce.participant),
            aggregate: PublicKey(nonce.aggregate),
            leaf_hash: optional_leaf_hash(nonce.has_leaf_hash, nonce.leaf_hash)?,
            nonce: nonce.nonce,
        });
    }
    Ok(response::MusigPrepared {
        session_id: view.session_id,
        max_inputs: view.max_inputs,
        nonces,
    })
}

unsafe fn musig_signed(view: &types::MusigSigned) -> Result<response::MusigSigned, Error> {
    Ok(response::MusigSigned {
        session_id: view.session_id,
        attempt_id: view.attempt_id,
        psbt: bytes(view.psbt)?,
    })
}

unsafe fn keys(view: &types::Keys) -> Result<response::Keys, Error> {
    Ok(response::Keys {
        keys: view
            .keys
            .as_slice()
            .iter()
            .copied()
            .map(ExtendedKey)
            .collect(),
        fingerprint: Fingerprint(view.fingerprint),
        vendor: fixed_string(&view.vendor)?,
        model: fixed_string(&view.model)?,
        version: response::FirmwareVersion {
            major: view.version.major,
            minor: view.version.minor,
            patch: view.version.patch,
            flag: view.version.flag.into(),
        },
        capabilities: response::Capabilities(view.capabilities),
    })
}

unsafe fn registration(view: &types::Registration) -> Result<response::Registration, Error> {
    Ok(response::Registration {
        descriptor_alias: string(view.descriptor_alias)?,
        registered: optional_bool(view.registered)?,
        stored: optional_bool(view.stored)?,
        proof: optional_bytes(view.proof),
    })
}

unsafe fn signed(view: &types::Signed) -> Result<response::Signed, Error> {
    match SignResponseKind::try_from(view.kind).map_err(|_| Error::UnknownTag)? {
        SignResponseKind::Psbt => Ok(response::Signed::Psbt(bytes(view.value.psbt)?)),
        SignResponseKind::Signatures => {
            let mut entries = Vec::new();
            for entry in view.value.signatures.as_slice() {
                entries.push(signature(entry)?);
            }
            Ok(response::Signed::Signatures(entries))
        }
    }
}

unsafe fn signature(view: &types::Signature) -> Result<response::SignatureEntry, Error> {
    let input_index = view.input_index;
    match view.kind {
        response::SIGNATURE_ECDSA => Ok(response::SignatureEntry::Ecdsa {
            input_index,
            public_key: PublicKey(view.value.ecdsa.public_key),
            signature: bytes(view.value.ecdsa.signature)?,
        }),
        response::SIGNATURE_TAP_KEY => Ok(response::SignatureEntry::TapKey {
            input_index,
            signature: bytes(view.value.tap_key.signature)?,
        }),
        response::SIGNATURE_TAP_SCRIPT => Ok(response::SignatureEntry::TapScript {
            input_index,
            xonly_public_key: view.value.tap_script.xonly_public_key,
            tap_leaf_hash: view.value.tap_script.tap_leaf_hash,
            signature: bytes(view.value.tap_script.signature)?,
        }),
        response::SIGNATURE_MUSIG_PUB_NONCE => {
            let value = view.value.musig_pub_nonce;
            Ok(response::SignatureEntry::MusigPubNonce {
                input_index,
                participant: PublicKey(value.participant),
                aggregate: PublicKey(value.aggregate),
                leaf_hash: optional_leaf_hash(value.has_leaf_hash, value.leaf_hash)?,
                nonce: value.nonce,
            })
        }
        response::SIGNATURE_MUSIG_PARTIAL_SIG => {
            let value = view.value.musig_partial_sig;
            Ok(response::SignatureEntry::MusigPartialSig {
                input_index,
                participant: PublicKey(value.participant),
                aggregate: PublicKey(value.aggregate),
                leaf_hash: optional_leaf_hash(value.has_leaf_hash, value.leaf_hash)?,
                signature: value.signature,
            })
        }
        _ => Err(Error::UnknownTag),
    }
}

unsafe fn error_body(
    message_type: MessageType,
    view: &types::ErrorBody,
) -> Result<response::ErrorBody, Error> {
    Ok(response::ErrorBody {
        message_type,
        error: view.error.into(),
        message: fixed_string(&view.message)?,
    })
}

unsafe fn optional_string(ptr: *const c_char) -> Result<Option<String>, Error> {
    if ptr.is_null() {
        return Ok(None);
    }
    string(ptr).map(Some)
}

unsafe fn string(ptr: *const c_char) -> Result<String, Error> {
    if ptr.is_null() {
        return Err(Error::NullPointer);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(ToString::to_string)
        .map_err(|_| Error::InvalidUtf8)
}

fn fixed_string(field: &[c_char]) -> Result<String, Error> {
    let bytes = field.iter().map(|c| *c as u8).collect::<Vec<_>>();
    let nul = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::UnterminatedFixedString)?;
    String::from_utf8(bytes[..nul].to_vec()).map_err(|_| Error::InvalidUtf8)
}

fn optional_bool(value: i8) -> Result<Option<bool>, Error> {
    match value {
        types::ABSENT_BOOL => Ok(None),
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(Error::InvalidBool),
    }
}

fn optional_leaf_hash(
    has_leaf_hash: u8,
    leaf_hash: [u8; TAP_LEAF_HASH_LEN],
) -> Result<Option<[u8; TAP_LEAF_HASH_LEN]>, Error> {
    match has_leaf_hash {
        0 => Ok(None),
        1 => Ok(Some(leaf_hash)),
        _ => Err(Error::InvalidBool),
    }
}

unsafe fn optional_bytes(view: types::Bytes) -> Option<Vec<u8>> {
    if view.is_absent() {
        None
    } else {
        Some(view.as_slice().to_vec())
    }
}

unsafe fn bytes(view: types::Bytes) -> Result<Vec<u8>, Error> {
    if view.is_absent() {
        return Err(Error::NullPointer);
    }
    Ok(view.as_slice().to_vec())
}
