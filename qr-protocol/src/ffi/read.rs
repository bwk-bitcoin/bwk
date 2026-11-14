//! Reads the C view of a response back into the Rust types. Nothing is retained:
//! the caller's memory is borrowed for the duration of the call only.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::{c_char, CStr};

use crate::{
    ffi::{types, Error},
    nonce_cache, response,
    types::{ExtendedKey, Fingerprint, PublicKey},
    MessageType, RequestId, Response, SignResponseKind,
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
            MessageType::NoncePreparation => {
                response::Body::NoncesPrepared(nonces_prepared(&view.body.nonces_prepared)?)
            }
            MessageType::GetInfo => response::Body::Info(info(&view.body.info)?),
        }
    };
    Ok(Response {
        id: RequestId(view.id),
        body,
    })
}

unsafe fn nonces_prepared(view: &types::NoncesPrepared) -> Result<response::NoncesPrepared, Error> {
    nonce_cache::validate_nonce_count(view.nonces.len, view.max_inputs, view.start, view.end)
        .map_err(Error::NonceCache)?;
    if view.nonces.is_absent() {
        return Err(Error::NullPointer);
    }
    Ok(response::NoncesPrepared {
        session_id: view.session_id,
        session_ref: view.session_ref,
        max_inputs: view.max_inputs,
        start: view.start,
        end: view.end,
        nonces: view.nonces.as_slice().to_vec(),
    })
}

unsafe fn info(view: &types::Info) -> Result<response::Info, Error> {
    Ok(response::Info {
        vendor: string(view.vendor)?,
        model: string(view.model)?,
        version: firmware_version(&view.version),
        capabilities: response::Capabilities(view.capabilities),
        state: view.state.into(),
        networks: response::Networks(view.networks),
        max_message: view.max_message,
        max_alias: view.max_alias,
        max_keys: view.max_keys,
        slots: view.slots,
        fingerprint: optional(view.has_fingerprint, Fingerprint(view.fingerprint))?,
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
        vendor: string(view.vendor)?,
        model: string(view.model)?,
        version: firmware_version(&view.version),
        capabilities: response::Capabilities(view.capabilities),
    })
}

fn firmware_version(view: &types::FirmwareVersion) -> response::FirmwareVersion {
    response::FirmwareVersion {
        major: view.major,
        minor: view.minor,
        patch: view.patch,
        flag: view.flag.into(),
    }
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
                leaf_hash: optional(value.has_leaf_hash, value.leaf_hash)?,
                nonce: value.nonce,
            })
        }
        response::SIGNATURE_MUSIG_PARTIAL_SIG => {
            let value = view.value.musig_partial_sig;
            Ok(response::SignatureEntry::MusigPartialSig {
                input_index,
                participant: PublicKey(value.participant),
                aggregate: PublicKey(value.aggregate),
                leaf_hash: optional(value.has_leaf_hash, value.leaf_hash)?,
                signature: value.signature,
            })
        }
        response::SIGNATURE_SP_ECDH_SHARE => {
            let value = view.value.sp_ecdh_share;
            Ok(response::SignatureEntry::SpEcdhShare {
                scope: sp_scope(value.global, input_index)?,
                scan_key: PublicKey(value.scan_key),
                share: PublicKey(value.share),
            })
        }
        response::SIGNATURE_SP_DLEQ_PROOF => {
            let value = view.value.sp_dleq_proof;
            Ok(response::SignatureEntry::SpDleqProof {
                scope: sp_scope(value.global, input_index)?,
                scan_key: PublicKey(value.scan_key),
                proof: value.proof,
            })
        }
        _ => Err(Error::UnknownTag),
    }
}

fn sp_scope(global: u8, input_index: u32) -> Result<response::SpScope, Error> {
    let global = match global {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidBool),
    };
    response::SpScope::from_wire(global, input_index).ok_or(Error::GlobalInputIndex)
}

unsafe fn error_body(
    message_type: MessageType,
    view: &types::ErrorBody,
) -> Result<response::ErrorBody, Error> {
    Ok(response::ErrorBody {
        message_type,
        error: view.error.into(),
        message: string(view.message)?,
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

fn optional_bool(value: i8) -> Result<Option<bool>, Error> {
    match value {
        types::ABSENT_BOOL => Ok(None),
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(Error::InvalidBool),
    }
}

/// A C field that is present when its `has_` flag is 1 and absent when it is 0.
fn optional<T>(has: u8, value: T) -> Result<Option<T>, Error> {
    match has {
        0 => Ok(None),
        1 => Ok(Some(value)),
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
