//! Reads the C view of a response back into the Rust types. Nothing is retained:
//! the caller's memory is borrowed for the duration of the call only.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::{c_char, CStr};

use crate::{
    ffi::{types, Error},
    response,
    types::{Fingerprint, PublicKey, Xpub},
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
            MessageType::GetXpubs => response::Body::Xpubs(xpubs(&view.body.xpubs)?),
            MessageType::RegisterDescriptor => {
                response::Body::Registration(registration(&view.body.registration)?)
            }
            MessageType::AddressVerification => response::Body::AddressUri(response::AddressUri {
                uri: optional_string(view.body.address_uri.uri)?,
            }),
            MessageType::Signing => response::Body::Signed(signed(&view.body.signed)?),
            MessageType::GetSpDescriptor => {
                response::Body::SpDescriptor(sp_descriptor(&view.body.sp_descriptor)?)
            }
        }
    };
    Ok(Response {
        id: RequestId(view.id),
        body,
    })
}

unsafe fn xpubs(view: &types::Xpubs) -> Result<response::Xpubs, Error> {
    Ok(response::Xpubs {
        xpubs: view.xpubs.as_slice().iter().copied().map(Xpub).collect(),
        fingerprint: Fingerprint(view.fingerprint),
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

unsafe fn sp_descriptor(view: &types::SpDescriptor) -> Result<response::SpDescriptor, Error> {
    Ok(response::SpDescriptor {
        descriptor: string(view.descriptor)?,
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
