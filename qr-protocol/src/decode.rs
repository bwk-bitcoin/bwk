use alloc::{string::String, vec::Vec};

use crate::{
    reader::{self, Reader},
    request, response,
    types::{DerivationPath, Fingerprint, PublicKey, Xpub},
    ErrorInfo, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    DIRECTION_RESPONSE, ERROR_MESSAGE_LEN, MAGIC, MAX_DESCRIPTOR_ALIAS, MODEL_LEN, STATUS_ERROR,
    TYPE_MASK,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMagic,
    ReservedVersion,
    UnknownMessageType(u8),
    ErrorStatusOnRequest,
    UnknownDescriptorForm(u8),
    UnknownSignatureKind(u8),
    UnknownSignResponseKind(u8),
    Read(reader::Error),
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::InvalidMagic => error_info!(200, "invalid magic"),
            Self::ReservedVersion => error_info!(201, "reserved protocol version"),
            Self::UnknownMessageType(_) => error_info!(202, "unknown message type"),
            Self::ErrorStatusOnRequest => error_info!(203, "request cannot carry error status"),
            Self::UnknownDescriptorForm(_) => error_info!(204, "unknown descriptor form"),
            Self::UnknownSignatureKind(_) => error_info!(205, "unknown signature kind"),
            Self::UnknownSignResponseKind(_) => error_info!(206, "unknown signing response kind"),
            Self::Read(inner) => inner.info(),
        }
    }
}

error_display!(Error);

impl From<reader::Error> for Error {
    fn from(error: reader::Error) -> Self {
        Self::Read(error)
    }
}

pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    let mut reader = Reader::new(bytes);
    read_magic(&mut reader)?;
    // A newer version only appends fields, so anything above VERSION parses as VERSION.
    if reader.take_u8()? == 0 {
        return Err(Error::ReservedVersion);
    }
    let msg_type = reader.take_u8()?;
    let response = msg_type & DIRECTION_RESPONSE != 0;
    let error = msg_type & STATUS_ERROR != 0;
    let message_type = MessageType::try_from(msg_type & TYPE_MASK)?;
    if error && !response {
        return Err(Error::ErrorStatusOnRequest);
    }
    let id = RequestId(reader.take_array()?);
    // The error flag is already known to be clear on a request.
    let decoded = match (response, error, message_type) {
        (false, _, MessageType::GetXpubs) => Message::Request(Request {
            id,
            body: request::Body::GetXpubs(read_get_xpubs_request(&mut reader)?),
        }),
        (false, _, MessageType::RegisterDescriptor) => Message::Request(Request {
            id,
            body: request::Body::RegisterDescriptor(read_register_request(&mut reader)?),
        }),
        (false, _, MessageType::AddressVerification) => Message::Request(Request {
            id,
            body: request::Body::VerifyAddress(read_verify_address_request(&mut reader)?),
        }),
        (false, _, MessageType::Signing) => Message::Request(Request {
            id,
            body: request::Body::Sign(read_sign_request(&mut reader)?),
        }),
        (false, _, MessageType::GetSpDescriptor) => Message::Request(Request {
            id,
            body: request::Body::GetSpDescriptor(request::GetSpDescriptor {}),
        }),
        (true, true, _) => Message::Response(Response {
            id,
            body: response::Body::Error(read_error_response(&mut reader, message_type)?),
        }),
        (true, false, MessageType::GetXpubs) => Message::Response(Response {
            id,
            body: response::Body::Xpubs(read_xpubs_response(&mut reader)?),
        }),
        (true, false, MessageType::RegisterDescriptor) => Message::Response(Response {
            id,
            body: response::Body::Registration(read_registration_response(&mut reader)?),
        }),
        (true, false, MessageType::AddressVerification) => Message::Response(Response {
            id,
            body: response::Body::AddressUri(read_address_response(&mut reader)?),
        }),
        (true, false, MessageType::Signing) => Message::Response(Response {
            id,
            body: response::Body::Signed(read_signed_response(&mut reader)?),
        }),
        (true, false, MessageType::GetSpDescriptor) => Message::Response(Response {
            id,
            body: response::Body::SpDescriptor(read_sp_descriptor_response(&mut reader)?),
        }),
    };
    Ok(decoded)
}

fn read_magic(reader: &mut Reader<'_>) -> Result<(), Error> {
    if reader.take_slice(MAGIC.len())? != MAGIC {
        return Err(Error::InvalidMagic);
    }
    Ok(())
}

fn read_get_xpubs_request(reader: &mut Reader<'_>) -> Result<request::GetXpubs, Error> {
    Ok(request::GetXpubs {
        derivation_paths: reader.take_vec(read_path)?,
    })
}

fn read_register_request(reader: &mut Reader<'_>) -> Result<request::RegisterDescriptor, Error> {
    Ok(request::RegisterDescriptor {
        descriptor_alias: read_descriptor_alias(reader)?,
        descriptor: reader.take_option(read_descriptor_body)?,
    })
}

fn read_verify_address_request(reader: &mut Reader<'_>) -> Result<request::VerifyAddress, Error> {
    Ok(request::VerifyAddress {
        descriptor_alias: read_descriptor_alias(reader)?,
        derivation_path: read_path(reader)?,
        address: reader.take_option(Reader::take_string)?,
        descriptor: reader.take_option(read_descriptor_body)?,
        proof: reader.take_option(Reader::take_bytes)?,
    })
}

fn read_sign_request(reader: &mut Reader<'_>) -> Result<request::Sign, Error> {
    Ok(request::Sign {
        descriptors: reader.take_vec(read_descriptor)?,
        psbt: reader.take_bytes()?,
        want_kind: reader.take_option(read_sign_response_kind)?,
    })
}

fn read_xpubs_response(reader: &mut Reader<'_>) -> Result<response::Xpubs, Error> {
    Ok(response::Xpubs {
        xpubs: reader.take_vec(read_xpub)?,
        fingerprint: read_fingerprint(reader)?,
        model: reader.take_fixed_string(MODEL_LEN)?,
        version: read_version(reader)?,
        capabilities: read_capabilites(reader)?,
    })
}

fn read_sp_descriptor_response(reader: &mut Reader<'_>) -> Result<response::SpDescriptor, Error> {
    Ok(response::SpDescriptor {
        descriptor: reader.take_string()?,
    })
}

fn read_registration_response(reader: &mut Reader<'_>) -> Result<response::Registration, Error> {
    Ok(response::Registration {
        descriptor_alias: read_descriptor_alias(reader)?,
        registered: reader.take_option(Reader::take_bool)?,
        stored: reader.take_option(Reader::take_bool)?,
        proof: reader.take_option(Reader::take_bytes)?,
    })
}

fn read_address_response(reader: &mut Reader<'_>) -> Result<response::AddressUri, Error> {
    Ok(response::AddressUri {
        uri: reader.take_option(Reader::take_string)?,
    })
}

fn read_signed_response(reader: &mut Reader<'_>) -> Result<response::Signed, Error> {
    match read_sign_response_kind(reader)? {
        SignResponseKind::Psbt => Ok(response::Signed::Psbt(reader.take_bytes()?)),
        SignResponseKind::Signatures => Ok(response::Signed::Signatures(
            reader.take_vec(read_signature)?,
        )),
    }
}

fn read_error_response(
    reader: &mut Reader<'_>,
    message_type: MessageType,
) -> Result<response::ErrorBody, Error> {
    Ok(response::ErrorBody {
        message_type,
        error: reader.take_u8()?.into(),
        message: reader.take_fixed_string(ERROR_MESSAGE_LEN)?,
    })
}

fn read_descriptor(reader: &mut Reader<'_>) -> Result<request::Descriptor, Error> {
    Ok(request::Descriptor {
        alias: read_descriptor_alias(reader)?,
        descriptor: reader.take_option(read_descriptor_body)?,
        proof: reader.take_option(Reader::take_bytes)?,
    })
}

fn read_descriptor_body(reader: &mut Reader<'_>) -> Result<request::DescriptorBody, Error> {
    match reader.take_u8()? {
        request::DESCRIPTOR_BIP380 => Ok(request::DescriptorBody::Bip380(reader.take_string()?)),
        request::DESCRIPTOR_BIP388 => Ok(request::DescriptorBody::Bip388 {
            keys: reader.take_vec(Reader::take_string)?,
            policy: reader.take_string()?,
        }),
        value => Err(Error::UnknownDescriptorForm(value)),
    }
}

fn read_signature(reader: &mut Reader<'_>) -> Result<response::SignatureEntry, Error> {
    let input_index = reader.take_u32_be()?;
    match reader.take_u8()? {
        response::SIGNATURE_ECDSA => Ok(response::SignatureEntry::Ecdsa {
            input_index,
            public_key: read_pubkey(reader)?,
            signature: reader.take_bytes()?,
        }),
        response::SIGNATURE_TAP_KEY => Ok(response::SignatureEntry::TapKey {
            input_index,
            signature: reader.take_bytes()?,
        }),
        response::SIGNATURE_TAP_SCRIPT => Ok(response::SignatureEntry::TapScript {
            input_index,
            xonly_public_key: reader.take_array()?,
            tap_leaf_hash: reader.take_array()?,
            signature: reader.take_bytes()?,
        }),
        value => Err(Error::UnknownSignatureKind(value)),
    }
}

fn read_path(reader: &mut Reader<'_>) -> Result<DerivationPath, Error> {
    let count = reader.take_u8()? as usize;
    let mut children = Vec::new();
    for _ in 0..count {
        children.push(reader.take_u32_be()?);
    }
    Ok(DerivationPath(children))
}

fn read_descriptor_alias(reader: &mut Reader<'_>) -> Result<String, Error> {
    Ok(reader.take_string_with_limit(MAX_DESCRIPTOR_ALIAS)?)
}

fn read_xpub(reader: &mut Reader<'_>) -> Result<Xpub, Error> {
    Ok(Xpub(reader.take_array()?))
}

fn read_fingerprint(reader: &mut Reader<'_>) -> Result<Fingerprint, Error> {
    Ok(Fingerprint(reader.take_array()?))
}

fn read_capabilites(reader: &mut Reader<'_>) -> Result<response::Capabilities, Error> {
    Ok(response::Capabilities(reader.take_u32_be()?))
}

fn read_pubkey(reader: &mut Reader<'_>) -> Result<PublicKey, Error> {
    Ok(PublicKey(reader.take_array()?))
}

fn read_version(reader: &mut Reader<'_>) -> Result<response::FirmwareVersion, Error> {
    let major = reader.take_u16_be()?;
    let minor = reader.take_u16_be()?;
    let patch = ((reader.take_u8()? as u32) << 16)
        | ((reader.take_u8()? as u32) << 8)
        | reader.take_u8()? as u32;
    let flag = response::ReleaseFlag::from(reader.take_u8()?);
    Ok(response::FirmwareVersion {
        major,
        minor,
        patch,
        flag,
    })
}

fn read_sign_response_kind(reader: &mut Reader<'_>) -> Result<SignResponseKind, Error> {
    SignResponseKind::try_from(reader.take_u8()?)
}
