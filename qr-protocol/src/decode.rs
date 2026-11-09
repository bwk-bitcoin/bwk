use alloc::{string::String, vec::Vec};

use crate::{
    get_info, musig,
    reader::{self, Reader},
    request, response, sp,
    types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey, SecretKey},
    ErrorInfo, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    DIRECTION_RESPONSE, ERROR_MESSAGE_LEN, MAGIC, MAX_DESCRIPTOR_ALIAS, MAX_MUSIG_DERIVATIONS,
    MAX_VEC, MODEL_LEN, STATUS_ERROR, TYPE_MASK, VENDOR_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Musig(musig::Error),
    InvalidMagic,
    ReservedVersion,
    UnknownMessageType(u8),
    ErrorStatusOnRequest,
    UnknownDescriptorForm(u8),
    UnknownSignResponseKind(u8),
    UnknownKeyKind(u8),
    SignatureLength(u8),
    GlobalInputIndex(u32),
    ScanPathAndKey,
    NoScan,
    Sp(sp::Error),
    GetInfo(get_info::Error),
    Read(reader::Error),
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::Musig(error) => error.info(),
            Self::InvalidMagic => error_info!(200, "invalid magic"),
            Self::ReservedVersion => error_info!(201, "reserved protocol version"),
            Self::UnknownMessageType(_) => error_info!(202, "unknown message type"),
            Self::ErrorStatusOnRequest => error_info!(203, "request cannot carry error status"),
            Self::UnknownDescriptorForm(_) => error_info!(204, "unknown descriptor form"),
            Self::UnknownSignResponseKind(_) => error_info!(206, "unknown signing response kind"),
            Self::UnknownKeyKind(_) => error_info!(207, "unknown key kind"),
            Self::SignatureLength(_) => {
                error_info!(208, "signature entry fields do not fill its length")
            }
            Self::GlobalInputIndex(_) => {
                error_info!(209, "global silent payment entry has a nonzero input index")
            }
            Self::ScanPathAndKey => {
                error_info!(
                    210,
                    "silent payment keys carry both a scan path and a scan key"
                )
            }
            Self::NoScan => {
                error_info!(
                    211,
                    "silent payment keys carry neither a scan path nor a scan key"
                )
            }
            Self::Sp(error) => error.info(),
            Self::GetInfo(error) => error.info(),
            Self::Read(inner) => inner.info(),
        }
    }
}

error_display!(Error);

impl From<musig::Error> for Error {
    fn from(error: musig::Error) -> Self {
        Self::Musig(error)
    }
}

impl From<sp::Error> for Error {
    fn from(error: sp::Error) -> Self {
        Self::Sp(error)
    }
}

impl From<get_info::Error> for Error {
    fn from(error: get_info::Error) -> Self {
        Self::GetInfo(error)
    }
}

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
        (false, _, MessageType::GetKeys) => Message::Request(Request {
            id,
            body: request::Body::GetKeys(read_get_keys_request(&mut reader)?),
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
        (false, _, MessageType::MusigPreparation) => Message::Request(Request {
            id,
            body: request::Body::PrepareMusig(read_prepare_musig(&mut reader)?),
        }),
        (false, _, MessageType::MusigSigning) => Message::Request(Request {
            id,
            body: request::Body::SignMusig(read_sign_musig(&mut reader)?),
        }),
        (false, _, MessageType::GetInfo) => Message::Request(Request {
            id,
            body: request::Body::GetInfo,
        }),
        (true, true, _) => Message::Response(Response {
            id,
            body: response::Body::Error(read_error_response(&mut reader, message_type)?),
        }),
        (true, false, MessageType::GetKeys) => Message::Response(Response {
            id,
            body: response::Body::Keys(read_keys_response(&mut reader)?),
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
        (true, false, MessageType::MusigPreparation) => Message::Response(Response {
            id,
            body: response::Body::MusigPrepared(read_musig_prepared(&mut reader)?),
        }),
        (true, false, MessageType::MusigSigning) => Message::Response(Response {
            id,
            body: response::Body::MusigSigned(read_musig_signed(&mut reader)?),
        }),
        (true, false, MessageType::GetInfo) => Message::Response(Response {
            id,
            body: response::Body::Info(read_info_response(&mut reader)?),
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

fn read_get_keys_request(reader: &mut Reader<'_>) -> Result<request::GetKeys, Error> {
    Ok(request::GetKeys {
        keys: reader.take_vec(read_key_request)?,
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

fn read_prepare_musig(reader: &mut Reader<'_>) -> Result<request::PrepareMusig, Error> {
    let descriptor = read_descriptor(reader)?;
    let session_id = reader.take_array()?;
    let max_inputs = reader.take_u8()?;
    musig::validate_input_coverage(max_inputs)?;
    let count = reader.take_compact()?;
    if count == 0 || count > MAX_MUSIG_DERIVATIONS {
        return Err(musig::Error::DerivationCount.into());
    }
    let mut derivations = Vec::new();
    for _ in 0..count {
        derivations.push(read_musig_derivation(reader)?);
    }
    let request = request::PrepareMusig {
        descriptor,
        session_id,
        max_inputs,
        derivations,
    };
    request.validate()?;
    Ok(request)
}

fn read_musig_derivation(reader: &mut Reader<'_>) -> Result<request::MusigDerivation, Error> {
    Ok(request::MusigDerivation {
        keychain: reader.take_u32_be()?,
        index: reader.take_u32_be()?,
    })
}

fn read_sign_musig(reader: &mut Reader<'_>) -> Result<request::SignMusig, Error> {
    Ok(request::SignMusig {
        session_id: reader.take_array()?,
        attempt_id: reader.take_array()?,
        psbt: reader.take_bytes()?,
    })
}

fn read_musig_prepared(reader: &mut Reader<'_>) -> Result<response::MusigPrepared, Error> {
    let session_id = reader.take_array()?;
    let max_inputs = reader.take_u8()?;
    musig::validate_input_coverage(max_inputs)?;
    let count = reader.take_compact()?;
    if count == 0 || count > MAX_VEC {
        return Err(musig::Error::NonceCount.into());
    }
    let mut nonces = Vec::new();
    for _ in 0..count {
        nonces.push(read_cached_musig_nonce(reader)?);
    }
    let response = response::MusigPrepared {
        session_id,
        max_inputs,
        nonces,
    };
    response.validate()?;
    Ok(response)
}

fn read_cached_musig_nonce(reader: &mut Reader<'_>) -> Result<response::MusigNonce, Error> {
    Ok(response::MusigNonce {
        derivation: read_musig_derivation(reader)?,
        input_index: reader.take_u32_be()?,
        expression_index: reader.take_u32_be()?,
        participant: read_pubkey(reader)?,
        aggregate: read_pubkey(reader)?,
        leaf_hash: reader.take_option(|r| r.take_array())?,
        nonce: reader.take_array()?,
    })
}

fn read_musig_signed(reader: &mut Reader<'_>) -> Result<response::MusigSigned, Error> {
    Ok(response::MusigSigned {
        session_id: reader.take_array()?,
        attempt_id: reader.take_array()?,
        psbt: reader.take_bytes()?,
    })
}

fn read_keys_response(reader: &mut Reader<'_>) -> Result<response::Keys, Error> {
    Ok(response::Keys {
        keys: reader.take_vec(read_extended_key)?,
        fingerprint: read_fingerprint(reader)?,
        vendor: reader.take_fixed_string(VENDOR_LEN)?,
        model: reader.take_fixed_string(MODEL_LEN)?,
        version: read_version(reader)?,
        capabilities: read_capabilites(reader)?,
    })
}

fn read_info_response(reader: &mut Reader<'_>) -> Result<response::Info, Error> {
    let response = response::Info {
        vendor: reader.take_fixed_string(VENDOR_LEN)?,
        model: reader.take_fixed_string(MODEL_LEN)?,
        version: read_version(reader)?,
        capabilities: read_capabilites(reader)?,
        state: reader.take_u8()?.into(),
        networks: response::Networks(reader.take_u8()?),
        max_message: reader.take_u32_be()?,
        max_alias: reader.take_u8()?,
        max_keys: reader.take_u8()?,
        slots: reader.take_u16_be()?,
        fingerprint: reader.take_option(read_fingerprint)?,
    };
    response.validate()?;
    Ok(response)
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
        SignResponseKind::Signatures => {
            let entries = reader.take_vec(read_signature)?;
            sp::validate_entries(&entries)?;
            Ok(response::Signed::Signatures(entries))
        }
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
        request::DESCRIPTOR_SP_KEYS => Ok(request::DescriptorBody::SpKeys(read_sp_keys(reader)?)),
        value => Err(Error::UnknownDescriptorForm(value)),
    }
}

fn read_sp_keys(reader: &mut Reader<'_>) -> Result<request::SpKeys, Error> {
    Ok(request::SpKeys {
        fingerprint: read_fingerprint(reader)?,
        spend_path: read_path(reader)?,
        scan: read_scan(reader)?,
    })
}

fn read_scan(reader: &mut Reader<'_>) -> Result<request::Scan, Error> {
    let path = reader.take_option(read_path)?;
    let key = reader.take_option(read_secret_key)?;
    match (path, key) {
        (Some(path), None) => Ok(request::Scan::Path(path)),
        (None, Some(key)) => Ok(request::Scan::Key(key)),
        (Some(_), Some(_)) => Err(Error::ScanPathAndKey),
        (None, None) => Err(Error::NoScan),
    }
}

fn read_signature(reader: &mut Reader<'_>) -> Result<response::SignatureEntry, Error> {
    let input_index = reader.take_u32_be()?;
    let kind = reader.take_u8()?;
    let mut fields = Reader::new(reader.take_bytes_slice()?);
    // running out of bytes inside the fields means they overflow the entry's LENGTH
    let entry =
        read_signature_fields(&mut fields, input_index, kind).map_err(|error| match error {
            Error::Read(reader::Error::Truncated) => Error::SignatureLength(kind),
            error => error,
        })?;
    if !fields.is_empty() {
        return Err(Error::SignatureLength(kind));
    }
    Ok(entry)
}

fn read_signature_fields(
    reader: &mut Reader<'_>,
    input_index: u32,
    kind: u8,
) -> Result<response::SignatureEntry, Error> {
    match kind {
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
        response::SIGNATURE_MUSIG_PUB_NONCE => Ok(response::SignatureEntry::MusigPubNonce {
            input_index,
            participant: read_pubkey(reader)?,
            aggregate: read_pubkey(reader)?,
            leaf_hash: reader.take_option(|r| r.take_array())?,
            nonce: reader.take_array()?,
        }),
        response::SIGNATURE_MUSIG_PARTIAL_SIG => Ok(response::SignatureEntry::MusigPartialSig {
            input_index,
            participant: read_pubkey(reader)?,
            aggregate: read_pubkey(reader)?,
            leaf_hash: reader.take_option(|r| r.take_array())?,
            signature: reader.take_array()?,
        }),
        response::SIGNATURE_SP_ECDH_SHARE => Ok(response::SignatureEntry::SpEcdhShare {
            scope: read_sp_scope(reader, input_index)?,
            scan_key: read_pubkey(reader)?,
            share: read_pubkey(reader)?,
        }),
        response::SIGNATURE_SP_DLEQ_PROOF => Ok(response::SignatureEntry::SpDleqProof {
            scope: read_sp_scope(reader, input_index)?,
            scan_key: read_pubkey(reader)?,
            proof: reader.take_array()?,
        }),
        kind => Ok(response::SignatureEntry::Unknown {
            input_index,
            kind,
            fields: reader.take_rest().to_vec(),
        }),
    }
}

fn read_sp_scope(reader: &mut Reader<'_>, input_index: u32) -> Result<response::SpScope, Error> {
    response::SpScope::from_wire(reader.take_bool()?, input_index)
        .ok_or(Error::GlobalInputIndex(input_index))
}

fn read_key_request(reader: &mut Reader<'_>) -> Result<request::KeyRequest, Error> {
    Ok(request::KeyRequest {
        derivation_path: read_path(reader)?,
        kind: request::KeyKind::try_from(reader.take_u8()?)?,
    })
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

fn read_extended_key(reader: &mut Reader<'_>) -> Result<ExtendedKey, Error> {
    Ok(ExtendedKey(reader.take_array()?))
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

fn read_secret_key(reader: &mut Reader<'_>) -> Result<SecretKey, Error> {
    Ok(SecretKey(reader.take_array()?))
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
