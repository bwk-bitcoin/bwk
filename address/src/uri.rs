//! The parser follows the one of the `bip321` crate (0.4.0, MIT).

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

const SCHEME: &str = "bitcoin:";
const REQUIRED_PREFIX: &str = "req-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    InvalidScheme,
    InvalidAddress(String),
    MalformedParam(String),
    DuplicateParam(String),
    UnsupportedRequiredParam(String),
    NoAddress,
    MultipleAddresses,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScheme => f.write_str("scheme is not bitcoin:"),
            Self::InvalidAddress(address) => write!(f, "invalid address: {address}"),
            Self::MalformedParam(param) => write!(f, "malformed parameter: {param}"),
            Self::DuplicateParam(key) => write!(f, "duplicate parameter: {key}"),
            Self::UnsupportedRequiredParam(key) => {
                write!(f, "unsupported required parameter: {key}")
            }
            Self::NoAddress => f.write_str("no address"),
            Self::MultipleAddresses => f.write_str("more than one address"),
        }
    }
}

impl core::error::Error for UriError {}

pub struct Uri<'a> {
    pub address: UriAddress<'a>,
    pub amount: Option<&'a str>,
}

pub enum UriAddress<'a> {
    Bitcoin(&'a str),
    SilentPayment(&'a str),
}

enum Param<'a> {
    Sp(&'a str),
    Amount(&'a str),
    Discarded,
}

pub fn parse(uri: &str) -> Result<Uri<'_>, UriError> {
    let body = strip_prefix_ignore_case(uri.trim(), SCHEME).ok_or(UriError::InvalidScheme)?;
    let (path, query) = match body.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (body, None),
    };
    if !path.is_empty() {
        check_address(path)?;
    }
    let mut sp = Vec::new();
    let mut amount = None;
    let mut seen = BTreeSet::new();
    let params = query.into_iter().flat_map(|query| query.split('&'));
    for param in params.filter(|param| !param.is_empty()) {
        match check_param(param, &mut seen)? {
            Param::Sp(value) => sp.push(value),
            Param::Amount(value) => amount = Some(value),
            Param::Discarded => {}
        }
    }
    Ok(Uri {
        address: address(path, &sp)?,
        amount,
    })
}

fn address<'a>(path: &'a str, sp: &[&'a str]) -> Result<UriAddress<'a>, UriError> {
    match (path, sp) {
        ("", [sp]) if !sp.is_empty() => Ok(UriAddress::SilentPayment(sp)),
        ("", [] | [_]) => Err(UriError::NoAddress),
        (path, []) => Ok(UriAddress::Bitcoin(path)),
        _ => Err(UriError::MultipleAddresses),
    }
}

fn check_param<'a>(param: &'a str, seen: &mut BTreeSet<String>) -> Result<Param<'a>, UriError> {
    let (raw_key, value) = param
        .split_once('=')
        .ok_or_else(|| UriError::MalformedParam(param.to_string()))?;
    let (required, key) = match strip_prefix_ignore_case(raw_key, REQUIRED_PREFIX) {
        Some(key) => (true, key),
        None => (false, raw_key),
    };
    let key = key.to_ascii_lowercase();
    match key.as_str() {
        "amount" | "label" | "message" | "pop" if !seen.insert(key.clone()) => {
            Err(UriError::DuplicateParam(key))
        }
        "amount" => Ok(Param::Amount(value)),
        "sp" => Ok(Param::Sp(value)),
        "bc" | "tb" => check_address(value).map(|()| Param::Discarded),
        "label" | "message" | "pop" | "lightning" | "lno" | "pay" => Ok(Param::Discarded),
        _ if required => Err(UriError::UnsupportedRequiredParam(key)),
        _ => Ok(Param::Discarded),
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    match s.get(..prefix.len()) {
        Some(head) if head.eq_ignore_ascii_case(prefix) => Some(&s[prefix.len()..]),
        _ => None,
    }
}

fn check_address(address: &str) -> Result<(), UriError> {
    if address.is_empty() || !address.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(UriError::InvalidAddress(address.to_string()));
    }
    Ok(())
}
