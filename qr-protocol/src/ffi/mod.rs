//! C binding for the signer direction: decode a request, encode a response.
//!
//! Ownership rule: Rust never frees C memory, and C never frees Rust memory except
//! through `bwk_qr_request_free` and `bwk_qr_buf_free`. On encode the C struct is
//! borrowed for the duration of the call only.
//!
//! No entry point may panic. `no_std` has no unwinding, so a panic would reach the
//! firmware's handler instead of returning a code.

mod owned;
mod read;
pub mod types;

use alloc::boxed::Box;
use core::{ffi::c_char, ptr, slice};

use crate::{ErrorInfo, Message};

pub const OK: i32 = 0;

/// Failures at the C boundary that the codec itself cannot produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NullPointer,
    StringNul,
    InvalidUtf8,
    InvalidBool,
    UnknownTag,
    UnterminatedFixedString,
    UnexpectedResponse,
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::NullPointer => error_info!(400, "null pointer"),
            Self::StringNul => error_info!(401, "string contains a nul byte"),
            Self::InvalidUtf8 => error_info!(402, "invalid utf-8 string"),
            Self::InvalidBool => error_info!(403, "invalid tri-state bool"),
            Self::UnknownTag => error_info!(404, "unknown union tag"),
            Self::UnterminatedFixedString => error_info!(405, "fixed string is not nul-terminated"),
            Self::UnexpectedResponse => error_info!(406, "expected a request, got a response"),
        }
    }
}

error_display!(Error);

/// Decodes a request. On success `*out` owns the tree until `bwk_qr_request_free`.
///
/// # Safety
/// `bytes` must be readable for `len`, and `out` writable. `err` may be null; when it
/// is not, a failure writes a static message to it.
#[no_mangle]
pub unsafe extern "C" fn bwk_qr_request_decode(
    bytes: *const u8,
    len: usize,
    out: *mut *const types::Request,
    err: *mut *const c_char,
) -> i32 {
    if bytes.is_null() || out.is_null() {
        return fail(Error::NullPointer.info(), err);
    }
    let message = match crate::decode(slice::from_raw_parts(bytes, len)) {
        Ok(message) => message,
        Err(error) => return fail(error.info(), err),
    };
    let Message::Request(request) = message else {
        return fail(Error::UnexpectedResponse.info(), err);
    };
    match owned::Owned::build(&request) {
        Ok(owned) => {
            *out = Box::into_raw(owned).cast();
            OK
        }
        Err(error) => fail(error.info(), err),
    }
}

/// Releases a request returned by `bwk_qr_request_decode`. A null pointer is a no-op.
///
/// # Safety
/// `request` must come from `bwk_qr_request_decode` and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn bwk_qr_request_free(request: *const types::Request) {
    if request.is_null() {
        return;
    }
    drop(Box::from_raw(request as *mut owned::Owned));
}

/// Encodes a response. On success `*out` owns the bytes until `bwk_qr_buf_free`.
///
/// # Safety
/// `response` must be a fully initialized response whose pointers are valid for
/// reading, and `out` must be writable. `err` may be null.
#[no_mangle]
pub unsafe extern "C" fn bwk_qr_response_encode(
    response: *const types::Response,
    out: *mut types::Buf,
    err: *mut *const c_char,
) -> i32 {
    if response.is_null() || out.is_null() {
        return fail(Error::NullPointer.info(), err);
    }
    let response = match read::response(&*response) {
        Ok(response) => response,
        Err(error) => return fail(error.info(), err),
    };
    match crate::encode_response(&response) {
        Ok(bytes) => {
            let bytes = Box::leak(bytes.into_boxed_slice());
            *out = types::Buf {
                ptr: bytes.as_mut_ptr(),
                len: bytes.len(),
            };
            OK
        }
        Err(error) => fail(error.info(), err),
    }
}

/// Releases a buffer returned by the codec. A null pointer is a no-op.
///
/// # Safety
/// `buf` must come from this crate and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn bwk_qr_buf_free(buf: types::Buf) {
    if buf.ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
        buf.ptr, buf.len,
    )));
}

unsafe fn fail(info: ErrorInfo, err: *mut *const c_char) -> i32 {
    if !err.is_null() {
        *err = info.message.as_ptr().cast();
    }
    info.code
}
