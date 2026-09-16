//! Builds the C view of a decoded request.
//!
//! Every pointer handed to C targets a heap buffer owned by [`Keep`], never a field
//! of [`Owned`] and never a temporary. `Owned` is moved into its `Box` after the view
//! is built, and moving a `Vec` header does not move its heap buffer, so the pointers
//! stay valid for as long as the handle lives.

use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::{ffi::c_char, ptr};

use crate::{
    ffi::{types, Error},
    request,
    types::DerivationPath,
    Request,
};

#[repr(C)]
pub struct Owned {
    // offset 0, the only thing C ever sees
    pub view: types::Request,
    keep: Keep,
}

impl Owned {
    pub fn build(request: &Request) -> Result<Box<Self>, Error> {
        let mut keep = Keep::default();
        let body = keep.request_body(&request.body)?;
        Ok(Box::new(Self {
            view: types::Request {
                id: request.id.0,
                message_type: request.body.message_type().value(),
                body,
            },
            keep,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi::{owned::Owned, types};

    #[test]
    fn the_view_sits_at_offset_zero() {
        // bwk_qr_request_free casts the handle C holds back to `Owned`
        assert_eq!(core::mem::offset_of!(Owned, view), 0);
        assert_eq!(
            core::mem::align_of::<Owned>() % core::mem::align_of::<types::Request>(),
            0
        );
    }
}

#[derive(Default)]
struct Keep {
    strings: Vec<CString>,
    bytes: Vec<Vec<u8>>,
    paths: Vec<Vec<u32>>,
    path_lists: Vec<Vec<types::Path>>,
    key_lists: Vec<Vec<*const c_char>>,
    descriptor_lists: Vec<Vec<types::Descriptor>>,
    // C holds a pointer to each body, so it must not move when the list grows
    #[allow(clippy::vec_box)]
    descriptor_bodies: Vec<Box<types::DescriptorBody>>,
}

impl Keep {
    fn request_body(&mut self, body: &request::Body) -> Result<types::RequestBody, Error> {
        Ok(match body {
            request::Body::GetXpubs(body) => types::RequestBody {
                get_xpubs: types::GetXpubs {
                    derivation_paths: self.path_list(&body.derivation_paths),
                },
            },
            request::Body::RegisterDescriptor(body) => types::RequestBody {
                register_descriptor: types::RegisterDescriptor {
                    descriptor_alias: self.string(&body.descriptor_alias)?,
                    descriptor: self.optional_descriptor_body(body.descriptor.as_ref())?,
                },
            },
            request::Body::VerifyAddress(body) => types::RequestBody {
                verify_address: types::VerifyAddress {
                    descriptor_alias: self.string(&body.descriptor_alias)?,
                    derivation_path: self.path(&body.derivation_path),
                    address: self.optional_string(body.address.as_deref())?,
                    descriptor: self.optional_descriptor_body(body.descriptor.as_ref())?,
                    proof: self.optional_bytes(body.proof.as_deref()),
                },
            },
            request::Body::Sign(body) => types::RequestBody {
                sign: types::Sign {
                    descriptors: self.descriptor_list(&body.descriptors)?,
                    psbt: self.bytes(&body.psbt),
                    want_kind: body
                        .want_kind
                        .map_or(types::ABSENT_KIND, |kind| kind.value() as i16),
                },
            },
            request::Body::GetSpDescriptor(_) => types::RequestBody {
                get_sp_descriptor: types::GetSpDescriptor { _unused: 0 },
            },
        })
    }

    fn descriptor_list(
        &mut self,
        descriptors: &[request::Descriptor],
    ) -> Result<types::List<types::Descriptor>, Error> {
        let mut items = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            items.push(types::Descriptor {
                alias: self.string(&descriptor.alias)?,
                body: self.optional_descriptor_body(descriptor.descriptor.as_ref())?,
                proof: self.optional_bytes(descriptor.proof.as_deref()),
            });
        }
        Ok(keep_list(&mut self.descriptor_lists, items))
    }

    fn optional_descriptor_body(
        &mut self,
        body: Option<&request::DescriptorBody>,
    ) -> Result<*const types::DescriptorBody, Error> {
        let Some(body) = body else {
            return Ok(ptr::null());
        };
        let body = self.descriptor_body(body)?;
        self.descriptor_bodies.push(Box::new(body));
        Ok(&**self.descriptor_bodies.last().expect("just pushed"))
    }

    fn descriptor_body(
        &mut self,
        body: &request::DescriptorBody,
    ) -> Result<types::DescriptorBody, Error> {
        let value = match body {
            request::DescriptorBody::Bip380(descriptor) => types::DescriptorValue {
                bip380: self.string(descriptor)?,
            },
            request::DescriptorBody::Bip388 { keys, policy } => types::DescriptorValue {
                bip388: types::Bip388 {
                    keys: self.key_list(keys)?,
                    policy: self.string(policy)?,
                },
            },
        };
        Ok(types::DescriptorBody {
            tag: body.value(),
            value,
        })
    }

    fn key_list(&mut self, keys: &[String]) -> Result<types::List<*const c_char>, Error> {
        let mut items = Vec::with_capacity(keys.len());
        for key in keys {
            items.push(self.string(key)?);
        }
        Ok(keep_list(&mut self.key_lists, items))
    }

    fn path_list(&mut self, paths: &[DerivationPath]) -> types::List<types::Path> {
        let items = paths.iter().map(|path| self.path(path)).collect::<Vec<_>>();
        keep_list(&mut self.path_lists, items)
    }

    fn path(&mut self, path: &DerivationPath) -> types::Path {
        self.paths.push(path.0.clone());
        let children = self.paths.last().expect("just pushed");
        types::Path {
            ptr: children.as_ptr(),
            // the encoder caps a path at MAX_PATH, so the count always fits
            len: children.len() as u8,
        }
    }

    fn optional_string(&mut self, value: Option<&str>) -> Result<*const c_char, Error> {
        match value {
            Some(value) => self.string(value),
            None => Ok(ptr::null()),
        }
    }

    fn string(&mut self, value: &str) -> Result<*const c_char, Error> {
        let value = CString::new(value).map_err(|_| Error::StringNul)?;
        self.strings.push(value);
        Ok(self.strings.last().expect("just pushed").as_ptr())
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) -> types::Bytes {
        match value {
            Some(value) => self.bytes(value),
            None => types::Bytes::absent(),
        }
    }

    fn bytes(&mut self, value: &[u8]) -> types::Bytes {
        keep_list(&mut self.bytes, value.to_vec())
    }
}

fn keep_list<T>(lists: &mut Vec<Vec<T>>, items: Vec<T>) -> types::List<T> {
    lists.push(items);
    let items = lists.last().expect("just pushed");
    types::List {
        ptr: items.as_ptr(),
        len: items.len(),
    }
}
