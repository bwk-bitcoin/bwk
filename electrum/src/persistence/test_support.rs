//! Caller-owned storage fixtures shared by wallet integration tests.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bwk_persist::{backend::PersistenceBackend, PersistError};

use crate::persistence::{BackendFactory, BackendIdentity, BackendKind};

type Rows = BTreeMap<String, Vec<u8>>;

#[derive(Debug)]
enum Data {
    Memory(BTreeMap<String, Rows>),
    WholeFile(BTreeMap<String, Vec<u8>>),
}

/// A backend over caller-held memory or serialized whole-store blobs.
#[derive(Debug)]
pub struct CallerBackend {
    data: Mutex<Data>,
    pub fail_read: Mutex<Option<String>>,
    pub fail_write: Mutex<Option<String>>,
}

impl CallerBackend {
    fn read(data: &Data, store: &str) -> Result<Rows, PersistError> {
        match data {
            Data::Memory(stores) => Ok(stores.get(store).cloned().unwrap_or_default()),
            Data::WholeFile(blobs) => match blobs.get(store) {
                Some(bytes) => {
                    serde_json::from_slice(bytes).map_err(|e| PersistError::Serde(e.to_string()))
                }
                None => Ok(Rows::new()),
            },
        }
    }

    pub fn corrupt(&self, store: &str) {
        match &mut *self.data.lock().unwrap() {
            Data::WholeFile(blobs) => {
                blobs.insert(store.into(), b"corrupt".to_vec());
            }
            Data::Memory(_) => panic!("corruption fixture requires whole files"),
        }
    }
}

impl PersistenceBackend for CallerBackend {
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError> {
        Ok(self
            .get_rows(store)?
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v))
    }

    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        self.validate_store_name(store)?;
        if self.fail_read.lock().unwrap().as_deref() == Some(store) {
            return Err(PersistError::Io(format!("read denied: {store}")));
        }
        Ok(Self::read(&self.data.lock().unwrap(), store)?
            .into_iter()
            .collect())
    }

    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        self.flush_batch(store, &[(key.into(), bytes.to_vec())], &[])
    }

    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError> {
        self.flush_batch(store, &[], &[key.into()])
    }

    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        if self.fail_write.lock().unwrap().as_deref() == Some(store) {
            return Err(PersistError::Io(format!("write denied: {store}")));
        }
        let mut data = self.data.lock().unwrap();
        let mut rows = Self::read(&data, store)?;
        for key in removed {
            rows.remove(key);
        }
        rows.extend(inserts.iter().cloned());
        match &mut *data {
            Data::Memory(stores) => {
                stores.insert(store.into(), rows);
            }
            Data::WholeFile(blobs) => {
                let bytes =
                    serde_json::to_vec(&rows).map_err(|e| PersistError::Serde(e.to_string()))?;
                blobs.insert(store.into(), bytes);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CallerFactory {
    whole_file: bool,
    backends: Mutex<BTreeMap<BackendIdentity, Arc<CallerBackend>>>,
    pub requests: Mutex<Vec<BackendIdentity>>,
    pub fail_open: Mutex<Option<BackendKind>>,
}

impl CallerFactory {
    pub fn new(whole_file: bool) -> Self {
        Self {
            whole_file,
            backends: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(Vec::new()),
            fail_open: Mutex::new(None),
        }
    }

    pub fn backend(&self, identity: BackendIdentity) -> Arc<CallerBackend> {
        self.backends
            .lock()
            .unwrap()
            .entry(identity)
            .or_insert_with(|| {
                Arc::new(CallerBackend {
                    data: Mutex::new(if self.whole_file {
                        Data::WholeFile(BTreeMap::new())
                    } else {
                        Data::Memory(BTreeMap::new())
                    }),
                    fail_read: Mutex::new(None),
                    fail_write: Mutex::new(None),
                })
            })
            .clone()
    }
}

impl BackendFactory for CallerFactory {
    fn open(
        &self,
        identity: &BackendIdentity,
    ) -> Result<Arc<dyn PersistenceBackend>, PersistError> {
        self.requests.lock().unwrap().push(identity.clone());
        if *self.fail_open.lock().unwrap() == Some(identity.kind) {
            return Err(PersistError::Io(format!(
                "open denied: {:?}",
                identity.kind
            )));
        }
        Ok(self.backend(identity.clone()))
    }
}
