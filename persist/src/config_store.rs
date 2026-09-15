//! Pluggable persistence for wallet `Config` structs.
//!
//! `Account` constructors hold an `Arc<dyn ConfigStore<Config>>` so the
//! orchestrator can persist a mutated config without knowing where it
//! lives. Three impls ship here:
//!
//! - [`NoopConfigStore`]: `save` is a no-op, `load` returns `None`.
//!   The default; suitable when the consumer holds the config
//!   externally (e.g. an FFI host).
//! - [`FileConfigStore`]: JSON file at a fixed [`PathBuf`]. The
//!   replacement for the old `Config::to_file` / `Config::from_file`
//!   inherent methods.
//! - [`CallbackConfigStore`]: bridges save/load to caller-supplied
//!   closures, for hosts that hold config through their own KV layer
//!   (e.g. platform preferences in an FFI consumer).

use std::{
    fs,
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{de::DeserializeOwned, Serialize};

use crate::PersistError;

/// Persistence interface for a wallet `Config` struct.
///
/// `C` is the consumer's config type (`bwk::config::Config` /
/// `bwk_sp::account::config::Config`). The trait itself is unconstrained;
/// only [`FileConfigStore`] requires `Serialize + DeserializeOwned`.
pub trait ConfigStore<C>: Send + Sync {
    fn save(&self, config: &C) -> Result<(), PersistError>;
    /// Returns `Ok(None)` when nothing is persisted yet (first run).
    fn load(&self) -> Result<Option<C>, PersistError>;
}

/// Discards saves and reports nothing on load.
///
/// Use as the default for FFI / mobile builds where native code owns
/// config persistence, or in tests that don't care about durability.
pub struct NoopConfigStore<C>(PhantomData<fn() -> C>);

impl<C> Default for NoopConfigStore<C> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C> NoopConfigStore<C> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<C: Send + Sync> ConfigStore<C> for NoopConfigStore<C> {
    fn save(&self, _config: &C) -> Result<(), PersistError> {
        Ok(())
    }
    fn load(&self) -> Result<Option<C>, PersistError> {
        Ok(None)
    }
}

/// Persists `C` as pretty-printed JSON at a fixed [`PathBuf`].
///
/// Save is atomic (write to `{path}.tmp`, fsync, rename over `path`).
/// Load returns `Ok(None)` when the file is absent.
pub struct FileConfigStore<C> {
    path: PathBuf,
    _marker: PhantomData<fn() -> C>,
}

impl<C> FileConfigStore<C> {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            _marker: PhantomData,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl<C> ConfigStore<C> for FileConfigStore<C>
where
    C: Serialize + DeserializeOwned + Send + Sync,
{
    fn save(&self, config: &C) -> Result<(), PersistError> {
        let bytes = serde_json::to_vec_pretty(config)
            .map_err(|e| PersistError::Serde(format!("serialize config: {e}")))?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    PersistError::Io(format!("create_dir_all {}: {e}", parent.display()))
                })?;
            }
        }

        let mut tmp = self.path.clone();
        let name = self
            .path
            .file_name()
            .ok_or_else(|| PersistError::Io("config path has no file name".into()))?
            .to_string_lossy()
            .into_owned();
        tmp.set_file_name(format!("{name}.tmp"));

        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| PersistError::Io(format!("create {}: {e}", tmp.display())))?;
            f.write_all(&bytes)
                .map_err(|e| PersistError::Io(format!("write {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| PersistError::Io(format!("fsync {}: {e}", tmp.display())))?;
        }

        fs::rename(&tmp, &self.path).map_err(|e| {
            PersistError::Io(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })
    }

    fn load(&self) -> Result<Option<C>, PersistError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let cfg: C = serde_json::from_slice(&bytes).map_err(|e| {
                    PersistError::Serde(format!("parse {}: {e}", self.path.display()))
                })?;
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PersistError::Io(format!(
                "read {}: {e}",
                self.path.display()
            ))),
        }
    }
}

type SaveFn<C> = dyn Fn(&C) -> Result<(), PersistError> + Send + Sync;
type LoadFn<C> = dyn Fn() -> Result<Option<C>, PersistError> + Send + Sync;

/// Bridges save/load to host-language closures. For FFI consumers
/// (e.g. mobile keeping config in platform-native KV stores).
pub struct CallbackConfigStore<C> {
    saver: Arc<SaveFn<C>>,
    loader: Arc<LoadFn<C>>,
}

impl<C> CallbackConfigStore<C> {
    pub fn new<S, L>(saver: S, loader: L) -> Self
    where
        S: Fn(&C) -> Result<(), PersistError> + Send + Sync + 'static,
        L: Fn() -> Result<Option<C>, PersistError> + Send + Sync + 'static,
    {
        Self {
            saver: Arc::new(saver),
            loader: Arc::new(loader),
        }
    }
}

impl<C: Send + Sync> ConfigStore<C> for CallbackConfigStore<C> {
    fn save(&self, config: &C) -> Result<(), PersistError> {
        (self.saver)(config)
    }
    fn load(&self) -> Result<Option<C>, PersistError> {
        (self.loader)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Demo {
        name: String,
        n: u32,
    }

    fn tmp_dir() -> temp_dir::TempDir {
        temp_dir::TempDir::new().unwrap()
    }

    #[test]
    fn noop_save_is_silent_load_is_none() {
        let s: NoopConfigStore<Demo> = NoopConfigStore::default();
        s.save(&Demo {
            name: "x".into(),
            n: 1,
        })
        .unwrap();
        assert!(s.load().unwrap().is_none());
    }

    #[test]
    fn file_round_trip() {
        let d = tmp_dir();
        let store: FileConfigStore<Demo> = FileConfigStore::new(d.path().join("c.json"));
        assert!(store.load().unwrap().is_none(), "fresh dir = None");
        let cfg = Demo {
            name: "alice".into(),
            n: 42,
        };
        store.save(&cfg).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn file_save_creates_missing_parents() {
        let d = tmp_dir();
        let nested = d.path().join("a").join("b").join("c.json");
        let store: FileConfigStore<Demo> = FileConfigStore::new(nested.clone());
        store
            .save(&Demo {
                name: "n".into(),
                n: 7,
            })
            .unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn file_save_is_atomic_no_tmp_left() {
        let d = tmp_dir();
        let path = d.path().join("c.json");
        let store: FileConfigStore<Demo> = FileConfigStore::new(path.clone());
        store
            .save(&Demo {
                name: "z".into(),
                n: 9,
            })
            .unwrap();
        let entries: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "expected only c.json, got {entries:?}");
    }

    #[test]
    fn callback_round_trip() {
        let saved: Arc<Mutex<Option<Demo>>> = Arc::new(Mutex::new(None));
        let saved_w = saved.clone();
        let saved_r = saved.clone();
        let s: CallbackConfigStore<Demo> = CallbackConfigStore::new(
            move |c: &Demo| {
                *saved_w.lock().unwrap() = Some(c.clone());
                Ok(())
            },
            move || Ok(saved_r.lock().unwrap().clone()),
        );
        assert!(s.load().unwrap().is_none());
        let cfg = Demo {
            name: "k".into(),
            n: 3,
        };
        s.save(&cfg).unwrap();
        assert_eq!(s.load().unwrap().unwrap(), cfg);
    }
}
