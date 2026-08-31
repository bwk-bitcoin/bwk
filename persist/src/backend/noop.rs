//! No-op backend: discards writes, reads always return absent.
//!
//! Used when persistence is disabled (e.g. `Config::with_persistence(None)`
//! or tests).

use super::PersistenceBackend;
use crate::PersistError;

/// A backend that discards all writes and reads as absent. Used when
/// persistence is disabled (e.g. `Config::with_persistence(None)` or tests).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBackend;

impl NoopBackend {
    pub fn new() -> Self {
        Self
    }
}

impl PersistenceBackend for NoopBackend {
    fn get_row(&self, _store: &str, _pk: &str) -> Result<Option<Vec<u8>>, PersistError> {
        Ok(None)
    }
    fn get_rows(&self, _store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        Ok(Vec::new())
    }
    fn put_row(&self, _store: &str, _pk: &str, _bytes: &[u8]) -> Result<(), PersistError> {
        Ok(())
    }
    fn delete_row(&self, _store: &str, _pk: &str) -> Result<(), PersistError> {
        Ok(())
    }
    fn flush_batch(
        &self,
        _store: &str,
        _inserts: &[(String, Vec<u8>)],
        _removed: &[String],
    ) -> Result<(), PersistError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_backend_load_row_is_absent() {
        let b = NoopBackend::new();
        assert!(b.get_row("any", "key").unwrap().is_none());
    }

    #[test]
    fn noop_backend_put_is_ignored() {
        let b = NoopBackend::new();
        b.put_row("s", "k", b"v").unwrap();
        assert!(b.get_row("s", "k").unwrap().is_none());
    }

    #[test]
    fn noop_backend_load_rows_empty() {
        let b = NoopBackend::new();
        assert!(b.get_rows("s").unwrap().is_empty());
    }
}
