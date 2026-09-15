//! Scan state tracking for Silent Payment blockchain scanning.
//!
//! The `ScanState` tracks progress of blockchain scanning, including the last
//! scanned block height and hash (for reorg detection), and the wallet's
//! birthday height.

use std::sync::Arc;

use bwk::persist::{
    self as persist,
    backend::{noop::NoopBackend, PersistenceBackend},
    PersistError,
};

/// Row key under the `account` store for [`ScanState::last_scanned_height`].
const LAST_SCANNED_HEIGHT_ROW: &str = "last_scanned_height";
/// Row key under the `account` store for [`ScanState::last_block_hash`].
const LAST_BLOCK_HASH_ROW: &str = "last_block_hash";
/// Row key under the `account` store for [`ScanState::birthday_height`].
const BIRTHDAY_HEIGHT_ROW: &str = "birthday_height";
/// Row key under the `account` store for [`ScanState::last_spend_height`].
const LAST_SPEND_HEIGHT_ROW: &str = "last_spend_height";

// ScanState

/// Tracks blockchain scanning progress for Silent Payment wallets.
///
/// This struct maintains the scan position (last scanned height and block hash)
/// and the wallet's birthday height. The block hash is stored for reorg detection.
#[derive(Clone)]
pub struct ScanState {
    /// Receive (output) scan done up to here, not both passes (None if never
    /// scanned). Drives `next_scan_start`; the spend pass trails it.
    last_scanned_height: Option<u32>,

    /// The hash of the last scanned block (for reorg detection). Corresponds to
    /// `last_scanned_height`, the contiguous frontier of the receive pass.
    last_block_hash: Option<[u8; 32]>,

    /// Spend (input) sweep done up to here (None if never swept). Trails the
    /// receive frontier; persisted separately so a resume skips swept heights.
    last_spend_height: Option<u32>,

    /// The wallet's birthday height (where scanning should start)
    birthday_height: u32,

    backend: Arc<dyn PersistenceBackend>,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            last_scanned_height: None,
            last_block_hash: None,
            last_spend_height: None,
            birthday_height: 0,
            backend: Arc::new(NoopBackend),
        }
    }
}

impl std::fmt::Debug for ScanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanState")
            .field("last_scanned_height", &self.last_scanned_height)
            .field("last_block_hash", &self.last_block_hash)
            .field("last_spend_height", &self.last_spend_height)
            .field("birthday_height", &self.birthday_height)
            .finish()
    }
}

impl ScanState {
    // Constructors

    /// Create a new scan state with the given birthday height (no persistence).
    pub fn new(birthday_height: u32) -> Self {
        Self {
            last_scanned_height: None,
            last_block_hash: None,
            last_spend_height: None,
            birthday_height,
            backend: Arc::new(NoopBackend),
        }
    }

    /// Create a scan state backed by an arbitrary backend.
    pub fn with_backend(birthday_height: u32, backend: Arc<dyn PersistenceBackend>) -> Self {
        Self {
            last_scanned_height: None,
            last_block_hash: None,
            last_spend_height: None,
            birthday_height,
            backend,
        }
    }

    /// Load a scan state from the per-field rows in the `account` store.
    ///
    /// `birthday_height` is used as the fallback when no birthday row
    /// has been persisted yet (fresh wallet).
    pub fn load_from_backend(
        birthday_height: u32,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, PersistError> {
        let read_bytes = |row: &str| backend.get_row(persist::ACCOUNT_STORE_KEY, row);

        let last_scanned_height = match read_bytes(LAST_SCANNED_HEIGHT_ROW)? {
            Some(b) => serde_json::from_slice::<Option<u32>>(&b)
                .map_err(|e| PersistError::Serde(format!("scan_state last_scanned_height: {e}")))?,
            None => None,
        };

        let last_block_hash = match read_bytes(LAST_BLOCK_HASH_ROW)? {
            Some(b) => serde_json::from_slice::<Option<[u8; 32]>>(&b)
                .map_err(|e| PersistError::Serde(format!("scan_state last_block_hash: {e}")))?,
            None => None,
        };

        let birthday = match read_bytes(BIRTHDAY_HEIGHT_ROW)? {
            Some(b) => serde_json::from_slice::<u32>(&b)
                .map_err(|e| PersistError::Serde(format!("scan_state birthday_height: {e}")))?,
            None => birthday_height,
        };

        let last_spend_height = match read_bytes(LAST_SPEND_HEIGHT_ROW)? {
            Some(b) => serde_json::from_slice::<Option<u32>>(&b)
                .map_err(|e| PersistError::Serde(format!("scan_state last_spend_height: {e}")))?,
            None => None,
        };

        Ok(Self {
            last_scanned_height,
            last_block_hash,
            last_spend_height,
            birthday_height: birthday,
            backend,
        })
    }

    /// Returns the last scanned block height, if any.
    pub fn last_scanned_height(&self) -> Option<u32> {
        self.last_scanned_height
    }

    /// Returns the last scanned block hash, for reorg detection.
    pub fn last_block_hash(&self) -> Option<[u8; 32]> {
        self.last_block_hash
    }

    /// Returns the wallet's birthday height.
    pub fn birthday_height(&self) -> u32 {
        self.birthday_height
    }

    /// Returns the highest spend-swept height, if any.
    pub fn last_spend_height(&self) -> Option<u32> {
        self.last_spend_height
    }

    /// Advance the spend frontier monotonically (only moves forward).
    ///
    /// Mirrors `advance_frontier` for the spend (input) sweep, which trails the
    /// receive frontier.
    pub fn advance_spend_frontier(&mut self, height: u32) {
        let advance = match self.last_spend_height {
            Some(h) => height > h,
            None => true,
        };
        if advance {
            self.last_spend_height = Some(height);
        }
    }

    pub fn clear_progress(&mut self) {
        self.last_scanned_height = None;
        self.last_block_hash = None;
        self.last_spend_height = None;
    }

    /// Advance the contiguous receive frontier monotonically with its block hash.
    ///
    /// Used by the two-phase receive pass as its contiguous tip fills in.
    /// `last_block_hash` corresponds to `last_scanned_height` (the receive
    /// frontier), so the height and hash always move together.
    pub fn advance_frontier(&mut self, height: u32, block_hash: [u8; 32]) {
        let advance = match self.last_scanned_height {
            Some(h) => height > h,
            None => true,
        };
        if advance {
            self.last_scanned_height = Some(height);
            self.last_block_hash = Some(block_hash);
        }
    }

    /// Sets only the last scanned height without updating the block hash.
    /// Used for progress tracking when the block hash is not available.
    pub fn set_last_scanned_height(&mut self, height: u32) {
        match self.last_scanned_height {
            Some(h) if height > h => self.last_scanned_height = Some(height),
            None => self.last_scanned_height = Some(height),
            _ => {}
        }
    }

    /// Returns the height where the next scan should start.
    ///
    /// If no blocks have been scanned yet, returns the birthday height.
    /// Otherwise, returns the last scanned height + 1.
    pub fn next_scan_start(&self) -> u32 {
        self.last_scanned_height
            .map(|h| h + 1)
            .unwrap_or(self.birthday_height)
    }

    /// Returns the height where the next spend sweep should start.
    ///
    /// Mirrors `next_scan_start` for the spend (input) sweep: last swept height
    /// + 1, or the birthday if nothing has been swept yet.
    pub fn next_spend_start(&self) -> u32 {
        self.last_spend_height
            .map(|h| h + 1)
            .unwrap_or(self.birthday_height)
    }

    /// Persist the state through the configured backend.
    ///
    /// Writes the three scalar fields as individual rows under the
    /// [`persist::ACCOUNT_STORE_KEY`] store.
    pub fn persist(&self) {
        if let Err(e) = self.try_persist() {
            log::error!("ScanState::persist(): {e}");
        }
    }

    pub fn try_persist(&self) -> Result<(), PersistError> {
        let last_scanned_height = serde_json::to_vec(&self.last_scanned_height)
            .map_err(|e| PersistError::Serde(format!("scan_state last_scanned_height: {e}")))?;
        let last_block_hash = serde_json::to_vec(&self.last_block_hash)
            .map_err(|e| PersistError::Serde(format!("scan_state last_block_hash: {e}")))?;
        let birthday_height = serde_json::to_vec(&self.birthday_height)
            .map_err(|e| PersistError::Serde(format!("scan_state birthday_height: {e}")))?;
        let last_spend_height = serde_json::to_vec(&self.last_spend_height)
            .map_err(|e| PersistError::Serde(format!("scan_state last_spend_height: {e}")))?;

        self.backend.flush_batch(
            persist::ACCOUNT_STORE_KEY,
            &[
                (LAST_SCANNED_HEIGHT_ROW.to_string(), last_scanned_height),
                (LAST_BLOCK_HASH_ROW.to_string(), last_block_hash),
                (BIRTHDAY_HEIGHT_ROW.to_string(), birthday_height),
                (LAST_SPEND_HEIGHT_ROW.to_string(), last_spend_height),
            ],
            &[],
        )
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use bwk::persist::backend::json::JsonBackend;
    use std::fs;

    #[test]
    fn test_scan_state_new() {
        let state = ScanState::new(100);

        assert_eq!(state.birthday_height(), 100);
        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);
    }

    #[test]
    fn test_scan_state_with_backend_json() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-scan-state-with-backend-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let backend = Arc::new(JsonBackend::open(temp_dir.clone()).unwrap());
        let state = ScanState::with_backend(200, backend);

        assert_eq!(state.birthday_height(), 200);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scan_state_next_scan_start_initial() {
        let state = ScanState::new(100);

        // No scanned height yet, should return birthday
        assert_eq!(state.next_scan_start(), 100);
    }

    #[test]
    fn test_scan_state_next_scan_start_after_scan() {
        let mut state = ScanState::new(100);
        let block_hash = [0xAB; 32];

        state.advance_frontier(150, block_hash);

        // After scanning to 150, next scan starts at 151
        assert_eq!(state.next_scan_start(), 151);
    }

    #[test]
    fn test_scan_state_next_spend_start() {
        let mut state = ScanState::new(100);

        // Nothing swept yet, should return birthday.
        assert_eq!(state.next_spend_start(), 100);

        state.advance_spend_frontier(150);

        // After sweeping to 150, next spend sweep starts at 151.
        assert_eq!(state.next_spend_start(), 151);
    }

    #[test]
    fn test_clear_progress_preserves_birthday() {
        let mut state = ScanState::new(100);

        state.advance_frontier(150, [0xAB; 32]);
        state.advance_spend_frontier(140);
        state.clear_progress();

        assert_eq!(state.birthday_height(), 100);
        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);
        assert_eq!(state.last_spend_height(), None);
        assert_eq!(state.next_scan_start(), 100);
        assert_eq!(state.next_spend_start(), 100);
    }

    #[test]
    fn test_scan_state_advance_frontier() {
        let mut state = ScanState::new(100);
        let block_hash = [0xCD; 32];

        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);

        state.advance_frontier(500, block_hash);

        assert_eq!(state.last_scanned_height(), Some(500));
        assert_eq!(state.last_block_hash(), Some(block_hash));
    }

    #[test]
    fn test_scan_state_persistence() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-scan-state-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        let block_hash = [0x12; 32];

        // Scoped so `state` drops at the closing brace, releasing
        // the DirLock before the reopener tries to acquire it.
        {
            let backend = JsonBackend::open(temp_dir.clone()).unwrap();
            let account_path = backend.path_for(persist::ACCOUNT_STORE_KEY);
            let mut state = ScanState::with_backend(300, Arc::new(backend));
            state.advance_frontier(350, block_hash);
            state.persist();

            // Singleton fields are persisted under the `account` store.
            assert!(account_path.exists());
        }

        // Load from dir
        let backend = Arc::new(JsonBackend::open(temp_dir.clone()).unwrap());
        let loaded = ScanState::load_from_backend(0, backend).expect("load scan state");

        assert_eq!(loaded.birthday_height(), 300);
        assert_eq!(loaded.last_scanned_height(), Some(350));
        assert_eq!(loaded.last_block_hash(), Some(block_hash));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scan_state_persist_disabled() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-scan-state-no-persist-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        // Create state with persist disabled (NoopBackend via ScanState::new)
        let backend = JsonBackend::open(temp_dir.clone()).unwrap();
        let account_path = backend.path_for(persist::ACCOUNT_STORE_KEY);
        drop(backend);
        let mut state = ScanState::new(100);
        state.advance_frontier(150, [0xAA; 32]);
        state.persist();

        // Account file should NOT exist (persist is a noop)
        assert!(!account_path.exists());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scan_state_load_from_backend_fresh_dir_returns_default() {
        use std::env;

        // Fresh directory: no persisted state yet. JsonBackend::open
        // stamps DB_VERSION; load_from_backend returns a state at birthday 0.
        let temp_dir = env::temp_dir().join("bwk-sp-scan-state-fresh-test");
        let _ = fs::remove_dir_all(&temp_dir);

        let backend = Arc::new(JsonBackend::open(temp_dir.clone()).unwrap());
        let state = ScanState::load_from_backend(0, backend).expect("load scan state");
        assert_eq!(state.birthday_height(), 0);
        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scan_state_getters() {
        let mut state = ScanState::new(500);
        let block_hash = [0x55; 32];

        // Before update
        assert_eq!(state.birthday_height(), 500);
        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);

        // After advancing the frontier
        state.advance_frontier(600, block_hash);

        assert_eq!(state.birthday_height(), 500); // Unchanged
        assert_eq!(state.last_scanned_height(), Some(600));
        assert_eq!(state.last_block_hash(), Some(block_hash));
    }

    #[test]
    fn test_scan_state_default() {
        let state = ScanState::default();

        assert_eq!(state.birthday_height(), 0);
        assert_eq!(state.last_scanned_height(), None);
        assert_eq!(state.last_block_hash(), None);
        assert_eq!(state.last_spend_height(), None);
    }

    #[test]
    fn test_advance_spend_frontier_is_monotonic() {
        let mut state = ScanState::new(0);
        assert_eq!(state.last_spend_height(), None);

        state.advance_spend_frontier(100);
        assert_eq!(state.last_spend_height(), Some(100));

        // A lower height must not move the frontier backward.
        state.advance_spend_frontier(50);
        assert_eq!(state.last_spend_height(), Some(100));

        state.advance_spend_frontier(200);
        assert_eq!(state.last_spend_height(), Some(200));
    }

    #[test]
    fn test_spend_frontier_persistence() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-spend-frontier-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        {
            let backend = JsonBackend::open(temp_dir.clone()).unwrap();
            let mut state = ScanState::with_backend(0, Arc::new(backend));
            state.advance_spend_frontier(420);
            state.persist();
        }

        let backend = Arc::new(JsonBackend::open(temp_dir.clone()).unwrap());
        let loaded = ScanState::load_from_backend(0, backend).expect("load scan state");
        assert_eq!(loaded.last_spend_height(), Some(420));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
