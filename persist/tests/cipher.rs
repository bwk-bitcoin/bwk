//! Backends seal what they write and open what they read through the installed
//! cipher. Its own binary: the cipher is process wide.

use std::sync::Arc;

use bwk_persist::{
    backend::{headers::HeaderBackend, json::JsonBackend, PersistenceBackend},
    cipher::{self, Cipher},
    config_store::{ConfigStore, FileConfigStore},
    PersistError,
};

/// A toy cipher: a magic prefix and every byte xored, enough to tell sealed
/// bytes from clear ones.
#[derive(Debug)]
struct Xor;

const MAGIC: &[u8] = b"SEALED";

impl Cipher for Xor {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, PersistError> {
        Ok(MAGIC
            .iter()
            .copied()
            .chain(plain.iter().map(|b| b ^ 0x5a))
            .collect())
    }
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, PersistError> {
        sealed
            .strip_prefix(MAGIC)
            .map(|body| body.iter().map(|b| b ^ 0x5a).collect())
            .ok_or_else(|| PersistError::Cipher("not sealed".into()))
    }
    fn extension(&self) -> &str {
        "sealed"
    }
}

#[test]
fn backends_write_through_the_installed_cipher() {
    let dir = temp_dir::TempDir::new().expect("tempdir");

    // In clear, without a cipher.
    let clear = JsonBackend::open(dir.path().join("clear")).unwrap();
    clear.put_row("coins", "a", b"{\"v\":1}").unwrap();
    drop(clear);

    cipher::set_cipher(Some(Arc::new(Xor)));

    // Rows round trip, the file is sealed.
    let json = JsonBackend::open(dir.path().join("sealed")).unwrap();
    json.put_row("coins", "a", b"{\"v\":42}").unwrap();
    json.flush_batch("coins", &[("b".into(), b"{\"v\":7}".to_vec())], &[])
        .unwrap();
    assert_eq!(
        json.get_row("coins", "a").unwrap(),
        Some(b"{\"v\":42}".to_vec())
    );
    assert_eq!(json.get_rows("coins").unwrap().len(), 2);
    assert!(
        !dir.path().join("sealed").join("coins.json").exists(),
        "no .json file"
    );
    let file = std::fs::read(dir.path().join("sealed").join("coins.sealed")).unwrap();
    assert!(file.starts_with(MAGIC), "the store file is sealed");
    assert!(
        !String::from_utf8_lossy(&file).contains("42"),
        "nothing in clear"
    );

    // The version file is sealed too: it cannot be changed under the wallet.
    let sealed_dir = dir.path().join("sealed");
    assert!(!sealed_dir.join("version").exists(), "no version in clear");
    assert!(std::fs::read(sealed_dir.join("version.sealed"))
        .unwrap()
        .starts_with(MAGIC));
    drop(json);
    let json = JsonBackend::open(sealed_dir.clone()).expect("reopens through the cipher");
    assert_eq!(json.get_rows("coins").unwrap().len(), 2);

    // A store written in clear does not open once a cipher is installed.
    assert!(matches!(
        JsonBackend::open(dir.path().join("clear")),
        Err(PersistError::Cipher(_))
    ));

    // Headers: rows round trip through whole-file rewrites, the file is sealed.
    let path = dir.path().join("headers.bin");
    let headers = HeaderBackend::open(path.clone(), 4).unwrap();
    headers.put_row("headers", "10", &[1, 2, 3, 4]).unwrap();
    headers.put_row("headers", "11", &[5, 6, 7, 8]).unwrap();
    headers.put_row("headers", "10", &[9, 9, 9, 9]).unwrap();
    assert_eq!(
        headers.get_rows("headers").unwrap(),
        vec![
            ("10".into(), vec![9, 9, 9, 9]),
            ("11".into(), vec![5, 6, 7, 8])
        ]
    );
    let sealed_path = dir.path().join("headers.sealed");
    assert!(std::fs::read(&sealed_path).unwrap().starts_with(MAGIC));
    drop(headers);

    // A header cache the cipher does not open is a cache: wiped, not an error.
    std::fs::write(&sealed_path, b"BWKH\0\0\0\0garbage!").unwrap();
    let headers = HeaderBackend::open(path.clone(), 4).unwrap();
    assert_eq!(headers.get_rows("headers").unwrap(), vec![]);

    // The file config store.
    let store: FileConfigStore<Vec<u32>> = FileConfigStore::new(dir.path().join("config.json"));
    store.save(&vec![1, 2, 3]).unwrap();
    assert_eq!(store.load().unwrap(), Some(vec![1, 2, 3]));
    assert!(std::fs::read(dir.path().join("config.sealed"))
        .unwrap()
        .starts_with(MAGIC));

    #[cfg(feature = "sqlite")]
    {
        use bwk_persist::backend::sqlite::SqliteBackend;
        let sqlite = SqliteBackend::open(dir.path().join("account.sqlite")).unwrap();
        sqlite.put_row("coins", "a", b"{\"v\":42}").unwrap();
        assert_eq!(
            sqlite.get_row("coins", "a").unwrap(),
            Some(b"{\"v\":42}".to_vec())
        );
        assert_eq!(sqlite.get_rows("coins").unwrap().len(), 1);
    }

    cipher::set_cipher(None);
    assert!(cipher::cipher().is_none());
}
