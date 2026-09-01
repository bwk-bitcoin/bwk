//! `Client::new` handshaking against a self-signed TLS server.
//!
//! electrs speaks plain TCP only, so the regtest harness cannot serve `ssl://`
//! and the endpoint here is a bare TLS listener instead. `Client::new` hands
//! the policy to the handshake and exchanges nothing else, so a listener that
//! only accepts is enough to tell the two policies apart.

use std::{io::Read, net::TcpListener, sync::Arc, thread};

use bwk_electrum::{
    client::{Client, Error},
    raw_client::{self, CertificateCheck},
};
use native_tls::{Identity, TlsAcceptor};

/// Throwaway self-signed pair for 127.0.0.1, generated for this test alone and
/// valid until 2126. It authenticates nothing and guards nothing.
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUR3LAZZXYxCxURW7u9Fowgdx66jIwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MDgzMTE5MDYxN1oYDzIxMjYwODA3
MTkwNjE3WjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAR+xuPBxSz/zVfiPiCDxBoyN33ZMnvrk2tm3Umr5ayK9txq/+ET/aSl
7VBfXNzP7mlkQSJj6EPcB1Vfd+uqQUf/o2QwYjAdBgNVHQ4EFgQUEEtjJX9KQSmP
02xwPg6NvcX+OEgwHwYDVR0jBBgwFoAUEEtjJX9KQSmP02xwPg6NvcX+OEgwDwYD
VR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMCA0gAMEUC
IQCajkJZICXrBtXSPdcfCYOQgDFIrcMd1iF/gl4tTtFANAIgbHAgfyADaHCuvP+i
O6dxonB08S7cRpOLwEiYh3sr4I0=
-----END CERTIFICATE-----
";
const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdqaloRGOwbP+Wpw4
gkxnpYpqZ/G8doJCvmujGpA9VOehRANCAAR+xuPBxSz/zVfiPiCDxBoyN33ZMnvr
k2tm3Umr5ayK9txq/+ET/aSl7VBfXNzP7mlkQSJj6EPcB1Vfd+uqQUf/
-----END PRIVATE KEY-----
";

/// Serve TLS on a localhost port and return it. Each connection gets its own
/// thread, so a handshake the client completed is not torn down under it and
/// the close ending it is answered rather than left hanging.
fn spawn_tls_listener() -> u16 {
    let identity = Identity::from_pkcs8(CERT_PEM.as_bytes(), KEY_PEM.as_bytes()).unwrap();
    let acceptor = Arc::new(TlsAcceptor::new(identity).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let acceptor = acceptor.clone();
            thread::spawn(move || {
                // A client refusing the certificate aborts the handshake, which
                // is an outcome under test rather than a listener failure.
                let Ok(mut tls) = acceptor.accept(stream) else {
                    return;
                };
                let mut sink = Vec::new();
                let _ = tls.read_to_end(&mut sink);
                let _ = tls.shutdown();
            });
        }
    });
    port
}

#[test]
fn client_new_honours_the_certificate_policy() {
    let port = spawn_tls_listener();

    let err = Client::new("ssl://127.0.0.1", port, CertificateCheck::Validate).unwrap_err();
    assert!(
        matches!(err, Error::Transport(raw_client::Error::TlsHandshake(_))),
        "expected a refused handshake, got {err:?}"
    );

    Client::new(
        "ssl://127.0.0.1",
        port,
        CertificateCheck::DangerAcceptInvalid,
    )
    .unwrap();
}

/// The policy cannot move under a live connection: the handshake is already
/// behind us, so the setter refuses rather than let the caller believe the new
/// policy applied.
#[test]
fn the_policy_is_refused_on_a_connected_client() {
    let port = spawn_tls_listener();

    let mut client = raw_client::Client::new_ssl("127.0.0.1", port)
        .certificate_check(CertificateCheck::DangerAcceptInvalid)
        .expect("policy set before connecting");
    client.try_connect(None).expect("self-signed handshake");

    let err = client
        .clone()
        .certificate_check(CertificateCheck::Validate)
        .expect_err("a connected client refuses a policy change");
    assert!(
        matches!(err, raw_client::Error::AlreadyConnected),
        "expected a refusal, got {err:?}"
    );

    // The refusal left the policy alone: this client still reaches the
    // self-signed server, which validating would refuse.
    client.close().expect("close");
    client.try_connect(None).expect("still not validating");
}
