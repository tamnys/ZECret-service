//! Real loopback TLS and Unix-socket tests; quote contents remain synthetic.
use super::*;
use crate::node::CookieAuth;
use rustls::{
    ClientConfig, ServerConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    sync::Notify,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug)]
struct TestVerifier(Arc<CryptoProvider>);
impl ServerCertVerifier for TestVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        rustls::server::ParsedCertificate::try_from(cert)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("test requires TLS13".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
fn configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert =
        CertificateDer::from(include_bytes!("../../../../tests/fixtures/tls/end.der").to_vec());
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../../../../tests/fixtures/tls/end.key"))
            .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.send_tls13_tickets = 0;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestVerifier(provider)))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    client.resumption = rustls::client::Resumption::disabled();
    (Arc::new(server), Arc::new(client))
}
type TestClient = hyper::client::conn::http1::SendRequest<Full<Bytes>>;
async fn connect<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    nonce: &[u8; 32],
) -> (TestClient, [u8; 64], AbortOnDrop, AbortOnDrop) {
    let (server_config, client_config) = configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = AbortOnDrop(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let stream = TlsAcceptor::from(server_config)
            .accept(socket)
            .await
            .unwrap();
        let _ = serve(shared, stream).await;
    }));
    let socket = TcpStream::connect(address).await.unwrap();
    let tls = TlsConnector::from(client_config)
        .connect(ServerName::try_from("fixture.invalid").unwrap(), socket)
        .await
        .unwrap();
    let expected = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 64], ATTESTATION_EXPORTER_LABEL, Some(nonce))
        .unwrap();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    (sender, expected, driver, server)
}
async fn connect_attested<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    nonce: [u8; 32],
) -> (TestClient, AbortOnDrop, AbortOnDrop) {
    let (mut client, _, driver, server) = connect(shared, &nonce).await;
    assert_eq!(
        read(
            client
                .send_request(request("/attestation", nonce_body(nonce)))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    (client, driver, server)
}
#[derive(Clone)]
struct FakeQuote {
    calls: Arc<Mutex<Vec<[u8; 64]>>>,
    hold: Option<Arc<Notify>>,
    started: Arc<Notify>,
    fail: bool,
}
impl FakeQuote {
    fn new() -> Self {
        Self {
            calls: Arc::default(),
            hold: None,
            started: Arc::new(Notify::new()),
            fail: false,
        }
    }
}
impl QuoteSource for FakeQuote {
    async fn quote(&self, report_data: [u8; 64]) -> Result<QuoteEvidence, SafeError> {
        self.calls.lock().unwrap().push(report_data);
        self.started.notify_one();
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        if self.fail {
            return Err(unavailable());
        }
        Ok(QuoteEvidence::Phala(GetQuoteResponse {
            quote: "SYNTHETIC_NOT_A_HARDWARE_QUOTE".into(),
            event_log: "[]".into(),
            report_data: hex::encode(report_data),
            vm_config: "{}".into(),
        }))
    }
}
// Test values exercise configured boundaries; they are not release defaults.
fn limits(connections: usize, quotes: usize, spacing: Duration) -> BootstrapLimits {
    BootstrapLimits::new(
        NonZeroUsize::new(connections).unwrap(),
        NonZeroUsize::new(quotes).unwrap(),
        spacing,
    )
    .unwrap()
}
fn request(path: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::post(path)
        .header(header::HOST, "fixture.invalid")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
fn nonce_body(nonce: [u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&zrpc_protocol::PublicAttestationRequest { nonce }).unwrap()
}
async fn read(response: Response<Incoming>) -> (StatusCode, Bytes) {
    let status = response.status();
    (
        status,
        response.into_body().collect().await.unwrap().to_bytes(),
    )
}

fn assert_private_store_excludes(directory: &std::path::Path, forbidden: &[&[u8]]) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for value in forbidden {
            assert!(!value.is_empty());
            assert!(!bytes.windows(value.len()).any(|window| window == *value));
        }
    }
}

#[tokio::test]
async fn quote_uses_own_live_session_exporter_and_connection_nonce_only_once() {
    let source = FakeQuote::new();
    let calls = source.calls.clone();
    let shared = Arc::new(Shared::new(source, limits(1, 1, Duration::from_nanos(1))));
    let nonce = [7; 32];
    let (mut client, expected, _driver, _server) = connect(shared, &nonce).await;
    let response = client
        .send_request(request("/attestation", nonce_body(nonce)))
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let (status, body) = read(response).await;
    assert_eq!(status, StatusCode::OK);
    let evidence = zrpc_protocol::parse_attestation_response(&body).unwrap();
    assert_eq!(evidence.nonce, nonce);
    assert_eq!(hex::decode(evidence.report_data).unwrap(), expected);
    assert_eq!(*calls.lock().unwrap(), vec![expected]);
    assert_eq!(
        read(
            client
                .send_request(request("/attestation", nonce_body([8; 32])))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        read(
            client
                .send_request(request("/rpc", br#"{"method":"getblockcount"}"#.to_vec()))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http2_quote_uses_same_tls_exporter_and_does_not_enable_http1_rpc() {
    let source = FakeQuote::new();
    let calls = source.calls.clone();
    let mut shared = Arc::new(Shared::new(source, limits(1, 1, Duration::from_nanos(1))));
    Arc::get_mut(&mut shared).unwrap().wallet_backend =
        Some(ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).unwrap());
    let (mut server_config, mut client_config) = configs();
    Arc::get_mut(&mut server_config).unwrap().alpn_protocols = vec![b"h2".to_vec()];
    Arc::get_mut(&mut client_config).unwrap().alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = AbortOnDrop(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(server_config)
            .accept(socket)
            .await
            .unwrap();
        let _ = serve(shared, tls).await;
    }));
    let socket = TcpStream::connect(address).await.unwrap();
    let tls = TlsConnector::from(client_config)
        .connect(ServerName::try_from("fixture.invalid").unwrap(), socket)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let nonce = [29; 32];
    let expected = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 64], ATTESTATION_EXPORTER_LABEL, Some(&nonce))
        .unwrap();
    let (mut client, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(tls),
    )
    .await
    .unwrap();
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let send = |path: &str, body: Vec<u8>| {
        Request::post(format!("https://fixture.invalid{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    };
    let wallet_path = ReadMethod::GetLatestBlock.path();
    let wallet_request = || {
        Request::post(format!("https://fixture.invalid{wallet_path}"))
            .header(header::CONTENT_TYPE, "application/grpc")
            .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
            .unwrap()
    };
    let snapshot_request = || {
        Request::post(format!(
            "https://fixture.invalid{}",
            ReadMethod::GetMempoolSnapshot.path()
        ))
        .header(header::CONTENT_TYPE, "application/grpc")
        .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
        .unwrap()
    };
    assert_eq!(
        read(client.send_request(wallet_request()).await.unwrap())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read(client.send_request(snapshot_request()).await.unwrap())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, evidence) = read(
        client
            .send_request(send("/attestation", nonce_body(nonce)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let evidence = zrpc_protocol::parse_attestation_response(&evidence).unwrap();
    assert_eq!(hex::decode(evidence.report_data).unwrap(), expected);
    assert_eq!(*calls.lock().unwrap(), vec![expected]);
    let (status, _) = read(
        client
            .send_request(send(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
                vec![],
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = read(
        client
            .send_request(send("/attestation", nonce_body([30; 32])))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = read(client.send_request(wallet_request()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = read(client.send_request(wallet_request()).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = read(client.send_request(snapshot_request()).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = read(
        client
            .send_request(send("/rpc", b"private".to_vec()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    drop(server);
}

#[test]
fn wallet_backend_cannot_be_attached_to_a_free_listener() {
    let service = AttestationService::new(
        Path::new("/run/zrpc-quote/quote.sock"),
        limits(1, 1, Duration::from_nanos(1)),
    )
    .unwrap();
    let backend = ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).unwrap();
    assert!(service.with_wallet_backend(backend).is_err());
}

#[tokio::test]
async fn gcp_response_has_separate_wire_format_and_same_live_exporter() {
    struct FakeGcp(Arc<Mutex<Vec<[u8; 64]>>>);
    impl QuoteSource for FakeGcp {
        async fn quote(&self, report_data: [u8; 64]) -> Result<QuoteEvidence, SafeError> {
            self.0.lock().unwrap().push(report_data);
            Ok(QuoteEvidence::Gcp(GcpQuoteEvidence {
                quote: hex::encode(b"SYNTHETIC_NOT_A_HARDWARE_QUOTE"),
                ccel: hex::encode(b"SYNTHETIC_NOT_A_CCEL"),
            }))
        }
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::new(Shared::new(
        FakeGcp(calls.clone()),
        limits(1, 1, Duration::from_nanos(1)),
    ));
    let nonce = [17; 32];
    let (mut client, expected, _driver, _server) = connect(shared, &nonce).await;
    let (status, body) = read(
        client
            .send_request(request("/attestation", nonce_body(nonce)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let evidence = zrpc_protocol::parse_gcp_attestation_response(&body).unwrap();
    assert_eq!(evidence.nonce, nonce);
    assert_eq!(evidence.platform, zrpc_protocol::Backend::GcpTdx);
    assert_eq!(*calls.lock().unwrap(), vec![expected]);
    assert!(zrpc_protocol::parse_attestation_response(&body).is_err());
    assert_eq!(
        read(
            client
                .send_request(request("/attestation", nonce_body(nonce)))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn optional_rpc_route_requires_attestation_then_enforces_method_allowlist() {
    let source = FakeQuote::new();
    let mut shared = Shared::new(source, limits(1, 1, Duration::from_nanos(1)));
    shared.node = Some(
        LocalNode::new(
            "127.0.0.1:1".parse().unwrap(),
            CookieAuth::from_cookie(b"fixture:fixture").unwrap(),
        )
        .unwrap(),
    );
    let shared = Arc::new(shared);
    let nonce = [13; 32];
    let (mut client, _, _driver, _server) = connect(shared, &nonce).await;
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
    let (status, _) = read(
        client
            .send_request(request("/rpc", body.to_vec()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = read(
        client
            .send_request(request("/attestation", nonce_body(nonce)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let unexpected_ticket = Request::post("/rpc")
        .header(header::HOST, "fixture.invalid")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "PrivateToken token=\"unexpected\"")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    assert_eq!(
        read(client.send_request(unexpected_ticket).await.unwrap())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let forbidden =
        br#"{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["PRIVATE_MARKER"]}"#;
    let (status, reply) = read(
        client
            .send_request(request("/rpc", forbidden.to_vec()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !reply
            .windows(b"PRIVATE_MARKER".len())
            .any(|window| window == b"PRIVATE_MARKER")
    );
    let (status, _) = read(
        client
            .send_request(request("/rpc", body.to_vec()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
#[ignore = "requires OpenSSL and the separately locked payment helper in the managed container"]
async fn paid_rpc_admits_once_and_preserves_replay_after_node_outcomes() {
    const PRIVATE_QUERY_MARKER: &[u8] = b"SYNTHETIC_PRIVATE_REQUEST_MARKER";
    let helper = std::path::PathBuf::from(
        std::env::var_os("ZRPC_PAYMENT_CRYPTO_HELPER")
            .expect("set ZRPC_PAYMENT_CRYPTO_HELPER to the helper executable"),
    );
    let root = std::env::temp_dir().join(format!(
        "zrpc-paid-rpc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    zrpc_payments::PrivateDirectory::create(&root).unwrap();
    let private_key = root.join("private.der");
    let public_key = root.join("public.der");
    assert!(
        std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
                "-out"
            ])
            .arg(&private_key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("openssl")
            .args(["pkey", "-inform", "DER", "-in"])
            .arg(&private_key)
            .args(["-pubout", "-outform", "DER", "-out"])
            .arg(&public_key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let issuer = zrpc_payments::IssuerPublic::from_public_der(
        &helper,
        &std::fs::read(&public_key).unwrap(),
        "issuer.example",
    )
    .unwrap();
    let client_dir = zrpc_payments::PrivateDirectory::create(&root.join("client")).unwrap();
    let issuer_dir = zrpc_payments::PrivateDirectory::create(&root.join("issuer")).unwrap();
    let redeemer_dir = zrpc_payments::PrivateDirectory::create(&root.join("redeemer")).unwrap();
    zrpc_payments::PrivateDirectory::create(&root.join("exchange")).unwrap();
    let request_file = root.join("exchange/request.bin");
    let response_file = root.join("exchange/response.bin");
    let mut ticket_store = zrpc_payments::ClientStore::create(&client_dir).unwrap();
    let purchase =
        zrpc_payments::prepare_purchase(&mut ticket_store, &issuer, &helper, 3, &request_file)
            .unwrap();
    let mut operator = zrpc_payments::IssuerStore::create(&issuer_dir).unwrap();
    zrpc_payments::mock_settle_purchase(
        &mut operator,
        &issuer,
        &helper,
        &zrpc_payments::load_private_key_file(&private_key).unwrap(),
        3,
        &request_file,
        &response_file,
    )
    .unwrap();
    zrpc_payments::collect_purchase(
        &mut ticket_store,
        &issuer,
        &helper,
        purchase,
        &response_file,
    )
    .unwrap();
    let ticket = ticket_store.preview_available().unwrap().unwrap();
    let authorization = issuer.authorization_for(ticket.token.expose()).unwrap();
    ticket_store.claim_available(&ticket).unwrap();
    let other_ticket = ticket_store.preview_available().unwrap().unwrap();
    let other_authorization = issuer
        .authorization_for(other_ticket.token.expose())
        .unwrap();
    ticket_store.claim_available(&other_ticket).unwrap();
    let success_ticket = ticket_store.preview_available().unwrap().unwrap();
    let success_authorization = issuer
        .authorization_for(success_ticket.token.expose())
        .unwrap();
    ticket_store.claim_available(&success_ticket).unwrap();
    let spent = zrpc_payments::RedeemerStore::create(&redeemer_dir).unwrap();
    let mut shared = Shared::new(FakeQuote::new(), limits(1, 1, Duration::from_nanos(1)));
    shared.node = Some(
        LocalNode::new(
            "127.0.0.1:1".parse().unwrap(),
            CookieAuth::from_cookie(b"fixture:fixture").unwrap(),
        )
        .unwrap(),
    );
    shared.payment = Some(Arc::new(Redeemer::new(issuer, helper.clone(), spent)));
    let shared = Arc::new(shared);
    let nonce = [31; 32];
    let (mut client, driver, server) = connect_attested(shared.clone(), nonce).await;
    let body = br#"{"jsonrpc":"2.0","id":"SYNTHETIC_PRIVATE_REQUEST_MARKER","method":"getblockcount","params":[]}"#;
    assert_eq!(
        read(
            client
                .send_request(request("/rpc", body.to_vec()))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    drop((client, driver, server));
    let (mut client, driver, server) = connect_attested(shared.clone(), nonce).await;
    let invalid = Request::post("/rpc")
        .header(header::HOST, "fixture.invalid")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "PrivateToken token=\"invalid\"")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    assert_eq!(
        read(client.send_request(invalid).await.unwrap()).await.0,
        StatusCode::FORBIDDEN
    );
    drop((client, driver, server));
    let (mut client, driver, server) = connect_attested(shared.clone(), nonce).await;
    let paid_request = |authorization: &[u8]| {
        Request::post("/rpc")
            .header(header::HOST, "fixture.invalid")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                header::HeaderValue::from_bytes(authorization).unwrap(),
            )
            .body(Full::new(Bytes::from_static(body)))
            .unwrap()
    };
    let (status, node_failure) = read(
        client
            .send_request(paid_request(authorization.as_ref()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !node_failure
            .windows(PRIVATE_QUERY_MARKER.len())
            .any(|window| window == PRIVATE_QUERY_MARKER)
    );
    // A second, independently valid ticket cannot be linked to the first on
    // this attested connection. It remains redeemable on a fresh connection.
    assert_eq!(
        read(
            client
                .send_request(paid_request(other_authorization.as_ref()))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    drop((client, driver, server));
    let (mut client, driver, server) = connect_attested(shared.clone(), nonce).await;
    assert_eq!(
        read(
            client
                .send_request(paid_request(other_authorization.as_ref()))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop((client, driver, server));
    drop(shared);
    let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_address = match node_listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!(),
    };
    let node_methods = Arc::new(Mutex::new(Vec::new()));
    let observed_methods = node_methods.clone();
    let node_task = tokio::spawn(async move {
        let (socket, _) = node_listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let observed_methods = observed_methods.clone();
            async move {
                assert_eq!(request.method(), hyper::Method::POST);
                assert_eq!(request.uri(), "/");
                assert_eq!(
                    request
                        .headers()
                        .get(header::AUTHORIZATION)
                        .unwrap()
                        .as_bytes(),
                    b"Basic Zml4dHVyZTpmaXh0dXJl"
                );
                let body = request.into_body().collect().await.unwrap().to_bytes();
                assert!(
                    !body
                        .windows(PRIVATE_QUERY_MARKER.len())
                        .any(|window| window == PRIVATE_QUERY_MARKER)
                );
                let call: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let method = call["method"].as_str().unwrap();
                observed_methods.lock().unwrap().push(method.to_owned());
                let result = match method {
                    "getblockchaininfo" => serde_json::json!({"chain":"test"}),
                    "getblockcount" => serde_json::json!(42),
                    _ => panic!("unexpected forwarded method"),
                };
                let response = serde_json::json!({
                    "jsonrpc":"2.0", "id":call["id"], "result":result
                });
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(
                            serde_json::to_vec(&response).unwrap(),
                        )))
                        .unwrap(),
                )
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), service)
            .await
            .unwrap();
    });
    let restarted_issuer = zrpc_payments::IssuerPublic::from_public_der(
        &helper,
        &std::fs::read(&public_key).unwrap(),
        "issuer.example",
    )
    .unwrap();
    let reopened_spent = zrpc_payments::RedeemerStore::open(&redeemer_dir).unwrap();
    let mut restarted = Shared::new(FakeQuote::new(), limits(1, 1, Duration::from_nanos(1)));
    restarted.node = Some(
        LocalNode::new(
            node_address,
            CookieAuth::from_cookie(b"fixture:fixture").unwrap(),
        )
        .unwrap(),
    );
    restarted.payment = Some(Arc::new(Redeemer::new(
        restarted_issuer,
        helper,
        reopened_spent,
    )));
    let restarted = Arc::new(restarted);
    let (mut client, driver, server) = connect_attested(restarted.clone(), nonce).await;
    assert_eq!(
        read(
            client
                .send_request(paid_request(authorization.as_ref()))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    drop((client, driver, server));
    let (mut client, driver, server) = connect_attested(restarted, nonce).await;
    let (status, body) = read(
        client
            .send_request(paid_request(success_authorization.as_ref()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["id"], "SYNTHETIC_PRIVATE_REQUEST_MARKER");
    assert_eq!(response["result"], 42);
    assert_eq!(ticket_store.balance().unwrap().uncertain, 3);
    drop((client, driver, server));
    node_task.await.unwrap();
    assert_eq!(
        node_methods.lock().unwrap().as_slice(),
        ["getblockchaininfo", "getblockcount"]
    );
    drop(ticket_store);
    drop(operator);
    assert_private_store_excludes(
        &root.join("issuer"),
        &[
            ticket.token.expose(),
            other_ticket.token.expose(),
            success_ticket.token.expose(),
        ],
    );
    assert_private_store_excludes(
        &root.join("redeemer"),
        &[
            PRIVATE_QUERY_MARKER,
            &purchase,
            ticket.token.expose(),
            other_ticket.token.expose(),
            success_ticket.token.expose(),
            authorization.as_ref(),
            other_authorization.as_ref(),
            success_authorization.as_ref(),
        ],
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn caller_keys_report_data_extra_fields_and_oversize_never_reach_quote_source() {
    let source = FakeQuote::new();
    let calls = source.calls.clone();
    let shared = Arc::new(Shared::new(source, limits(1, 1, Duration::from_nanos(1))));
    let nonce = [0; 32];
    let (mut client, _, _driver, _server) = connect(shared, &nonce).await;
    let nonce_json = serde_json::to_string(&nonce).unwrap();
    for body in [
        format!(r#"{{"nonce":{nonce_json},"report_data":"CALLER_SECRET"}}"#).into_bytes(),
        format!(r#"{{"nonce":{nonce_json},"nonce":{nonce_json}}}"#).into_bytes(),
        format!("[{nonce_json}]").into_bytes(),
        vec![b' '; MAX_ATTESTATION_REQUEST_BYTES + 1],
    ] {
        let response = client
            .send_request(request("/attestation", body))
            .await
            .unwrap();
        let (status, body) = read(response).await;
        assert!(matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
        ));
        assert!(!String::from_utf8_lossy(&body).contains("CALLER_SECRET"));
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn global_quote_parallelism_and_rate_policy_cannot_be_bypassed_with_new_sessions() {
    let mut source = FakeQuote::new();
    source.hold = Some(Arc::new(Notify::new()));
    let started = source.started.clone();
    let hold = source.hold.clone().unwrap();
    let calls = source.calls.clone();
    let shared = Arc::new(Shared::new(
        source,
        limits(3, 1, Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS)),
    ));
    let (mut first, _, _d1, _s1) = connect(shared.clone(), &[1; 32]).await;
    let query = tokio::spawn(async move {
        read(
            first
                .send_request(request("/attestation", nonce_body([1; 32])))
                .await
                .unwrap(),
        )
        .await
    });
    started.notified().await;
    let (mut second, _, _d2, _s2) = connect(shared.clone(), &[2; 32]).await;
    assert_eq!(
        read(
            second
                .send_request(request("/attestation", nonce_body([2; 32])))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    hold.notify_one();
    assert_eq!(query.await.unwrap().0, StatusCode::OK);
    let (mut third, _, _d3, _s3) = connect(shared, &[3; 32]).await;
    assert_eq!(
        read(
            third
                .send_request(request("/attestation", nonce_body([3; 32])))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn failed_quote_has_fixed_error_and_connection_cannot_retry_it() {
    let mut source = FakeQuote::new();
    source.fail = true;
    let calls = source.calls.clone();
    let shared = Arc::new(Shared::new(source, limits(1, 1, Duration::from_nanos(1))));
    let (mut client, _, _driver, _server) = connect(shared, &[0; 32]).await;
    let (status, body) = read(
        client
            .send_request(request("/attestation", nonce_body([0; 32])))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(&body[..], br#"{"error":"public_attestation_unavailable"}"#);
    assert_eq!(
        read(
            client
                .send_request(request("/attestation", nonce_body([0; 32])))
                .await
                .unwrap()
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

struct SocketPath(PathBuf);
impl SocketPath {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.codex-tmp");
        std::fs::create_dir_all(&path).unwrap();
        Self(std::fs::canonicalize(path).unwrap().join(format!(
            "quote-fixture-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn bounded_guest_adapter_uses_only_explicit_unix_get_quote_and_sdk_shape() {
    for mode in 0..4 {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                move |request: Request<Incoming>| async move {
                    assert_eq!(request.method(), hyper::Method::POST);
                    assert_eq!(request.uri(), "/GetQuote");
                    assert_eq!(request.headers()[header::HOST], "dstack");
                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(body.as_object().unwrap().len(), 1);
                    assert_eq!(body["report_data"], hex::encode([42u8; 64]));
                    let body=match mode {
                    0=>serde_json::to_vec(&GetQuoteResponse { quote:"SYNTHETIC".into(),event_log:"[]".into(),report_data:hex::encode([42u8;64]),vm_config:"{}".into() }).unwrap(),
                    1=>br#"{"quote":"SYNTHETIC","event_log":"[]","report_data":"00","vm_config":"{}"}"#.to_vec(),
                    2=>vec![b' ';MAX_ATTESTATION_RESPONSE_BYTES+1],
                    _=>br#"{"quote":"a","quote":"b","event_log":"[]"}"#.to_vec(),
                };
                    Ok::<_, Infallible>(reply(StatusCode::OK, Bytes::from(body)))
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let source = DstackQuoteSource {
            socket: path.0.clone(),
        };
        let result = source.quote([42; 64]).await;
        assert_eq!(result.is_ok(), mode == 0);
        server.abort();
        let _ = server.await;
    }
}

#[test]
fn endpoint_and_quote_policy_have_no_environment_or_implicit_defaults() {
    assert!(
        AttestationService::new(
            Path::new("https://outside.example"),
            limits(1, 1, Duration::from_secs(1))
        )
        .is_err()
    );
    assert!(
        AttestationService::new(
            Path::new("/run/../etc/sock"),
            limits(1, 1, Duration::from_secs(1))
        )
        .is_err()
    );
    assert!(
        BootstrapLimits::new(
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            Duration::ZERO
        )
        .is_err()
    );
    assert!(
        BootstrapLimits::new(
            NonZeroUsize::new(usize::MAX).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            Duration::from_secs(1)
        )
        .is_err()
    );
}

#[tokio::test]
async fn lifetime_expiry_cancels_pending_quote_and_releases_global_admission() {
    let mut source = FakeQuote::new();
    source.hold = Some(Arc::new(Notify::new()));
    let started = source.started.clone();
    let shared = Arc::new(Shared::new(source, limits(1, 1, Duration::from_nanos(1))));
    let (mut client, _, _driver, mut server) = connect(shared.clone(), &[0; 32]).await;
    let query = tokio::spawn(async move {
        client
            .send_request(request("/attestation", nonce_body([0; 32])))
            .await
    });
    started.notified().await;
    assert_eq!(shared.connections.available_permits(), 0);
    assert_eq!(shared.quotes.available_permits(), 0);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS)).await;
    (&mut server.0).await.unwrap();
    assert!(query.await.unwrap().is_err());
    assert_eq!(shared.connections.available_permits(), 1);
    assert_eq!(shared.quotes.available_permits(), 1);
}

#[tokio::test]
async fn native_public_client_and_server_exchange_only_unverified_evidence() {
    let path = SocketPath::new();
    let guest = UnixListener::bind(&path.0).unwrap();
    let guest_task = AbortOnDrop(tokio::spawn(async move {
        let (stream, _) = guest.accept().await.unwrap();
        let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.uri(), "/GetQuote");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let report_data = body["report_data"].as_str().unwrap().to_owned();
            assert_eq!(hex::decode(&report_data).unwrap().len(), 64);
            let body = serde_json::to_vec(&GetQuoteResponse {
                quote: "SYNTHETIC_NOT_A_QUOTE".into(),
                event_log: "[]".into(),
                report_data,
                vm_config: "{}".into(),
            })
            .unwrap();
            Ok::<_, Infallible>(reply(StatusCode::OK, Bytes::from(body)))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }));
    let service = AttestationService::new(&path.0, limits(1, 1, Duration::from_nanos(1))).unwrap();
    let (server_config, _) = configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!(),
    };
    let server = AbortOnDrop(tokio::spawn(async move {
        // A local SOCKS fixture, not a running Tor process.
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        socket.write_all(&[5, 2]).await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), 1);
        let user = socket.read_u8().await.unwrap();
        let mut username = vec![0; user as usize];
        socket.read_exact(&mut username).await.unwrap();
        assert_eq!(username, b"<torS0X>0");
        let password = socket.read_u8().await.unwrap();
        let mut isolation = vec![0; password as usize];
        socket.read_exact(&mut isolation).await.unwrap();
        socket.write_all(&[1, 0]).await.unwrap();
        let mut command = [0; 4];
        socket.read_exact(&mut command).await.unwrap();
        assert_eq!(command, [5, 1, 0, 3]);
        let length = socket.read_u8().await.unwrap();
        let mut hostname = vec![0; length as usize];
        socket.read_exact(&mut hostname).await.unwrap();
        assert_eq!(hostname, b"fixture.invalid");
        assert_eq!(socket.read_u16().await.unwrap(), 443);
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let tls = TlsAcceptor::from(server_config)
            .accept(socket)
            .await
            .unwrap();
        let _ = service.serve_connection(tls).await;
    }));
    let endpoint = zrpc_transport::RemoteEndpoint::new("fixture.invalid", 443).unwrap();
    let bootstrap = zrpc_transport::TorConfig::new(address)
        .unwrap()
        .connect_bootstrap(
            &endpoint,
            zrpc_transport::IsolationLabel::new("synthetic-integration-session").unwrap(),
        )
        .await
        .unwrap()
        .start_tls()
        .await
        .unwrap();
    let challenge = bootstrap.prepare_challenge().unwrap();
    let nonce = *challenge.nonce().unwrap();
    let evidence = challenge.request_attestation().await.unwrap();
    assert_eq!(evidence.raw_unverified().nonce, nonce);
    assert_eq!(evidence.raw_unverified().quote, "SYNTHETIC_NOT_A_QUOTE");
    assert!(!evidence.private_rpc_allowed());
    drop(evidence);
    drop(server);
    drop(guest_task);
}
