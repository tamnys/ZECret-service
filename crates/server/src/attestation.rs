//! Session-owned attestation and optional typed node RPC on the same TLS stream.
use crate::gcp_quote::{GcpQuoteEvidence, request_gcp_quote};
use crate::node::LocalNode;
use bytes::Bytes;
use dstack_sdk_types::dstack::GetQuoteResponse;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, Version, body::Incoming, header};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    future::Future,
    io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::server::TlsStream;
use tonic::{body::Body, codegen::Service};
use zeroize::Zeroizing;
use zrpc_payments::{Admission, Redeemer};
#[cfg(test)]
use zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS;
use zrpc_protocol::{
    ATTESTATION_EXPORTER_LABEL, ErrorCode, MAX_ATTESTATION_REQUEST_BYTES,
    MAX_ATTESTATION_RESPONSE_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    PublicAttestationResponse, SafeError, parse_attestation_request, parse_request,
};
use zrpc_wallet_read::{
    ReadMethod, backend::ZebraReadOnly, snapshot_wire::snapshot_read_server::SnapshotReadServer,
    wire::compact_tx_streamer_server::CompactTxStreamerServer,
};

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "Public attestation is unavailable.",
    )
}

/// Values must come from an independently reviewed release configuration.
/// No deployment defaults or experimentally guessed production quotas exist.
pub struct BootstrapLimits {
    connections: NonZeroUsize,
    quotes: NonZeroUsize,
    quote_spacing: Duration,
}
impl BootstrapLimits {
    pub fn new(
        connections: NonZeroUsize,
        quotes: NonZeroUsize,
        quote_spacing: Duration,
    ) -> Result<Self, SafeError> {
        if quote_spacing.is_zero()
            || connections.get() > Semaphore::MAX_PERMITS
            || quotes.get() > Semaphore::MAX_PERMITS
        {
            return Err(unavailable());
        }
        Ok(Self {
            connections,
            quotes,
            quote_spacing,
        })
    }
}

/// Local, explicit guest socket only. No environment endpoint, URL, TCP fallback,
/// generic forwarding, secret-key derivation or signing operation is exposed.
struct DstackQuoteSource {
    socket: PathBuf,
}
trait QuoteSource: Send + Sync + 'static {
    fn quote(
        &self,
        report_data: [u8; 64],
    ) -> impl Future<Output = Result<QuoteEvidence, SafeError>> + Send;
}
enum QuoteEvidence {
    Phala(GetQuoteResponse),
    Gcp(GcpQuoteEvidence),
}
impl QuoteSource for DstackQuoteSource {
    async fn quote(&self, report_data: [u8; 64]) -> Result<QuoteEvidence, SafeError> {
        self.request(report_data).await.map(QuoteEvidence::Phala)
    }
}
impl DstackQuoteSource {
    async fn request(&self, report_data: [u8; 64]) -> Result<GetQuoteResponse, SafeError> {
        let socket = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| unavailable())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| unavailable())?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        // Exact SDK v0.1.2 DstackClient::get_quote wire operation. The maintained
        // response type is reused; HTTP body collection is independently bounded.
        let body = serde_json::to_vec(&serde_json::json!({"report_data":hex::encode(report_data)}))
            .map_err(|_| unavailable())?;
        let request = Request::post("/GetQuote")
            .header(header::HOST, "dstack")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| unavailable())?;
        if response.status() != StatusCode::OK
            || response.headers().contains_key(header::CONTENT_ENCODING)
        {
            return Err(unavailable());
        }
        let body = Limited::new(response.into_body(), MAX_ATTESTATION_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| unavailable())?
            .to_bytes();
        // Parse directly: don't normalize through Value and erase duplicate fields.
        if body.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
            return Err(unavailable());
        }
        let response: GetQuoteResponse =
            serde_json::from_slice(&body).map_err(|_| unavailable())?;
        // This unauthenticated echo only detects a malformed guest reply. The
        // native client must authenticate the quote and compare actual REPORTDATA.
        if hex::decode(&response.report_data).ok().as_deref() != Some(report_data.as_slice()) {
            return Err(unavailable());
        }
        Ok(response)
    }
}

/// The quote-only Unix bridge reuses this exact bounded dstack wire operation;
/// it must not gain a second implementation of guest-agent requests.
pub(crate) async fn request_dstack_quote(
    socket: &Path,
    report_data: [u8; 64],
) -> Result<GetQuoteResponse, SafeError> {
    DstackQuoteSource {
        socket: socket.to_owned(),
    }
    .request(report_data)
    .await
}

enum GuestQuoteSource {
    Phala(DstackQuoteSource),
    Gcp(PathBuf),
}
impl QuoteSource for GuestQuoteSource {
    async fn quote(&self, report_data: [u8; 64]) -> Result<QuoteEvidence, SafeError> {
        match self {
            Self::Phala(source) => source.quote(report_data).await,
            Self::Gcp(path) => request_gcp_quote(path, report_data)
                .await
                .map(QuoteEvidence::Gcp),
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Shared<Q> {
    source: Q,
    node: Option<LocalNode>,
    wallet_backend: Option<ZebraReadOnly>,
    payment: Option<Arc<Redeemer>>,
    connections: Arc<Semaphore>,
    quotes: Semaphore,
    quote_spacing: Duration,
    last_quote: Mutex<Option<Instant>>,
}
impl<Q: QuoteSource> Shared<Q> {
    fn new(source: Q, limits: BootstrapLimits) -> Self {
        Self {
            source,
            node: None,
            wallet_backend: None,
            payment: None,
            connections: Arc::new(Semaphore::new(limits.connections.get())),
            quotes: Semaphore::new(limits.quotes.get()),
            quote_spacing: limits.quote_spacing,
            last_quote: Mutex::new(None),
        }
    }
}

/// Public attestation service used by the owned bootstrap listener. The runnable
/// path generates its TLS identity locally and admits sockets before handshake.
/// Node RPC is enabled only when an explicit internal node adapter is supplied.
/// It does not itself assert that a client approved this workload.
#[derive(Clone)]
pub struct AttestationService {
    shared: Arc<Shared<GuestQuoteSource>>,
}
impl AttestationService {
    pub fn new(socket: &Path, limits: BootstrapLimits) -> Result<Self, SafeError> {
        if !socket.is_absolute()
            || socket
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(unavailable());
        }
        Ok(Self {
            shared: Arc::new(Shared::new(
                GuestQuoteSource::Phala(DstackQuoteSource {
                    socket: socket.to_owned(),
                }),
                limits,
            )),
        })
    }
    pub fn new_gcp(socket: &Path, limits: BootstrapLimits) -> Result<Self, SafeError> {
        if !socket.is_absolute()
            || socket
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(unavailable());
        }
        Ok(Self {
            shared: Arc::new(Shared::new(
                GuestQuoteSource::Gcp(socket.to_owned()),
                limits,
            )),
        })
    }
    /// Bind the allowlisted loopback node adapter to the same TLS listener.
    /// Deployment must separately prove the measured image and node isolation.
    pub fn with_node(mut self, node: LocalNode) -> Result<Self, SafeError> {
        let shared = Arc::get_mut(&mut self.shared).ok_or_else(unavailable)?;
        shared.node = Some(node);
        Ok(self)
    }

    /// Require a locally verified, unspent ticket before every allowlisted
    /// node query. The caller must open the spent store and validate the shared
    /// issuer configuration before constructing this service.
    pub fn with_paid_node(
        mut self,
        node: LocalNode,
        payment: Arc<Redeemer>,
    ) -> Result<Self, SafeError> {
        let shared = Arc::get_mut(&mut self.shared).ok_or_else(unavailable)?;
        shared.node = Some(node);
        shared.payment = Some(payment);
        Ok(self)
    }

    /// Add Zebra's typed read-only gRPC adapter. The caller must bind Zebra's
    /// listener to loopback and keep this wrapper's wallet route disabled until
    /// the native verified transport and exact release are ready.
    pub fn with_wallet_backend(mut self, backend: ZebraReadOnly) -> Result<Self, SafeError> {
        let shared = Arc::get_mut(&mut self.shared).ok_or_else(unavailable)?;
        if shared.payment.is_none() || shared.wallet_backend.is_some() || shared.node.is_none() {
            return Err(unavailable());
        }
        let snapshot_source = shared.node.as_ref().ok_or_else(unavailable)?.clone();
        shared.wallet_backend = Some(backend.with_snapshot_source(Arc::new(snapshot_source)));
        Ok(self)
    }
    // Only tests may inject a pre-negotiated stream. Production listener owns
    // key generation and admission before negotiating any TLS connection.
    #[cfg(test)]
    pub async fn serve_connection(&self, stream: TlsStream<TcpStream>) -> Result<(), SafeError> {
        serve(self.shared.clone(), stream).await
    }

    pub(crate) fn admit_connection(&self) -> Result<OwnedSemaphorePermit, SafeError> {
        self.shared
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())
    }

    pub(crate) async fn serve_admitted_connection(
        &self,
        stream: TlsStream<TcpStream>,
        _admission: OwnedSemaphorePermit,
        deadline: tokio::time::Instant,
    ) -> Result<(), SafeError> {
        serve_until(self.shared.clone(), stream, deadline).await
    }
}

// Both Hyper I/O and the exporter use the same Rustls session. Locks are held
// only during one synchronous poll/exporter operation, never across await.
#[derive(Clone)]
struct SessionIo(Arc<Mutex<TlsStream<TcpStream>>>, tokio::time::Instant);
impl SessionIo {
    fn check_deadline(&self) -> io::Result<()> {
        if tokio::time::Instant::now() >= self.1 {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Public connection expired.",
            ))
        } else {
            Ok(())
        }
    }
}
impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_read(cx, buf),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
}
impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_write(cx, buf),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_flush(cx),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_deadline() {
            return Poll::Ready(Err(error));
        }
        match self.0.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_shutdown(cx),
            Err(_) => Poll::Ready(Err(io::Error::other("TLS session unavailable"))),
        }
    }
}
struct Session {
    io: SessionIo,
    challenged: AtomicBool,
    attestation_issued: AtomicBool,
    paid_rpc_attempted: AtomicBool,
    wallet_rpc_attempted: AtomicBool,
}

#[cfg(test)]
async fn serve<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    stream: TlsStream<TcpStream>,
) -> Result<(), SafeError> {
    let _connection = shared
        .connections
        .try_acquire()
        .map_err(|_| unavailable())?;
    serve_until(
        shared.clone(),
        stream,
        tokio::time::Instant::now() + Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS),
    )
    .await
}

async fn serve_until<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    stream: TlsStream<TcpStream>,
    deadline: tokio::time::Instant,
) -> Result<(), SafeError> {
    let (_, tls) = stream.get_ref();
    let http2 = tls.alpn_protocol() == Some(b"h2");
    if tokio::time::Instant::now() >= deadline
        || tls.is_handshaking()
        || tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || (tls.alpn_protocol() != Some(b"http/1.1") && !http2)
        || !matches!(
            tls.handshake_kind(),
            Some(rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest)
        )
    {
        return Err(unavailable());
    }
    let io = SessionIo(Arc::new(Mutex::new(stream)), deadline);
    let session = Arc::new(Session {
        io: io.clone(),
        challenged: AtomicBool::new(false),
        attestation_issued: AtomicBool::new(false),
        paid_rpc_attempted: AtomicBool::new(false),
        wallet_rpc_attempted: AtomicBool::new(false),
    });
    let service = hyper::service::service_fn(|request| {
        let shared = shared.clone();
        let session = session.clone();
        async move { Ok::<_, Infallible>(handle(shared, session, request).await) }
    });
    // Dropping the connection future also drops an in-progress quote future.
    if http2 {
        tokio::time::timeout_at(
            deadline,
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(TokioIo::new(io), service),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
    } else {
        tokio::time::timeout_at(
            deadline,
            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io), service),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
    }
}

fn reply(status: StatusCode, body: Bytes) -> Response<Body> {
    let mut response = Response::new(Body::new(Full::new(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
fn failure(status: StatusCode) -> Response<Body> {
    reply(
        status,
        Bytes::from_static(br#"{"error":"public_attestation_unavailable"}"#),
    )
}
async fn handle<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    session: Arc<Session>,
    request: Request<Incoming>,
) -> Response<Body> {
    if session.io.check_deadline().is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    let version = request.version();
    if request.method() != hyper::Method::POST
        || !matches!(version, Version::HTTP_11 | Version::HTTP_2)
        || (version == Version::HTTP_11 && request.uri().authority().is_some())
    {
        return failure(StatusCode::NOT_FOUND);
    }
    match request.uri().path_and_query().map(|p| p.as_str()) {
        Some("/rpc") if version == Version::HTTP_11 => {
            return handle_rpc(shared, session, request).await;
        }
        Some(path) if version == Version::HTTP_2 && ReadMethod::from_path(path).is_some() => {
            return handle_wallet_rpc(shared, session, request).await;
        }
        Some("/attestation") => {}
        _ => return failure(StatusCode::NOT_FOUND),
    }
    if request.headers().contains_key(header::CONTENT_ENCODING)
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|h| h != "application/json")
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let body = match Limited::new(request.into_body(), MAX_ATTESTATION_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return failure(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request = match parse_attestation_request(&body) {
        Ok(request) => request,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    // Every connection can attempt just its one challenge. Failure does not make
    // it reusable with another nonce, nor does any status grant RPC permission.
    if session.challenged.swap(true, Ordering::SeqCst) {
        return failure(StatusCode::CONFLICT);
    }
    let _quote = match shared.quotes.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return failure(StatusCode::TOO_MANY_REQUESTS),
    };
    {
        let mut last = match shared.last_quote.lock() {
            Ok(last) => last,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        let now = Instant::now();
        if last
            .is_some_and(|previous| now.saturating_duration_since(previous) < shared.quote_spacing)
        {
            return failure(StatusCode::TOO_MANY_REQUESTS);
        }
        *last = Some(now);
    }
    let exporter = {
        if session.io.check_deadline().is_err() {
            return failure(StatusCode::SERVICE_UNAVAILABLE);
        }
        let stream = match session.io.0.lock() {
            Ok(stream) => stream,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        };
        match stream.get_ref().1.export_keying_material(
            [0u8; 64],
            ATTESTATION_EXPORTER_LABEL,
            Some(&request.nonce),
        ) {
            Ok(exporter) => exporter,
            Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
        }
    };
    let evidence = match shared.source.quote(exporter).await {
        Ok(evidence) => evidence,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    if session.io.check_deadline().is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    // Bound while serializing, avoiding a second unbounded response allocation.
    let mut output = BoundedOutput(Vec::new());
    let serialized = match evidence {
        QuoteEvidence::Phala(evidence) => serde_json::to_writer(
            &mut output,
            &PublicAttestationResponse {
                nonce: request.nonce,
                quote: evidence.quote,
                event_log: evidence.event_log,
                report_data: evidence.report_data,
                vm_config: evidence.vm_config,
            },
        ),
        QuoteEvidence::Gcp(evidence) => serde_json::to_writer(
            &mut output,
            &zrpc_protocol::GcpAttestationResponse {
                schema_version: 1,
                platform: zrpc_protocol::Backend::GcpTdx,
                nonce: request.nonce,
                quote: evidence.quote,
                ccel: evidence.ccel,
            },
        ),
    };
    if serialized.is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    session.attestation_issued.store(true, Ordering::SeqCst);
    reply(StatusCode::OK, Bytes::from(output.0))
}

async fn handle_wallet_rpc<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    session: Arc<Session>,
    mut request: Request<Incoming>,
) -> Response<Body> {
    let Some(backend) = shared.wallet_backend.as_ref() else {
        return failure(StatusCode::NOT_FOUND);
    };
    // Claim the one wallet RPC on this connection before polling its body.
    // HTTP/2 can deliver parallel streams, so this is a connection-wide atom.
    if !session.attestation_issued.load(Ordering::SeqCst)
        || session.io.check_deadline().is_err()
        || session.wallet_rpc_attempted.swap(true, Ordering::SeqCst)
        || session.paid_rpc_attempted.swap(true, Ordering::SeqCst)
    {
        return failure(StatusCode::FORBIDDEN);
    }
    let authorization = if shared.payment.is_some() {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return failure(StatusCode::FORBIDDEN);
        };
        if values.next().is_some() {
            return failure(StatusCode::FORBIDDEN);
        }
        Some(Zeroizing::new(value.as_bytes().to_vec()))
    } else {
        if request.headers().contains_key(header::AUTHORIZATION) {
            return failure(StatusCode::FORBIDDEN);
        }
        None
    };
    if request.headers().contains_key(header::CONTENT_ENCODING)
        || request.headers().contains_key("grpc-encoding")
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|value| value != "application/grpc")
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    if let Some(payment) = &shared.payment {
        let Some(header) = authorization.as_ref() else {
            return failure(StatusCode::FORBIDDEN);
        };
        if !matches!(
            payment.redeem(header, session.io.1).await,
            Ok(Admission::Accepted)
        ) || session.io.check_deadline().is_err()
        {
            return failure(StatusCode::FORBIDDEN);
        }
    }
    request.headers_mut().remove(header::AUTHORIZATION);
    // Generated Tonic service dispatches only the allowlisted path selected
    // above. Its backing implementation validates typed requests and strips
    // backend metadata/errors; SendTransaction and Ping cannot reach Zebra.
    let result = if request.uri().path() == ReadMethod::GetMempoolSnapshot.path() {
        let mut service = SnapshotReadServer::new(backend.clone());
        service.call(request).await
    } else {
        let mut service = CompactTxStreamerServer::new(backend.clone());
        service.call(request).await
    };
    match result {
        Ok(response) => response,
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn handle_rpc<Q: QuoteSource>(
    shared: Arc<Shared<Q>>,
    session: Arc<Session>,
    request: Request<Incoming>,
) -> Response<Body> {
    let Some(node) = shared.node.as_ref() else {
        return failure(StatusCode::NOT_FOUND);
    };
    if shared.wallet_backend.is_some() && session.wallet_rpc_attempted.swap(true, Ordering::SeqCst)
    {
        return failure(StatusCode::FORBIDDEN);
    }
    // Reject before reading any body unless this exact TLS session completed
    // its one nonce/exporter quote exchange. The native client independently
    // gates private bodies on reviewed-release approval; the preview client
    // sends only typed public testnet reads after diagnostic quote checks.
    if !session.attestation_issued.load(Ordering::SeqCst) || session.io.check_deadline().is_err() {
        return failure(StatusCode::FORBIDDEN);
    }
    // A paid ticket must never share a verified TLS session with another RPC
    // attempt. Otherwise the service could link independently issued tickets
    // simply because the caller presented them over one connection. Claim the
    // attempt before parsing credentials or reading a private request body.
    if shared.payment.is_some() && session.paid_rpc_attempted.swap(true, Ordering::SeqCst) {
        return failure(StatusCode::FORBIDDEN);
    }
    let authorization = if shared.payment.is_some() {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return failure(StatusCode::FORBIDDEN);
        };
        if values.next().is_some() {
            return failure(StatusCode::FORBIDDEN);
        }
        Some(Zeroizing::new(value.as_bytes().to_vec()))
    } else {
        if request.headers().contains_key(header::AUTHORIZATION) {
            return failure(StatusCode::FORBIDDEN);
        }
        None
    };
    if request.headers().contains_key(header::CONTENT_ENCODING)
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|h| h != "application/json")
    {
        return failure(StatusCode::BAD_REQUEST);
    }
    let body = match Limited::new(request.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return failure(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let parsed = match parse_request(&body) {
        Ok(parsed) => parsed,
        Err(_) => return failure(StatusCode::BAD_REQUEST),
    };
    if let Some(payment) = &shared.payment {
        let Some(header) = authorization.as_ref() else {
            return failure(StatusCode::FORBIDDEN);
        };
        if !matches!(
            payment.redeem(header, session.io.1).await,
            Ok(Admission::Accepted)
        ) {
            return failure(StatusCode::FORBIDDEN);
        }
        if session.io.check_deadline().is_err() {
            return failure(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    let result = match node.query(&parsed).await {
        Ok(value) => value,
        Err(error) => {
            // A block mismatch is a typed RPC failure on the retained session.
            // Never include the requested block, address or backend diagnostics.
            if error.code == zrpc_protocol::ErrorCode::BlockMismatch {
                let mut output = BoundedOutput(Vec::new());
                if serde_json::to_writer(
                    &mut output,
                    &serde_json::json!({
                        "jsonrpc":"2.0", "id":parsed.id(), "error":error
                    }),
                )
                .is_err()
                {
                    return failure(StatusCode::SERVICE_UNAVAILABLE);
                }
                return reply(StatusCode::OK, Bytes::from(output.0));
            }
            // SafeError messages are fixed, query-independent literals.
            let mut output = BoundedOutput(Vec::new());
            if serde_json::to_writer(&mut output, &serde_json::json!({"error":error})).is_err() {
                return failure(StatusCode::SERVICE_UNAVAILABLE);
            }
            return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::from(output.0));
        }
    };
    let mut output = BoundedOutput(Vec::new());
    if serde_json::to_writer(&mut output, &result).is_err()
        || output.0.len() > MAX_RESPONSE_BYTES
        || session.io.check_deadline().is_err()
    {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    reply(StatusCode::OK, Bytes::from(output.0))
}
struct BoundedOutput(Vec<u8>);
impl io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("public evidence bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
