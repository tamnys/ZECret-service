//! Internal Zebra JSON-RPC over an explicit loopback socket. This module grants
//! no customer transport or attestation authority and has no public listener.
mod cookie_file;
#[cfg(target_os = "linux")]
pub use cookie_file::stage_gcp_cookie;
mod chain;
mod identity;

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request as HttpRequest, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fmt,
    net::SocketAddrV4,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpStream, sync::Semaphore};
use zcash_protocol::TxId;
use zrpc_protocol::{
    BACKEND_TIMEOUT_SECONDS, BlockRef, EXECUTING_QUERIES, ErrorCode, MAX_RESPONSE_BYTES, Method,
    QUEUED_QUERIES, Request, SafeError, Verbosity, parse_request, validate_chain_context,
};
use zrpc_wallet_read::{
    backend::{MempoolSnapshot as WalletMempoolSnapshot, MempoolSnapshotSource},
    snapshot_wire,
};

/// Only an operator-provided internal cookie is accepted, never browser headers.
/// Cookie bytes are retained in memory; Debug is redacted and no logging exists.
pub struct CookieAuth(header::HeaderValue);

impl CookieAuth {
    pub fn from_cookie(bytes: &[u8]) -> Result<Self, SafeError> {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        let split = bytes
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(unavailable)?;
        if split == 0 || split + 1 == bytes.len() || bytes.iter().any(u8::is_ascii_control) {
            return Err(unavailable());
        }
        let encoded = zeroize::Zeroizing::new(STANDARD.encode(bytes));
        let value = zeroize::Zeroizing::new(format!("Basic {}", encoded.as_str()));
        let mut header = header::HeaderValue::from_str(&value).map_err(|_| unavailable())?;
        header.set_sensitive(true);
        Ok(Self(header))
    }

    /// Read Zebra's pinned 32-byte cookie format from a non-symlink regular
    /// file on tmpfs. The measured container profile must mount the same
    /// memory-backed cookie directory into Zebra and this wrapper.
    pub fn from_tmpfs_file(path: &Path) -> Result<Self, SafeError> {
        cookie_file::read(path)
    }
}

impl fmt::Debug for CookieAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CookieAuth([redacted])")
    }
}

/// All clones share the design's global admission/execution limits and ID source.
/// Instantiate once per wrapper process, not once per incoming request.
#[derive(Clone)]
pub struct LocalNode(Arc<Inner>);

struct Inner {
    address: SocketAddrV4,
    auth: CookieAuth,
    admitted: Semaphore,
    executing: Semaphore,
    next_id: AtomicU64,
}

/// One node-reported mempool ID set, anchored to an unchanged testnet tip.
/// The mempool can still change independently of the chain tip, so callers
/// must not treat this as a globally atomic or consensus-approved set.
pub(crate) struct MempoolSnapshot {
    pub tip: BlockRef,
    pub txids: Vec<TxId>,
}

impl fmt::Debug for LocalNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalNode([internal endpoint])")
    }
}

impl LocalNode {
    /// Numeric loopback only: no hostname, URL, resolver, proxy environment or
    /// external node. The eventual Compose configuration must share this network
    /// namespace with Zebra and keep its RPC port unexposed.
    pub fn new(address: SocketAddrV4, auth: CookieAuth) -> Result<Self, SafeError> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(unavailable());
        }
        Ok(Self(Arc::new(Inner {
            address,
            auth,
            admitted: Semaphore::new(EXECUTING_QUERIES + QUEUED_QUERIES),
            executing: Semaphore::new(EXECUTING_QUERIES),
            next_id: AtomicU64::new(1),
        })))
    }

    pub async fn handle(&self, bytes: &[u8]) -> Result<Value, SafeError> {
        let request = parse_request(bytes)?;
        self.query(&request).await
    }

    pub async fn query(&self, request: &Request) -> Result<Value, SafeError> {
        // The pinned Zebra method accepts i32 (negative means relative height).
        // This wrapper never sends a negative/overflowing height.
        if matches!(request.method(), Method::GetBlockHash { height } if *height > i32::MAX as u32)
        {
            return Err(SafeError::new(
                ErrorCode::InvalidParameters,
                "Block height is outside the supported node range.",
            ));
        }
        let _admitted = self.0.admitted.try_acquire().map_err(|_| {
            SafeError::new(ErrorCode::BackendBusy, "The bounded backend queue is full.")
        })?;
        // The design's 15-second bound includes queueing, network check and body
        // collection, so a slow peer cannot turn queueing into unbounded waiting.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(BACKEND_TIMEOUT_SECONDS);
        let result = tokio::time::timeout_at(deadline, async {
            let _executing = self
                .0
                .executing
                .acquire()
                .await
                .map_err(|_| unavailable())?;
            self.exchange(request).await
        })
        .await
        .map_err(|_| timed_out())?;
        // Tokio cannot preempt a synchronous maintained decoder/hash operation.
        // Its result must still not escape after the original operation deadline.
        finish_before_deadline(deadline, result)
    }

    /// Internal typed supplier for wallet pending checks. This method is not
    /// reachable through the public JSON-RPC request parser or its allowlist.
    pub(crate) async fn mempool_snapshot(&self) -> Result<MempoolSnapshot, SafeError> {
        let _admitted = self.0.admitted.try_acquire().map_err(|_| {
            SafeError::new(ErrorCode::BackendBusy, "The bounded backend queue is full.")
        })?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(BACKEND_TIMEOUT_SECONDS);
        let result = tokio::time::timeout_at(deadline, async {
            let _executing = self
                .0
                .executing
                .acquire()
                .await
                .map_err(|_| unavailable())?;
            self.exchange_mempool_snapshot().await
        })
        .await
        .map_err(|_| timed_out())?;
        finish_before_deadline(deadline, result)
    }

    async fn exchange_mempool_snapshot(&self) -> Result<MempoolSnapshot, SafeError> {
        let socket = TcpStream::connect(self.0.address)
            .await
            .map_err(|_| unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| unavailable())?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let before = self
            .call(&mut sender, "getblockchaininfo", json!([]))
            .await?;
        let tip = testnet_tip(&before)?;
        let response = self
            .call(&mut sender, "getrawmempool", json!([false]))
            .await?;
        let txids = parse_mempool_txids(&response)?;
        let after = self
            .call(&mut sender, "getblockchaininfo", json!([]))
            .await?;
        if testnet_tip(&after)? != tip {
            return Err(SafeError::new(
                ErrorCode::BlockMismatch,
                "The internal node tip changed during the mempool read.",
            ));
        }
        Ok(MempoolSnapshot { tip, txids })
    }

    async fn exchange(&self, request: &Request) -> Result<Value, SafeError> {
        let socket = TcpStream::connect(self.0.address)
            .await
            .map_err(|_| unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| unavailable())?;
        // A cancelled/timed-out request must not detach a live network task.
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        // Check network on the SAME connection before forwarding query parameters.
        // Never cache acceptance across node restarts or new connections.
        let info = self
            .call(&mut sender, "getblockchaininfo", json!([]))
            .await?;
        if info.get("chain").and_then(Value::as_str) != Some("test") {
            return Err(SafeError::new(
                ErrorCode::WrongNetwork,
                "The internal node did not report Zcash testnet.",
            ));
        }
        let (result, chain_context) = match request.method() {
            Method::GetBlockchainInfo => {
                let context = BlockRef::from_parts(&info["blocks"], &info["bestblockhash"])?;
                (info, Some(context))
            }
            Method::GetBlockCount => {
                let context = BlockRef::from_parts(&info["blocks"], &info["bestblockhash"])?;
                (json!(context.height), Some(context))
            }
            Method::GetPreviewAddressBalance { address } => {
                let utxos = self
                    .call(
                        &mut sender,
                        "getaddressutxos",
                        json!([{"addresses":[address.as_str()], "chainInfo":true}]),
                    )
                    .await?;
                let (balance, context) = chain::balance(&utxos, address)?;
                (json!({"balance":balance}), Some(context))
            }
            _ => (
                self.call(
                    &mut sender,
                    request.method().name(),
                    params(request.method()),
                )
                .await?,
                None,
            ),
        };
        validate_result(request.method(), &result)?;
        validate_chain_context(request, &result, chain_context.as_ref())?;
        if let Method::GetBlockHeader {
            hash,
            verbosity: Verbosity::Verbose,
        } = request.method()
        {
            // The raw companion stays on this socket, with the original admission
            // permit and deadline. No new connection, retry, or deadline reset.
            let raw = self
                .call(&mut sender, "getblockheader", json!([hash.as_str(), false]))
                .await?;
            let header = identity::header(&raw, hash.as_str())?;
            identity::verbose_header(&result, &header)?;
        }
        let mut response = json!({"jsonrpc":"2.0", "id":request.id(), "result":result});
        if let Some(context) = chain_context {
            response["chain_context"] = json!(context);
        }
        // The caller's original ID can increase size; bound the returned envelope too.
        super::check_response_bound(&response)?;
        Ok(response)
    }

    async fn call(
        &self,
        sender: &mut http1::SendRequest<Full<Bytes>>,
        method: &'static str,
        params: Value,
    ) -> Result<Value, SafeError> {
        let id = self
            .0
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| unavailable())?;
        // IDs are fresh process-local numbers, never caller IDs or trace metadata.
        let body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}),
        )
        .map_err(|_| unavailable())?;
        let mut request = HttpRequest::post("/")
            .header(header::HOST, self.0.address.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| unavailable())?;
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, self.0.auth.0.clone());
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| unavailable())?;
        // No redirects, compression, cookies, tracing or retry behavior.
        if response.status() != StatusCode::OK {
            return Err(unavailable());
        }
        if response.headers().contains_key(header::CONTENT_ENCODING) {
            return Err(invalid_response());
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next());
        if content_type != Some("application/json") {
            return Err(invalid_response());
        }
        if response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    too_large()
                } else {
                    unavailable()
                }
            })?
            .to_bytes();
        decode_response(&body, id)
    }
}

#[tonic::async_trait]
impl MempoolSnapshotSource for LocalNode {
    async fn mempool_snapshot(&self) -> Result<WalletMempoolSnapshot, tonic::Status> {
        let snapshot = LocalNode::mempool_snapshot(self).await.map_err(|error| {
            if error.code == ErrorCode::BlockMismatch {
                tonic::Status::aborted("Wallet node tip changed during the mempool read.")
            } else if error.code == ErrorCode::InvalidBackendResponse {
                tonic::Status::data_loss("Invalid wallet node mempool response.")
            } else {
                tonic::Status::unavailable("Wallet node is unavailable.")
            }
        })?;
        let mut hash = hex::decode(snapshot.tip.hash.as_str())
            .map_err(|_| tonic::Status::data_loss("Invalid wallet node block hash."))?;
        hash.reverse();
        Ok(WalletMempoolSnapshot {
            tip: snapshot_wire::SnapshotTip {
                height: u64::from(snapshot.tip.height),
                hash,
            },
            txids: snapshot.txids.into_iter().map(|id| *id.as_ref()).collect(),
        })
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn params(method: &Method) -> Value {
    match method {
        Method::GetBlockchainInfo | Method::GetBlockCount => json!([]),
        Method::GetBlockHash { height } => json!([height]),
        Method::GetBlockHeader { hash, verbosity } => {
            json!([hash.as_str(), *verbosity == Verbosity::Verbose])
        }
        // Zebra uses numeric 0/1 here; the public wrapper's boolean is translated.
        Method::GetRawTransaction { txid, verbosity } => {
            json!([txid.as_str(), u8::from(*verbosity == Verbosity::Verbose)])
        }
        Method::GetPreviewAddressBalance { address } => {
            json!([{"addresses": [address.as_str()]}])
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    jsonrpc: String,
    id: u64,
    result: Option<Value>,
    error: Option<Value>,
}

fn decode_response(bytes: &[u8], expected_id: u64) -> Result<Value, SafeError> {
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(invalid_response());
    }
    let response: WireResponse = serde_json::from_slice(bytes).map_err(|_| invalid_response())?;
    if response.jsonrpc != "2.0" || response.id != expected_id {
        return Err(invalid_response());
    }
    if response.error.is_some() {
        return Err(unavailable());
    }
    response.result.ok_or_else(invalid_response)
}

fn is_hash(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn testnet_tip(info: &Value) -> Result<BlockRef, SafeError> {
    if info.get("chain").and_then(Value::as_str) != Some("test") {
        return Err(SafeError::new(
            ErrorCode::WrongNetwork,
            "The internal node did not report Zcash testnet.",
        ));
    }
    BlockRef::from_parts(&info["blocks"], &info["bestblockhash"])
}

fn parse_mempool_txids(value: &Value) -> Result<Vec<TxId>, SafeError> {
    let ids = value.as_array().ok_or_else(invalid_response)?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    result
        .try_reserve_exact(ids.len())
        .map_err(|_| too_large())?;
    for id in ids {
        let text = id.as_str().ok_or_else(invalid_response)?;
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_response());
        }
        let txid = TxId::from_hex(text).ok_or_else(invalid_response)?;
        if !seen.insert(txid) {
            return Err(invalid_response());
        }
        result.push(txid);
    }
    Ok(result)
}

fn validate_result(method: &Method, result: &Value) -> Result<(), SafeError> {
    let valid = match method {
        Method::GetBlockchainInfo => {
            result.get("chain").and_then(Value::as_str) == Some("test")
                && result
                    .get("blocks")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n <= u32::MAX as u64)
                && result.get("bestblockhash").is_some_and(is_hash)
        }
        Method::GetBlockCount => result.as_u64().is_some_and(|n| n <= u32::MAX as u64),
        Method::GetBlockHash { .. } => is_hash(result),
        Method::GetPreviewAddressBalance { .. } => {
            result.get("balance").and_then(Value::as_u64).is_some()
                && result
                    .get("received")
                    .is_none_or(|received| received.as_u64().is_some())
        }
        Method::GetBlockHeader {
            hash,
            verbosity: Verbosity::Verbose,
        } => result
            .get("hash")
            .and_then(Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case(hash.as_str())),
        Method::GetRawTransaction {
            txid,
            verbosity: Verbosity::Verbose,
        } => return identity::verbose_transaction(result, txid.as_str()),
        Method::GetBlockHeader {
            hash,
            verbosity: Verbosity::Raw,
        } => return identity::header(result, hash.as_str()).map(|_| ()),
        Method::GetRawTransaction {
            txid,
            verbosity: Verbosity::Raw,
        } => return identity::transaction(result, txid.as_str()).map(|_| ()),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_response())
    }
}

fn finish_before_deadline<T>(
    deadline: tokio::time::Instant,
    result: Result<T, SafeError>,
) -> Result<T, SafeError> {
    if tokio::time::Instant::now() >= deadline {
        Err(timed_out())
    } else {
        result
    }
}

fn timed_out() -> SafeError {
    SafeError::new(
        ErrorCode::BackendTimeout,
        "The internal node deadline expired.",
    )
}

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::NodeUnavailable,
        "The internal node request failed.",
    )
}
fn invalid_response() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidBackendResponse,
        "The internal node returned an invalid RPC response.",
    )
}
fn too_large() -> SafeError {
    SafeError::new(
        ErrorCode::ResponseTooLarge,
        "The internal node response exceeded the decoded response limit.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::combinators::BoxBody;
    use hyper::{
        Response,
        body::{Body, Frame, Incoming},
        service::service_fn,
    };
    use std::{
        convert::Infallible,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };
    use tokio::{io::AsyncReadExt, net::TcpListener, task::JoinSet};

    const COOKIE: &[u8] = b"__cookie__:SYNTHETIC_COOKIE_ONLY";
    const MARKER: &str = "SYNTHETIC_CUSTOMER_ID";
    const HEADER_HASH: &str = "025579869bcf52a989337342f5f57a84f3a28b968f7d6a8307902b065a668d23";
    const HEADER: &str = include_str!("../../../tests/fixtures/zcash/testnet-header.hex");
    const HEADER_JSON: &str =
        include_str!("../../../tests/fixtures/zcash/testnet-header-verbose.json");
    const TX_ID: &str = "64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639";
    const TX: &str = include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex");
    fn auth() -> CookieAuth {
        CookieAuth::from_cookie(COOKIE).unwrap()
    }
    fn request(method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":MARKER, "method":method, "params":params}))
            .unwrap()
    }
    fn chain() -> Value {
        json!({"chain":"test", "blocks":42, "bestblockhash":"ab".repeat(32)})
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Good,
        Mainnet,
        Error,
        WrongId,
        Redirect,
        Compressed,
        Oversized,
        Malformed,
        HeaderFieldMismatch,
        BytesMismatch,
        HeaderRawStall,
        SnapshotTipChanged,
        SnapshotDistinctHash,
    }
    struct Seen {
        body: Value,
        headers: header::HeaderMap,
        connection: u64,
    }
    struct FakeNode {
        node: LocalNode,
        seen: Arc<Mutex<Vec<Seen>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    // No size hint: exercises the decoded streaming bound even without a
    // Content-Length header. Production uses the maintained Limited body type.
    struct UnknownSize(Option<Bytes>);
    impl Body for UnknownSize {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
        }
    }

    async fn fake(mode: Mode) -> FakeNode {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut connection = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        connection += 1;
                        let seen = captured.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |req: HttpRequest<Incoming>| {
                                let seen = seen.clone();
                                async move {
                                    assert_eq!(req.method(), hyper::Method::POST);
                                    assert_eq!(req.uri(), "/");
                                    let (parts, body) = req.into_parts();
                                    let bytes = body.collect().await.unwrap().to_bytes();
                                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                                    let id = value["id"].as_u64().unwrap();
                                    let method = value["method"].as_str().unwrap().to_owned();
                                    let params = value["params"].clone();
                                    seen.lock().unwrap().push(Seen { body:value, headers:parts.headers, connection });
                                    if matches!(mode, Mode::HeaderRawStall) && method == "getblockheader" && params[1] == false {
                                        std::future::pending::<()>().await;
                                    }
                                    let mut result = match method.as_str() {
                                        "getblockchaininfo" => if matches!(mode, Mode::Mainnet) {
                                            json!({"chain":"main"})
                                        } else if matches!(mode, Mode::SnapshotDistinctHash) {
                                            json!({"chain":"test", "blocks":42, "bestblockhash":hex::encode((0_u8..32).collect::<Vec<_>>())})
                                        } else if matches!(mode, Mode::SnapshotTipChanged)
                                            && seen.lock().unwrap().iter().any(|request| request.body["method"] == "getrawmempool") {
                                            json!({"chain":"test", "blocks":43, "bestblockhash":"cd".repeat(32)})
                                        } else { chain() },
                                        "getrawmempool" => json!([TX_ID, "ab".repeat(32)]),
                                        "getblockhash" => json!("ab".repeat(32)),
                                        "getaddressutxos" => json!({"height":43,"hash":"cd".repeat(32),"utxos":[{
                                            "address":params[0]["addresses"][0],"txid":"ab".repeat(32),"outputIndex":0,"satoshis":7,"height":40
                                        }]}),
                                        "getblockheader" if params[1] == true => serde_json::from_str(HEADER_JSON).unwrap(),
                                        "getrawtransaction" if params[1] == 1 => json!({"txid":TX_ID, "hex":TX.trim()}),
                                        "getblockheader" => json!(HEADER.trim()),
                                        "getrawtransaction" => json!(TX.trim()),
                                        _ => panic!("unexpected forwarded method"),
                                    };
                                    if matches!(mode, Mode::HeaderFieldMismatch) && method == "getblockheader" && params[1] == true {
                                        result["merkleroot"] = json!("ab".repeat(32));
                                    }
                                    if matches!(mode, Mode::BytesMismatch) {
                                        if method == "getblockheader" && params[1] == false {
                                            result = json!(format!("{}00", HEADER.trim()));
                                        } else if method == "getrawtransaction" && params[1] == 1 {
                                            result["hex"] = json!(format!("{}00", TX.trim()));
                                        } else if method == "getrawtransaction" {
                                            result = json!(format!("{}00", TX.trim()));
                                        }
                                    }
                                    let mut response = json!({"jsonrpc":"2.0", "id":id, "result":result});
                                    let mut status = StatusCode::OK;
                                    let mut compressed = false;
                                    let mut oversized = false;
                                    let mut malformed = false;
                                    if method != "getblockchaininfo" {
                                        match mode {
                                            Mode::Error => response = json!({"jsonrpc":"2.0", "id":id, "error":{"code":-1,"message":"SYNTHETIC_PRIVATE_MARKER"}}),
                                            Mode::WrongId => response["id"] = json!(id + 1),
                                            Mode::Redirect => status = StatusCode::FOUND,
                                            Mode::Compressed => compressed = true,
                                            Mode::Oversized => oversized = true,
                                            Mode::Malformed => malformed = true,
                                            _ => {},
                                        }
                                    }
                                    let body: BoxBody<Bytes, Infallible> = if oversized {
                                        UnknownSize(Some(Bytes::from(vec![b' '; MAX_RESPONSE_BYTES + 1]))).boxed()
                                    } else if malformed {
                                        Full::new(Bytes::from_static(b"[{\"verified\":true}] SYNTHETIC_PRIVATE_MARKER")).boxed()
                                    } else { Full::new(Bytes::from(serde_json::to_vec(&response).unwrap())).boxed() };
                                    let mut response = Response::builder().status(status)
                                        .header(header::CONTENT_TYPE, "application/json");
                                    if compressed { response = response.header(header::CONTENT_ENCODING, "gzip"); }
                                    if status.is_redirection() { response = response.header(header::LOCATION, "http://direct-trap.invalid/"); }
                                    Ok::<_, Infallible>(response.body(body).unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        FakeNode {
            node: LocalNode::new(address, auth()).unwrap(),
            seen,
            task,
        }
    }

    #[test]
    fn local_configuration_and_cookie_are_bounded_to_internal_use() {
        for endpoint in ["0.0.0.0:8232", "192.0.2.1:8232", "127.0.0.1:0"] {
            assert!(LocalNode::new(endpoint.parse().unwrap(), auth()).is_err());
        }
        for invalid in [
            b"".as_slice(),
            b"no-colon",
            b":password",
            b"username:",
            b"u:p\nInjected",
        ] {
            assert!(CookieAuth::from_cookie(invalid).is_err());
        }
        assert!(!format!("{:?}", auth()).contains("SYNTHETIC_COOKIE_ONLY"));
        assert!(CookieAuth::from_cookie(b"__cookie__:fixture\r\n").is_ok());
    }

    #[tokio::test]
    async fn expected_block_matches_the_result_and_never_causes_a_retry() {
        let backend = fake(Mode::Good).await;
        for (method, params, height, hash) in [
            ("getblockcount", json!([]), 42, "ab"),
            ("getblockchaininfo", json!([]), 42, "ab"),
            (
                "getaddressbalance",
                json!([{"addresses":[zrpc_protocol::PREVIEW_TESTNET_ADDRESS]}]),
                43,
                "cd",
            ),
        ] {
            for (selected_height, selected_hash, matched) in [
                (height, hash, true),
                (height - 1, hash, false),
                (height, "ef", false),
            ] {
                let before = backend.seen.lock().unwrap().len();
                let request = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params,
                    "expected_block":{"height":selected_height,"hash":selected_hash.repeat(32)}}),
                )
                .unwrap();
                let result = backend.node.handle(&request).await;
                if matched {
                    let response = result.unwrap();
                    assert_eq!(
                        response["chain_context"],
                        json!({"height":height,"hash":hash.repeat(32)})
                    );
                    if method == "getblockcount" {
                        assert_eq!(response["result"], json!(height));
                    }
                } else {
                    assert_eq!(result.unwrap_err().code, ErrorCode::BlockMismatch);
                }
                assert_eq!(
                    backend.seen.lock().unwrap().len() - before,
                    if method == "getaddressbalance" { 2 } else { 1 }
                );
            }
        }
        let oversized = fake(Mode::Oversized).await;
        assert_eq!(
            oversized
                .node
                .handle(&request(
                    "getaddressbalance",
                    json!([{"addresses":[zrpc_protocol::PREVIEW_TESTNET_ADDRESS]}])
                ))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ResponseTooLarge
        );
    }

    #[tokio::test]
    async fn address_balance_forwards_only_validated_testnet_transparent_selection() {
        let fake = fake(Mode::Good).await;
        let exact = json!([{"addresses": [zrpc_protocol::PREVIEW_TESTNET_ADDRESS]}]);
        let response = fake
            .node
            .handle(&request("getaddressbalance", exact.clone()))
            .await
            .unwrap();
        assert_eq!(response["id"], MARKER);
        assert_eq!(response["result"], json!({"balance": 7}));
        // Chain status was at 42/ab; the balance belongs to its own 43/cd state.
        assert_eq!(
            response["chain_context"],
            json!({"height":43,"hash":"cd".repeat(32)})
        );
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].body["method"], "getblockchaininfo");
        assert_eq!(seen[1].body["method"], "getaddressutxos");
        assert_eq!(
            seen[1].body["params"],
            json!([{"addresses":exact[0]["addresses"],"chainInfo":true}])
        );
        assert_eq!(seen[0].connection, seen[1].connection);
        drop(seen);

        let second = "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma";
        let second_params = json!([{"addresses": [second]}]);
        fake.node
            .handle(&request("getaddressbalance", second_params.clone()))
            .await
            .unwrap();
        assert_eq!(
            fake.seen.lock().unwrap().last().unwrap().body["params"],
            json!([{"addresses":second_params[0]["addresses"],"chainInfo":true}])
        );

        for selection in [
            json!([{"addresses": ["tmArbitraryAddress"]}]),
            json!([{"addresses": ["t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"]}]),
            json!([{"addresses": [zrpc_protocol::PREVIEW_TESTNET_ADDRESS, "tmArbitraryAddress"]}]),
        ] {
            assert_eq!(
                fake.node
                    .handle(&request("getaddressbalance", selection))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidParameters
            );
        }
        assert_eq!(fake.seen.lock().unwrap().len(), 4);
    }

    #[test]
    fn address_balance_requires_unsigned_integer_amounts() {
        let method = Method::GetPreviewAddressBalance {
            address: zrpc_protocol::TestnetTransparentAddress::parse(
                zrpc_protocol::PREVIEW_TESTNET_ADDRESS,
            )
            .unwrap(),
        };
        for valid in [json!({"balance": 0}), json!({"balance": 7, "received": 11})] {
            assert!(validate_result(&method, &valid).is_ok());
        }
        for invalid in [
            json!(7),
            json!({"received": 11}),
            json!({"balance": -1}),
            json!({"balance": 0.5}),
            json!({"balance": "7"}),
            json!({"balance": 7, "received": null}),
            json!({"balance": 7, "received": "11"}),
        ] {
            assert_eq!(
                validate_result(&method, &invalid).unwrap_err().code,
                ErrorCode::InvalidBackendResponse
            );
        }
    }

    #[tokio::test]
    async fn actual_http_allowlist_translation_network_check_and_id_isolation() {
        let fake = fake(Mode::Good).await;
        let selections = [
            ("getblockchaininfo", json!([])),
            ("getblockcount", json!([])),
            ("getblockhash", json!([42])),
            ("getblockheader", json!([HEADER_HASH, true])),
            ("getblockheader", json!([HEADER_HASH, false])),
            ("getrawtransaction", json!([TX_ID, true])),
            ("getrawtransaction", json!([TX_ID, false])),
        ];
        for (method, params) in selections {
            let response = fake.node.handle(&request(method, params)).await.unwrap();
            assert_eq!(response["id"], MARKER);
        }
        let seen = fake.seen.lock().unwrap();
        let ids = seen
            .iter()
            .map(|r| r.body["id"].as_u64().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), seen.len());
        for req in seen.iter() {
            assert!(!serde_json::to_string(&req.body).unwrap().contains(MARKER));
            assert_eq!(
                req.headers[header::AUTHORIZATION],
                format!("Basic {}", STANDARD.encode(COOKIE))
            );
            for forbidden in [
                header::COOKIE,
                header::USER_AGENT,
                header::REFERER,
                header::ORIGIN,
            ] {
                assert!(!req.headers.contains_key(forbidden));
            }
        }
        let raw: Vec<_> = seen
            .iter()
            .filter(|r| r.body["method"] == "getrawtransaction")
            .collect();
        assert_eq!(raw[0].body["params"][1], 1);
        assert_eq!(raw[1].body["params"][1], 0);
        let mut connections = std::collections::BTreeMap::<u64, Vec<&Seen>>::new();
        for req in seen.iter() {
            connections.entry(req.connection).or_default().push(req);
        }
        assert_eq!(connections.len(), 7);
        for requests in connections.values() {
            assert_eq!(requests[0].body["method"], "getblockchaininfo");
        }
        let companion = connections
            .values()
            .find(|requests| requests.len() == 3)
            .unwrap();
        assert_eq!(companion[1].body["params"], json!([HEADER_HASH, true]));
        assert_eq!(companion[2].body["params"], json!([HEADER_HASH, false]));
    }

    #[test]
    fn mempool_ids_reject_malformed_or_duplicate_node_results() {
        assert!(parse_mempool_txids(&json!([])).unwrap().is_empty());
        for value in [
            json!({}),
            json!(["bad"]),
            json!([42]),
            json!([TX_ID, TX_ID]),
            json!([TX_ID, TX_ID.to_ascii_uppercase()]),
        ] {
            assert_eq!(
                parse_mempool_txids(&value).err().unwrap().code,
                ErrorCode::InvalidBackendResponse
            );
        }
    }

    #[tokio::test]
    async fn complete_mempool_id_read_uses_one_testnet_connection_and_tip() {
        let fake = fake(Mode::Good).await;
        let snapshot = fake.node.mempool_snapshot().await.unwrap();
        assert_eq!(snapshot.tip.height, 42);
        assert_eq!(snapshot.tip.hash.as_str(), "ab".repeat(32));
        assert_eq!(snapshot.txids.len(), 2);
        assert_eq!(snapshot.txids[0], TxId::from_hex(TX_ID).unwrap());
        let seen = fake.seen.lock().unwrap();
        let methods: Vec<_> = seen
            .iter()
            .map(|request| request.body["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            ["getblockchaininfo", "getrawmempool", "getblockchaininfo"]
        );
        assert!(
            seen.iter()
                .all(|request| request.connection == seen[0].connection)
        );
        assert_eq!(seen[1].body["params"], json!([false]));
    }

    #[tokio::test]
    async fn wallet_snapshot_converts_display_hashes_to_protocol_byte_order() {
        let fake = fake(Mode::SnapshotDistinctHash).await;
        let snapshot = MempoolSnapshotSource::mempool_snapshot(&fake.node)
            .await
            .unwrap();
        assert_eq!(snapshot.tip.height, 42);
        assert_eq!(snapshot.tip.hash, (0_u8..32).rev().collect::<Vec<_>>());
        assert_eq!(
            snapshot.txids[0].as_slice(),
            TxId::from_hex(TX_ID).unwrap().as_ref()
        );
    }

    #[tokio::test]
    async fn mempool_id_read_rejects_wrong_network_changed_tip_and_bad_reply() {
        for (mode, expected, calls) in [
            (Mode::Mainnet, ErrorCode::WrongNetwork, 1),
            (Mode::SnapshotTipChanged, ErrorCode::BlockMismatch, 3),
            (Mode::WrongId, ErrorCode::InvalidBackendResponse, 2),
        ] {
            let fake = fake(mode).await;
            assert_eq!(
                fake.node.mempool_snapshot().await.err().unwrap().code,
                expected
            );
            assert_eq!(fake.seen.lock().unwrap().len(), calls);
        }
    }

    #[tokio::test]
    async fn actual_http_rejects_fabricated_fields_and_mismatched_companion_bytes() {
        let fake = fake(Mode::HeaderFieldMismatch).await;
        assert_eq!(
            fake.node
                .handle(&request("getblockheader", json!([HEADER_HASH, true])))
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidBackendResponse
        );
        assert_eq!(fake.seen.lock().unwrap().len(), 3);
        let fake = super::tests::fake(Mode::BytesMismatch).await;
        for (method, params) in [
            ("getblockheader", json!([HEADER_HASH, true])),
            ("getblockheader", json!([HEADER_HASH, false])),
            ("getrawtransaction", json!([TX_ID, true])),
            ("getrawtransaction", json!([TX_ID, false])),
        ] {
            assert_eq!(
                fake.node
                    .handle(&request(method, params))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidBackendResponse
            );
        }
    }

    #[tokio::test]
    async fn companion_raw_header_uses_original_deadline_and_capacity() {
        let fake = fake(Mode::HeaderRawStall).await;
        let node = fake.node.clone();
        let operation = tokio::spawn(async move {
            node.handle(&request("getblockheader", json!([HEADER_HASH, true])))
                .await
        });
        while fake.seen.lock().unwrap().len() != 3 {
            tokio::task::yield_now().await;
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(BACKEND_TIMEOUT_SECONDS)).await;
        assert_eq!(
            operation.await.unwrap().unwrap_err().code,
            ErrorCode::BackendTimeout
        );
        tokio::time::resume();
        assert_eq!(
            fake.node.0.admitted.available_permits(),
            EXECUTING_QUERIES + QUEUED_QUERIES
        );
        assert_eq!(fake.node.0.executing.available_permits(), EXECUTING_QUERIES);
        let seen = fake.seen.lock().unwrap();
        assert!(seen.iter().all(|req| req.connection == seen[0].connection));
    }

    #[tokio::test(start_paused = true)]
    async fn synchronous_result_cannot_escape_after_original_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(BACKEND_TIMEOUT_SECONDS);
        assert!(finish_before_deadline(deadline, Ok(())).is_ok());
        tokio::time::advance(Duration::from_secs(BACKEND_TIMEOUT_SECONDS)).await;
        assert_eq!(
            finish_before_deadline(deadline, Ok(())).unwrap_err().code,
            ErrorCode::BackendTimeout
        );
    }

    #[tokio::test]
    async fn wrong_network_never_receives_customer_selection() {
        let fake = fake(Mode::Mainnet).await;
        let error = fake
            .node
            .handle(&request(
                "getrawtransaction",
                json!(["ab".repeat(32), true]),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WrongNetwork);
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body["method"], "getblockchaininfo");
        assert_eq!(seen[0].body["params"], json!([]));
    }

    #[tokio::test]
    async fn bad_backend_responses_are_bounded_and_sanitized() {
        for (mode, expected) in [
            (Mode::Error, ErrorCode::NodeUnavailable),
            (Mode::WrongId, ErrorCode::InvalidBackendResponse),
            (Mode::Redirect, ErrorCode::NodeUnavailable),
            (Mode::Compressed, ErrorCode::InvalidBackendResponse),
            (Mode::Oversized, ErrorCode::ResponseTooLarge),
            (Mode::Malformed, ErrorCode::InvalidBackendResponse),
        ] {
            let fake = fake(mode).await;
            let error = fake
                .node
                .handle(&request("getblockhash", json!([42])))
                .await
                .unwrap_err();
            assert_eq!(error.code, expected);
            assert!(
                !serde_json::to_string(&error)
                    .unwrap()
                    .contains("SYNTHETIC_PRIVATE_MARKER")
            );
            assert_eq!(fake.seen.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn prohibited_or_out_of_range_input_never_dials_backend() {
        let fake = fake(Mode::Good).await;
        for bytes in [
            request("sendrawtransaction", json!(["SYNTHETIC_PRIVATE_MARKER"])),
            request("getblockhash", json!([u32::MAX])),
            vec![b' '; zrpc_protocol::MAX_REQUEST_BYTES + 1],
        ] {
            assert!(fake.node.handle(&bytes).await.is_err());
        }
        assert!(fake.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn response_envelope_and_selection_consistency_are_strict() {
        for body in [
            br#"{"jsonrpc":"2.0","id":1,"id":1,"result":42}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":2,"result":42}"#,
            br#"{"jsonrpc":"2.0","id":1,"result":42,"extra":"marker"}"#,
            br#"["2.0",1,42,null]"#,
        ] {
            assert!(decode_response(body, 1).is_err());
        }
        let req = parse_request(&request(
            "getrawtransaction",
            json!(["ab".repeat(32), true]),
        ))
        .unwrap();
        assert!(validate_result(req.method(), &json!({"txid":"cd".repeat(32)})).is_err());
    }

    #[tokio::test]
    async fn timeout_drops_socket_and_restores_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let node = LocalNode::new(address, auth()).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut first = [0; 1];
            socket.read_exact(&mut first).await.unwrap();
            started_tx.send(()).unwrap();
            let mut remainder = Vec::new();
            socket.read_to_end(&mut remainder).await.unwrap();
        });
        let copy = node.clone();
        let operation =
            tokio::spawn(async move { copy.handle(&request("getblockcount", json!([]))).await });
        started_rx.await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(BACKEND_TIMEOUT_SECONDS)).await;
        assert_eq!(
            operation.await.unwrap().unwrap_err().code,
            ErrorCode::BackendTimeout
        );
        tokio::time::resume();
        server.await.unwrap();
        assert_eq!(
            node.0.admitted.available_permits(),
            EXECUTING_QUERIES + QUEUED_QUERIES
        );
        assert_eq!(node.0.executing.available_permits(), EXECUTING_QUERIES);
    }

    #[tokio::test]
    async fn shared_admission_allows_two_executing_and_four_waiting_and_releases_on_cancel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let node = LocalNode::new(address, auth()).unwrap();
        let mut operations = Vec::new();
        for _ in 0..EXECUTING_QUERIES + QUEUED_QUERIES {
            let copy = node.clone();
            operations.push(tokio::spawn(async move {
                copy.handle(&request("getblockcount", json!([]))).await
            }));
        }
        while node.0.admitted.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(node.0.executing.available_permits(), 0);
        assert_eq!(
            node.handle(&request("getblockcount", json!([])))
                .await
                .unwrap_err()
                .code,
            ErrorCode::BackendBusy
        );
        for operation in operations {
            operation.abort();
            let _ = operation.await;
        }
        assert_eq!(
            node.0.admitted.available_permits(),
            EXECUTING_QUERIES + QUEUED_QUERIES
        );
        assert_eq!(node.0.executing.available_permits(), EXECUTING_QUERIES);
    }
}
