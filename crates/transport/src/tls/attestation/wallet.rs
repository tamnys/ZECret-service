//! One typed wallet read on the exact Phala-trusting, attested HTTP/2 stream.
//! This module cannot dial, resolve, reconnect, or construct its own TLS trust.

use super::{
    OwnedHttpSession, SessionSender, VerifiedRpcSession, collateral_expired, expired, unavailable,
};
use hyper::{Request, Response, Uri, body::Incoming, client::conn::http2};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tonic::{
    body::Body,
    codegen::Service,
    metadata::{Ascii, MetadataValue},
};
use zrpc_protocol::{ErrorCode, SafeError};
use zrpc_wallet_read::{NodeReadContext, WalletReadRequest, snapshot_wire, wire};

type Client = wire::compact_tx_streamer_client::CompactTxStreamerClient<RetainedH2>;
type SnapshotClient = snapshot_wire::snapshot_read_client::SnapshotReadClient<RetainedH2>;

fn bad_request() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidParameters,
        "Invalid testnet wallet read request.",
    )
}

fn status_error(status: tonic::Status) -> SafeError {
    use tonic::Code;
    let (code, message) = match status.code() {
        Code::InvalidArgument | Code::OutOfRange => (
            ErrorCode::InvalidParameters,
            "Wallet read request was rejected.",
        ),
        Code::NotFound => (
            ErrorCode::NodeUnavailable,
            "Wallet chain data is unavailable.",
        ),
        Code::DeadlineExceeded => (ErrorCode::BackendTimeout, "Wallet read timed out."),
        Code::Aborted => (ErrorCode::BlockMismatch, "Wallet chain continuity changed."),
        Code::DataLoss => (
            ErrorCode::InvalidBackendResponse,
            "Wallet chain data is malformed.",
        ),
        Code::Unavailable | Code::ResourceExhausted => {
            (ErrorCode::NodeUnavailable, "Wallet node is unavailable.")
        }
        Code::PermissionDenied | Code::Unauthenticated => (
            ErrorCode::PrivateModeUnavailable,
            "Wallet read authorization failed.",
        ),
        _ => (ErrorCode::InvalidBackendResponse, "Wallet read failed."),
    };
    SafeError::new(code, message)
}

fn transaction_status_error(status: tonic::Status) -> SafeError {
    if status.code() == tonic::Code::NotFound {
        SafeError::new(
            ErrorCode::WalletTransactionNotFound,
            "Wallet transaction was not found by the node.",
        )
    } else {
        status_error(status)
    }
}

fn check_live(session: &OwnedHttpSession, deadline: Instant) -> Result<(), SafeError> {
    session.origin.require_managed()?;
    if Instant::now() >= deadline {
        return Err(expired());
    }
    match session.private_deadline.get() {
        Some(value) if !value.is_expired() => {}
        Some(_) => return Err(collateral_expired()),
        None => return Err(unavailable()),
    }
    if session.sender.is_closed() || session.driver.is_finished() {
        return Err(expired());
    }
    Ok(())
}

#[derive(Clone)]
struct RetainedH2 {
    sender: http2::SendRequest<Body>,
}

impl Service<Request<Body>> for RetainedH2 {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut sender = self.sender.clone();
        Box::pin(async move {
            sender.ready().await?;
            sender.send_request(request).await
        })
    }
}

fn with_authorization<T>(value: T, authorization: &MetadataValue<Ascii>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(value);
    request
        .metadata_mut()
        .insert("authorization", authorization.clone());
    request
}

/// A stream owns the verified TLS driver. Dropping it cancels the connection;
/// receiving EOF is distinct from receiving a complete requested block range.
pub struct WalletReadStream<T> {
    inner: tonic::Streaming<T>,
    session: OwnedHttpSession,
    deadline: Instant,
}

impl<T> WalletReadStream<T>
where
    T: prost::Message + Default,
{
    pub async fn next(&mut self) -> Result<Option<T>, SafeError> {
        check_live(&self.session, self.deadline)?;
        let private_deadline = self
            .session
            .private_deadline
            .get()
            .ok_or_else(unavailable)?;
        let operation_deadline = self.deadline.min(private_deadline.monotonic);
        let next = tokio::time::timeout_at(
            tokio::time::Instant::from_std(operation_deadline),
            self.inner.message(),
        )
        .await
        .map_err(|_| expired())?
        .map_err(status_error)?;
        // The backend may end a stream after the original connection expires.
        // Never report a clean EOF or another item in that case.
        if Instant::now() >= self.deadline || private_deadline.is_expired() {
            return Err(expired());
        }
        Ok(next)
    }
}

pub enum WalletReadResult {
    LatestBlock(wire::BlockId),
    Block(wire::CompactBlock),
    BlockNullifiers(wire::CompactBlock),
    BlockRange(WalletReadStream<wire::CompactBlock>),
    BlockRangeNullifiers(WalletReadStream<wire::CompactBlock>),
    Transaction(wire::RawTransaction),
    TaddressTxids(WalletReadStream<wire::RawTransaction>),
    TaddressTransactions(WalletReadStream<wire::RawTransaction>),
    TaddressBalance(wire::Balance),
    TaddressBalanceStream(wire::Balance),
    MempoolTx(WalletReadStream<wire::CompactTx>),
    MempoolStream(WalletReadStream<wire::RawTransaction>),
    MempoolSnapshot(WalletReadStream<snapshot_wire::SnapshotItem>),
    TreeState(wire::TreeState),
    LatestTreeState(wire::TreeState),
    SubtreeRoots(WalletReadStream<wire::SubtreeRoot>),
    AddressUtxos(wire::GetAddressUtxosReplyList),
    AddressUtxosStream(WalletReadStream<wire::GetAddressUtxosReply>),
    LightdInfo(wire::LightdInfo),
}

/// Available only after the existing Phala-trusting quote/release/collateral
/// verifier has authorized the original HTTP/2 TLS connection.
pub struct PhalaTrustedWalletSession(VerifiedRpcSession);

impl fmt::Debug for PhalaTrustedWalletSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhalaTrustedWalletSession([one typed read; retained verified TLS])")
    }
}

impl PhalaTrustedWalletSession {
    pub(super) fn new(verified: VerifiedRpcSession) -> Result<Self, SafeError> {
        verified.ensure_private_ready()?;
        if !matches!(verified.session.sender, SessionSender::Wallet(_)) {
            return Err(unavailable());
        }
        Ok(Self(verified))
    }

    fn client(&self) -> Result<Client, SafeError> {
        let SessionSender::Wallet(sender) = &self.0.session.sender else {
            return Err(unavailable());
        };
        let origin =
            Uri::try_from(format!("https://{}", self.0.authority)).map_err(|_| unavailable())?;
        Ok(Client::with_origin(
            RetainedH2 {
                sender: sender.clone(),
            },
            origin,
        ))
    }

    fn snapshot_client(&self) -> Result<SnapshotClient, SafeError> {
        let SessionSender::Wallet(sender) = &self.0.session.sender else {
            return Err(unavailable());
        };
        let origin =
            Uri::try_from(format!("https://{}", self.0.authority)).map_err(|_| unavailable())?;
        Ok(SnapshotClient::with_origin(
            RetainedH2 {
                sender: sender.clone(),
            },
            origin,
        ))
    }

    /// A local bridge can defer polling and decoding its incoming private
    /// request until this retained connection has already been authorized.
    pub async fn read_from_request_async<F, Fut, P, C, A, H, R>(
        self,
        request: F,
        prepare: P,
    ) -> Result<(WalletReadResult, Option<NodeReadContext>, R), SafeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<WalletReadRequest, SafeError>>,
        P: FnOnce() -> Result<(H, R, C), SafeError>,
        H: AsRef<[u8]>,
        C: FnOnce() -> Result<A, SafeError>,
        A: FnOnce() -> Result<(), SafeError>,
    {
        self.0.ensure_private_ready()?;
        let deadline = self.0.private_operation_deadline()?;
        let request = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), request())
            .await
            .map_err(|_| expired())??;
        self.read_authorized(request, prepare).await
    }

    /// `prepare` runs after the typed request, managed Tor lease, release and
    /// collateral have passed. The claim happens only immediately before the
    /// retained HTTP/2 sender can be polled. Once a send starts, an interrupted
    /// ticket is ambiguous and must remain unavailable for reuse.
    pub async fn read_authorized<P, C, A, H, R>(
        self,
        request: WalletReadRequest,
        prepare: P,
    ) -> Result<(WalletReadResult, Option<NodeReadContext>, R), SafeError>
    where
        P: FnOnce() -> Result<(H, R, C), SafeError>,
        H: AsRef<[u8]>,
        C: FnOnce() -> Result<A, SafeError>,
        A: FnOnce() -> Result<(), SafeError>,
    {
        self.0.ensure_private_ready()?;
        request.validate().map_err(|_| bad_request())?;
        let operation_deadline = self.0.private_operation_deadline()?;
        let mut client = self.client()?;
        self.0.ensure_private_ready()?;
        let (authorization, receipt, claim) = prepare()?;
        let authorization =
            MetadataValue::try_from(authorization.as_ref()).map_err(|_| bad_request())?;
        self.0.ensure_private_ready()?;
        let release_untransmitted = claim()?;
        if let Err(error) = self.0.ensure_private_ready() {
            release_untransmitted()?;
            return Err(error);
        }
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(operation_deadline),
            self.execute(&mut client, request, &authorization),
        )
        .await
        .map_err(|_| expired())??;
        Ok((result.0, result.1, receipt))
    }

    async fn execute(
        self,
        client: &mut Client,
        request: WalletReadRequest,
        authorization: &MetadataValue<Ascii>,
    ) -> Result<(WalletReadResult, Option<NodeReadContext>), SafeError> {
        let mut snapshot_client = if matches!(&request, WalletReadRequest::MempoolSnapshot(_)) {
            Some(self.snapshot_client()?)
        } else {
            None
        };
        let deadline = self.0.deadline;
        let session = self.0.session;
        let context;
        macro_rules! unary {
            ($method:ident, $value:ident, $variant:ident) => {{
                let response = client
                    .$method(with_authorization($value, authorization))
                    .await
                    .map_err(status_error)?;
                context =
                    NodeReadContext::read_metadata(response.metadata()).map_err(status_error)?;
                let response = response.into_inner();
                check_live(&session, deadline)?;
                WalletReadResult::$variant(response)
            }};
        }
        macro_rules! streamed {
            ($method:ident, $value:ident, $variant:ident) => {{
                let response = client
                    .$method(with_authorization($value, authorization))
                    .await
                    .map_err(status_error)?;
                context =
                    NodeReadContext::read_metadata(response.metadata()).map_err(status_error)?;
                let response = response.into_inner();
                check_live(&session, deadline)?;
                WalletReadResult::$variant(WalletReadStream {
                    inner: response,
                    session,
                    deadline,
                })
            }};
        }
        let result = match request {
            WalletReadRequest::LatestBlock(value) => unary!(get_latest_block, value, LatestBlock),
            WalletReadRequest::Block(value) => unary!(get_block, value, Block),
            WalletReadRequest::BlockNullifiers(value) => {
                unary!(get_block_nullifiers, value, BlockNullifiers)
            }
            WalletReadRequest::BlockRange(value) => streamed!(get_block_range, value, BlockRange),
            WalletReadRequest::BlockRangeNullifiers(value) => {
                streamed!(get_block_range_nullifiers, value, BlockRangeNullifiers)
            }
            WalletReadRequest::Transaction(value) => {
                let response = client
                    .get_transaction(with_authorization(value, authorization))
                    .await
                    .map_err(transaction_status_error)?;
                context =
                    NodeReadContext::read_metadata(response.metadata()).map_err(status_error)?;
                let response = response.into_inner();
                check_live(&session, deadline)?;
                WalletReadResult::Transaction(response)
            }
            WalletReadRequest::TaddressTxids(value) => {
                streamed!(get_taddress_txids, value, TaddressTxids)
            }
            WalletReadRequest::TaddressTransactions(value) => {
                streamed!(get_taddress_transactions, value, TaddressTransactions)
            }
            WalletReadRequest::TaddressBalance(value) => {
                unary!(get_taddress_balance, value, TaddressBalance)
            }
            WalletReadRequest::TaddressBalanceStream(value) => {
                let address_stream = tonic::codegen::tokio_stream::iter(value);
                let response = client
                    .get_taddress_balance_stream(with_authorization(address_stream, authorization))
                    .await
                    .map_err(status_error)?;
                context =
                    NodeReadContext::read_metadata(response.metadata()).map_err(status_error)?;
                let response = response.into_inner();
                check_live(&session, deadline)?;
                WalletReadResult::TaddressBalanceStream(response)
            }
            WalletReadRequest::MempoolTx(value) => streamed!(get_mempool_tx, value, MempoolTx),
            WalletReadRequest::MempoolStream(value) => {
                streamed!(get_mempool_stream, value, MempoolStream)
            }
            WalletReadRequest::MempoolSnapshot(value) => {
                let response = snapshot_client
                    .as_mut()
                    .ok_or_else(unavailable)?
                    .get_mempool_snapshot(with_authorization(value, authorization))
                    .await
                    .map_err(status_error)?;
                context =
                    NodeReadContext::read_metadata(response.metadata()).map_err(status_error)?;
                let response = response.into_inner();
                check_live(&session, deadline)?;
                WalletReadResult::MempoolSnapshot(WalletReadStream {
                    inner: response,
                    session,
                    deadline,
                })
            }
            WalletReadRequest::TreeState(value) => unary!(get_tree_state, value, TreeState),
            WalletReadRequest::LatestTreeState(value) => {
                unary!(get_latest_tree_state, value, LatestTreeState)
            }
            WalletReadRequest::SubtreeRoots(value) => {
                streamed!(get_subtree_roots, value, SubtreeRoots)
            }
            WalletReadRequest::AddressUtxos(value) => {
                unary!(get_address_utxos, value, AddressUtxos)
            }
            WalletReadRequest::AddressUtxosStream(value) => {
                streamed!(get_address_utxos_stream, value, AddressUtxosStream)
            }
            WalletReadRequest::LightdInfo(value) => unary!(get_lightd_info, value, LightdInfo),
        };
        Ok((result, context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transaction_lookup_reports_missing_transaction() {
        let missing = tonic::Status::not_found("backend-private detail");
        assert_eq!(
            status_error(missing.clone()).code,
            ErrorCode::NodeUnavailable
        );
        let safe = transaction_status_error(missing);
        assert_eq!(safe.code, ErrorCode::WalletTransactionNotFound);
        assert!(!safe.message.contains("backend-private detail"));
    }
    use crate::{
        ManagedTor, TransportOrigin,
        tls::{
            MAX_CONNECTION_LIFETIME, WALLET_ALPN,
            tests::{connect_wallet_pair, server_config},
        },
    };
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{StatusCode, Version, header};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use prost::Message;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use zrpc_protocol::{
        ATTESTATION_EXPORTER_LABEL, PublicAttestationResponse, parse_attestation_request,
    };

    #[tokio::test]
    async fn synthetic_promotion_uses_original_http2_sender_once() {
        let (client, server) = connect_wallet_pair(server_config(false, Some(WALLET_ALPN))).await;
        let pending = client.unwrap().prepare_challenge().unwrap();
        let nonce = *pending.nonce().unwrap();
        let server = server.unwrap();
        let expected = server
            .get_ref()
            .1
            .export_keying_material([0; 64], ATTESTATION_EXPORTER_LABEL, Some(&nonce))
            .unwrap();
        let promoted = Arc::new(AtomicBool::new(false));
        let wallet_calls = Arc::new(AtomicUsize::new(0));
        let peer = tokio::spawn({
            let promoted = promoted.clone();
            let wallet_calls = wallet_calls.clone();
            async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let promoted = promoted.clone();
                    let wallet_calls = wallet_calls.clone();
                    async move {
                        assert_eq!(request.version(), Version::HTTP_2);
                        let path = request.uri().path().to_owned();
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        if path == "/attestation" {
                            let challenge = parse_attestation_request(&body).unwrap();
                            let evidence = PublicAttestationResponse {
                                nonce: challenge.nonce,
                                quote: "SYNTHETIC_NOT_A_QUOTE".into(),
                                event_log: "[]".into(),
                                report_data: hex::encode(expected),
                                vm_config: "{}".into(),
                            };
                            let mut response = Response::new(Full::new(Bytes::from(
                                serde_json::to_vec(&evidence).unwrap(),
                            )));
                            response.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("application/json"),
                            );
                            return Ok::<_, Infallible>(response);
                        }
                        assert_eq!(
                            path,
                            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"
                        );
                        assert!(promoted.load(Ordering::SeqCst));
                        assert_eq!(wallet_calls.fetch_add(1, Ordering::SeqCst), 0);
                        assert_eq!(body.as_ref(), &[0, 0, 0, 0, 0]);
                        let block = wire::BlockId {
                            height: 42,
                            hash: vec![7; 32],
                        }
                        .encode_to_vec();
                        let mut frame = vec![0];
                        frame.extend_from_slice(&(block.len() as u32).to_be_bytes());
                        frame.extend_from_slice(&block);
                        let mut response = Response::new(Full::new(Bytes::from(frame)));
                        *response.status_mut() = StatusCode::OK;
                        response.headers_mut().insert(
                            header::CONTENT_TYPE,
                            header::HeaderValue::from_static("application/grpc"),
                        );
                        response
                            .headers_mut()
                            .insert("grpc-status", header::HeaderValue::from_static("0"));
                        let mut metadata = tonic::metadata::MetadataMap::new();
                        NodeReadContext {
                            height: 41,
                            hash: [8; 32],
                        }
                        .write_metadata(&mut metadata)
                        .unwrap();
                        response.headers_mut().extend(metadata.into_headers());
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(server), service)
                    .await;
            }
        });
        let mut evidence = pending.request_attestation().await.unwrap();
        assert!(!evidence.private_rpc_allowed());
        assert_eq!(wallet_calls.load(Ordering::SeqCst), 0);
        // No fixture evidence is accepted by the production verifier. Only this
        // test directly constructs a session after replacing Tor with a fake.
        let (tor, _listener) = ManagedTor::synthetic_live().unwrap();
        evidence._session.origin = TransportOrigin::Managed(tor);
        let session = super::super::PhalaTrustedRpcSession::from_authenticated_inspection(
            evidence._session,
            evidence.deadline,
            evidence.authority,
            super::super::PrivateDeadline {
                monotonic: Instant::now() + MAX_CONNECTION_LIFETIME,
                collateral_expiration_unix_seconds: u64::MAX,
            },
        )
        .unwrap();
        promoted.store(true, Ordering::SeqCst);
        let wallet = session.into_wallet().unwrap();
        let response = wallet
            .read_authorized(WalletReadRequest::LatestBlock(wire::ChainSpec {}), || {
                Ok((b"synthetic-ticket".as_slice(), (), || Ok(|| Ok(()))))
            })
            .await
            .unwrap();
        let WalletReadResult::LatestBlock(block) = response.0 else {
            panic!("wrong typed result")
        };
        assert_eq!(block.height, 42);
        assert_eq!(block.hash, vec![7; 32]);
        assert_eq!(
            response.1,
            Some(NodeReadContext {
                height: 41,
                hash: [8; 32]
            })
        );
        assert_eq!(wallet_calls.load(Ordering::SeqCst), 1);
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
