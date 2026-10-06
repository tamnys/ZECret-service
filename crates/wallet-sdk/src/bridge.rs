//! Local-only lightwalletd-compatible gRPC bridge. Tonic's interceptor checks
//! the per-run capability before it decodes a protobuf request body. No wallet
//! state is kept here; every permitted method goes through `WalletReader`.

use crate::{WalletReadCompletion, WalletReadItem, WalletReader};
use futures_util::{Stream, stream};
use std::{
    fs::OpenOptions,
    future::{Future, ready},
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
};
use tonic::{
    Request, Response, Status,
    service::Interceptor,
    transport::{Channel, Endpoint, Server},
};
use wire::compact_tx_streamer_server::{CompactTxStreamer, CompactTxStreamerServer};
use zeroize::Zeroize;
use zrpc_payments::{PrivateDirectory, SecretBytes};
use zrpc_protocol::{ErrorCode, SafeError};
pub use zrpc_wallet_read::snapshot_wire;
use zrpc_wallet_read::snapshot_wire::snapshot_read_server::{SnapshotRead, SnapshotReadServer};
use zrpc_wallet_read::{WalletReadRequest, wire};

type ReadStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;
pub type LocalClient = wire::compact_tx_streamer_client::CompactTxStreamerClient<
    tonic::service::interceptor::InterceptedService<Channel, LocalCapabilityInterceptor>,
>;
pub type LocalSnapshotClient = snapshot_wire::snapshot_read_client::SnapshotReadClient<
    tonic::service::interceptor::InterceptedService<Channel, LocalCapabilityInterceptor>,
>;
pub type MaintainedScannerClient =
    zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<
        tonic::service::interceptor::InterceptedService<Channel, LocalCapabilityInterceptor>,
    >;

/// A local observation of the bridge, never authority for a future request.
/// Failed or cancelled reads cannot establish which verification or ticket
/// steps completed, so their outcome does not claim either one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeReadOutcome {
    NotAttempted,
    InProgress,
    Completed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletBridgeStatus {
    pub active: bool,
    pub last_outcome: BridgeReadOutcome,
    /// None means the ticket outcome is not established by this snapshot.
    pub last_ticket_spent: Option<bool>,
}

impl Default for WalletBridgeStatus {
    fn default() -> Self {
        Self {
            active: false,
            last_outcome: BridgeReadOutcome::NotAttempted,
            last_ticket_spent: None,
        }
    }
}

struct ActivityGuard {
    status: Arc<StdMutex<WalletBridgeStatus>>,
    completed: bool,
}

impl ActivityGuard {
    fn begin(status: Arc<StdMutex<WalletBridgeStatus>>) -> Result<Self, SafeError> {
        let mut snapshot = status.lock().map_err(|_| unavailable())?;
        *snapshot = WalletBridgeStatus {
            active: true,
            last_outcome: BridgeReadOutcome::InProgress,
            last_ticket_spent: None,
        };
        drop(snapshot);
        Ok(Self {
            status,
            completed: false,
        })
    }

    fn complete(&mut self, result: WalletReadCompletion) -> Result<(), SafeError> {
        let mut snapshot = self.status.lock().map_err(|_| unavailable())?;
        *snapshot = WalletBridgeStatus {
            active: false,
            last_outcome: BridgeReadOutcome::Completed,
            last_ticket_spent: Some(result.ticket_spent),
        };
        self.completed = true;
        Ok(())
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(mut snapshot) = self.status.lock() {
                *snapshot = WalletBridgeStatus {
                    active: false,
                    last_outcome: BridgeReadOutcome::Unavailable,
                    last_ticket_spent: None,
                };
            }
        }
    }
}

fn unavailable() -> SafeError {
    SafeError::new(
        ErrorCode::NodeUnavailable,
        "Local wallet reader unavailable.",
    )
}

fn wrong_result() -> SafeError {
    SafeError::new(
        ErrorCode::InvalidBackendResponse,
        "Wallet read returned an unexpected message type.",
    )
}

fn status(error: SafeError) -> Status {
    match error.code {
        ErrorCode::InvalidRequest | ErrorCode::InvalidParameters | ErrorCode::MethodNotAllowed => {
            Status::invalid_argument("Invalid testnet wallet read request.")
        }
        ErrorCode::BlockMismatch | ErrorCode::InvalidBackendResponse => {
            Status::data_loss("Wallet chain data is incomplete or inconsistent.")
        }
        ErrorCode::BackendTimeout | ErrorCode::StaleNonce => {
            Status::deadline_exceeded("Wallet read timed out.")
        }
        ErrorCode::WalletTransactionNotFound => Status::not_found("Wallet transaction not found."),
        _ => Status::unavailable("Verified wallet read unavailable."),
    }
}

fn authenticate(request: Request<()>, expected: &SecretBytes) -> Result<Request<()>, Status> {
    let headers = request.metadata();
    if headers.get("origin").is_some()
        || headers.get("sec-fetch-mode").is_some()
        || headers.get("sec-fetch-site").is_some()
        || headers.get("sec-fetch-dest").is_some()
    {
        return Err(Status::permission_denied(
            "Browser-origin wallet requests are unavailable.",
        ));
    }
    let Some(provided) = headers.get("x-zrpc-capability") else {
        return Err(Status::unauthenticated("Local wallet capability required."));
    };
    let bytes = provided.as_bytes();
    if bytes.len() != expected.expose().len() || !bool::from(bytes.ct_eq(expected.expose())) {
        return Err(Status::unauthenticated("Local wallet capability required."));
    }
    Ok(request)
}

#[derive(Clone)]
pub struct LocalCapabilityInterceptor(Arc<SecretBytes>);

impl Interceptor for LocalCapabilityInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let value = tonic::metadata::MetadataValue::try_from(self.0.expose())
            .map_err(|_| Status::unavailable("Local wallet capability unavailable."))?;
        request.metadata_mut().insert("x-zrpc-capability", value);
        Ok(request)
    }
}

/// Adapter for wallet software able to install a local Tonic client hook.
/// An unmodified lightwalletd client lacks the capability metadata and is
/// deliberately rejected by the bridge.
pub struct LocalWalletAdapter {
    client: LocalClient,
    channel: Channel,
    interceptor: LocalCapabilityInterceptor,
}

impl LocalWalletAdapter {
    pub async fn connect(bind: SocketAddr, capability_dir: &Path) -> Result<Self, SafeError> {
        if !bind.ip().is_loopback() || bind.port() == 0 {
            return Err(unavailable());
        }
        PrivateDirectory::open(capability_dir).map_err(|_| unavailable())?;
        let path = capability_dir.join("capability");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(unavailable());
        }
        let mut value = Vec::new();
        file.take(65)
            .read_to_end(&mut value)
            .map_err(|_| unavailable())?;
        if value.len() != 64 || !value.iter().all(u8::is_ascii_hexdigit) {
            return Err(unavailable());
        }
        let endpoint =
            Endpoint::from_shared(format!("http://{bind}")).map_err(|_| unavailable())?;
        let channel = endpoint.connect().await.map_err(|_| unavailable())?;
        let interceptor = LocalCapabilityInterceptor(Arc::new(SecretBytes::new(value)));
        Ok(Self {
            client: wire::compact_tx_streamer_client::CompactTxStreamerClient::with_interceptor(
                channel.clone(),
                interceptor.clone(),
            ),
            channel,
            interceptor,
        })
    }

    pub fn client(&mut self) -> &mut LocalClient {
        &mut self.client
    }

    pub fn snapshot_client(&self) -> LocalSnapshotClient {
        snapshot_wire::snapshot_read_client::SnapshotReadClient::with_interceptor(
            self.channel.clone(),
            self.interceptor.clone(),
        )
    }

    /// Uses the maintained `zcash_client_backend` generated protobuf types and
    /// their native sync APIs, while retaining the bridge's local capability.
    pub fn maintained_scanner_client(&self) -> MaintainedScannerClient {
        zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::with_interceptor(
            self.channel.clone(), self.interceptor.clone(),
        )
    }
}

#[derive(Clone)]
pub struct WalletBridge {
    reader: Arc<Mutex<WalletReader>>,
    capability: Arc<SecretBytes>,
    status: Arc<StdMutex<WalletBridgeStatus>>,
}

impl WalletBridge {
    /// The returned secret is for the local adapter only. Callers must store
    /// it in a new owner-private file and remove that file when the run ends.
    pub fn new(reader: WalletReader) -> Result<(Self, SecretBytes), SafeError> {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| unavailable())?;
        let encoded = hex::encode(random).into_bytes();
        random.zeroize();
        let local_copy = SecretBytes::new(encoded.clone());
        Ok((
            Self {
                reader: Arc::new(Mutex::new(reader)),
                capability: Arc::new(SecretBytes::new(encoded)),
                status: Arc::new(StdMutex::new(WalletBridgeStatus::default())),
            },
            local_copy,
        ))
    }

    pub fn status(&self) -> Result<WalletBridgeStatus, SafeError> {
        self.status
            .lock()
            .map(|value| *value)
            .map_err(|_| unavailable())
    }

    /// Tonic accepts HTTP/2 gRPC only. No gRPC-Web, reflection or public bind
    /// is installed. The interceptor rejects unauthenticated metadata before
    /// Tonic passes the request body to a generated method handler.
    pub async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), SafeError> {
        let bind: SocketAddr = listener.local_addr().map_err(|_| unavailable())?;
        if !bind.ip().is_loopback() || bind.port() == 0 {
            return Err(unavailable());
        }
        let capability = self.capability.clone();
        let snapshot_capability = self.capability.clone();
        let snapshot_service = SnapshotReadServer::with_interceptor(self.clone(), move |request| {
            authenticate(request, &snapshot_capability)
        });
        let service = CompactTxStreamerServer::with_interceptor(self, move |request| {
            authenticate(request, &capability)
        });
        let incoming = stream::unfold(listener, |listener| async {
            let accepted = listener.accept().await.map(|(socket, _)| socket);
            Some((accepted, listener))
        });
        Server::builder()
            .add_service(service)
            .add_service(snapshot_service)
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
            .map_err(|_| unavailable())
    }

    async fn unary<T, F>(
        &self,
        request: WalletReadRequest,
        select: F,
    ) -> Result<Response<T>, Status>
    where
        T: Send,
        F: Fn(WalletReadItem) -> Result<T, SafeError>,
    {
        self.unary_from(|| ready(Ok(request)), select).await
    }

    async fn unary_from<T, F, Fut, Select>(
        &self,
        request: F,
        select: Select,
    ) -> Result<Response<T>, Status>
    where
        T: Send,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<WalletReadRequest, SafeError>>,
        Select: Fn(WalletReadItem) -> Result<T, SafeError>,
    {
        let mut reader = self.reader.lock().await;
        let mut activity = ActivityGuard::begin(self.status.clone()).map_err(status)?;
        let mut selected = None;
        let completion = reader
            .read_from_request(
                request,
                |item| {
                    let outcome = select(item).and_then(|value| {
                        if selected.replace(value).is_some() {
                            Err(wrong_result())
                        } else {
                            Ok(())
                        }
                    });
                    ready(outcome)
                },
                None,
            )
            .await
            .map_err(status)?;
        let response = selected
            .map(Response::new)
            .ok_or_else(|| status(wrong_result()))?;
        activity.complete(completion).map_err(status)?;
        Ok(response)
    }

    fn streamed<T, F>(&self, request: WalletReadRequest, select: F) -> Response<ReadStream<T>>
    where
        T: Send + 'static,
        F: Fn(WalletReadItem) -> Result<T, SafeError> + Send + Sync + 'static,
    {
        // A single in-flight item is the minimum channel capacity that still
        // lets an async producer wait for a slow local wallet consumer.
        let (sender, receiver) = mpsc::channel(1);
        let reader = self.reader.clone();
        let status_snapshot = self.status.clone();
        let task = tokio::spawn(async move {
            let mut reader = tokio::select! {
                guard = reader.lock() => guard,
                _ = sender.closed() => {
                    return Err(Status::cancelled("Local wallet reader disconnected."));
                }
            };
            let mut activity = ActivityGuard::begin(status_snapshot).map_err(status)?;
            let closed = sender.clone();
            let read = reader.read_from_request(
                || ready(Ok(request)),
                |item| {
                    let value = select(item);
                    let sender = sender.clone();
                    async move {
                        let value = value?;
                        sender.send(value).await.map_err(|_| unavailable())
                    }
                },
                None,
            );
            let result = tokio::select! {
                result = read => result.map_err(status),
                _ = closed.closed() => Err(Status::cancelled("Local wallet reader disconnected.")),
            };
            if let Ok(completion) = result {
                activity.complete(completion).map_err(status)?;
                Ok(())
            } else {
                result.map(|_| ())
            }
        });
        let output = stream::unfold(
            (receiver, Some(task)),
            |(mut receiver, mut task)| async move {
                if let Some(item) = receiver.recv().await {
                    return Some((Ok(item), (receiver, task)));
                }
                let Some(task) = task.take() else {
                    return None;
                };
                match task.await {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some((Err(error), (receiver, None))),
                    Err(_) => Some((
                        Err(Status::unavailable("Wallet read interrupted.")),
                        (receiver, None),
                    )),
                }
            },
        );
        Response::new(Box::pin(output))
    }
}

#[tonic::async_trait]
impl CompactTxStreamer for WalletBridge {
    async fn get_latest_block(
        &self,
        request: Request<wire::ChainSpec>,
    ) -> Result<Response<wire::BlockId>, Status> {
        self.unary(
            WalletReadRequest::LatestBlock(request.into_inner()),
            |item| match item {
                WalletReadItem::LatestBlock(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn get_block(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        self.unary(
            WalletReadRequest::Block(request.into_inner()),
            |item| match item {
                WalletReadItem::Block(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn get_block_nullifiers(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        self.unary(
            WalletReadRequest::BlockNullifiers(request.into_inner()),
            |item| match item {
                WalletReadItem::BlockNullifiers(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    type GetBlockRangeStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::BlockRange(request.into_inner()),
            |item| match item {
                WalletReadItem::BlockRange(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    type GetBlockRangeNullifiersStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range_nullifiers(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::BlockRangeNullifiers(request.into_inner()),
            |item| match item {
                WalletReadItem::BlockRangeNullifiers(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    async fn get_transaction(
        &self,
        request: Request<wire::TxFilter>,
    ) -> Result<Response<wire::RawTransaction>, Status> {
        self.unary(
            WalletReadRequest::Transaction(request.into_inner()),
            |item| match item {
                WalletReadItem::Transaction(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn send_transaction(
        &self,
        _: Request<wire::RawTransaction>,
    ) -> Result<Response<wire::SendResponse>, Status> {
        Err(Status::permission_denied(
            "Transaction submission is unavailable.",
        ))
    }
    type GetTaddressTxidsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_txids(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::TaddressTxids(request.into_inner()),
            |item| match item {
                WalletReadItem::TaddressTxids(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    type GetTaddressTransactionsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_transactions(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::TaddressTransactions(request.into_inner()),
            |item| match item {
                WalletReadItem::TaddressTransactions(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    async fn get_taddress_balance(
        &self,
        request: Request<wire::AddressList>,
    ) -> Result<Response<wire::Balance>, Status> {
        self.unary(
            WalletReadRequest::TaddressBalance(request.into_inner()),
            |item| match item {
                WalletReadItem::TaddressBalance(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn get_taddress_balance_stream(
        &self,
        request: Request<tonic::Streaming<wire::Address>>,
    ) -> Result<Response<wire::Balance>, Status> {
        let mut incoming = request.into_inner();
        self.unary_from(
            || async move {
                let mut addresses = Vec::new();
                while let Some(address) = incoming.message().await.map_err(|_| unavailable())? {
                    addresses.push(address);
                    // Zebra v6.4.2 enforces MAX_REQUEST_ADDRESSES=10_000.
                    if addresses.len() > 10_000 {
                        return Err(SafeError::new(
                            ErrorCode::InvalidParameters,
                            "Too many testnet addresses.",
                        ));
                    }
                }
                Ok(WalletReadRequest::TaddressBalanceStream(addresses))
            },
            |item| match item {
                WalletReadItem::TaddressBalanceStream(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    type GetMempoolTxStream = ReadStream<wire::CompactTx>;
    async fn get_mempool_tx(
        &self,
        request: Request<wire::Exclude>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::MempoolTx(request.into_inner()),
            |item| match item {
                WalletReadItem::MempoolTx(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    type GetMempoolStreamStream = ReadStream<wire::RawTransaction>;
    async fn get_mempool_stream(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::MempoolStream(request.into_inner()),
            |item| match item {
                WalletReadItem::MempoolStream(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    async fn get_tree_state(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::TreeState>, Status> {
        self.unary(
            WalletReadRequest::TreeState(request.into_inner()),
            |item| match item {
                WalletReadItem::TreeState(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn get_latest_tree_state(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::TreeState>, Status> {
        self.unary(
            WalletReadRequest::LatestTreeState(request.into_inner()),
            |item| match item {
                WalletReadItem::LatestTreeState(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    type GetSubtreeRootsStream = ReadStream<wire::SubtreeRoot>;
    async fn get_subtree_roots(
        &self,
        request: Request<wire::GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::SubtreeRoots(request.into_inner()),
            |item| match item {
                WalletReadItem::SubtreeRoots(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    async fn get_address_utxos(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<wire::GetAddressUtxosReplyList>, Status> {
        self.unary(
            WalletReadRequest::AddressUtxos(request.into_inner()),
            |item| match item {
                WalletReadItem::AddressUtxos(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    type GetAddressUtxosStreamStream = ReadStream<wire::GetAddressUtxosReply>;
    async fn get_address_utxos_stream(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::AddressUtxosStream(request.into_inner()),
            |item| match item {
                WalletReadItem::AddressUtxosStream(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
    async fn get_lightd_info(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::LightdInfo>, Status> {
        self.unary(
            WalletReadRequest::LightdInfo(request.into_inner()),
            |item| match item {
                WalletReadItem::LightdInfo(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        )
        .await
    }
    async fn ping(
        &self,
        _: Request<wire::Duration>,
    ) -> Result<Response<wire::PingResponse>, Status> {
        Err(Status::permission_denied(
            "Testing methods are unavailable.",
        ))
    }
}

#[tonic::async_trait]
impl SnapshotRead for WalletBridge {
    type GetMempoolSnapshotStream = ReadStream<snapshot_wire::SnapshotItem>;

    async fn get_mempool_snapshot(
        &self,
        request: Request<snapshot_wire::SnapshotRequest>,
    ) -> Result<Response<Self::GetMempoolSnapshotStream>, Status> {
        Ok(self.streamed(
            WalletReadRequest::MempoolSnapshot(request.into_inner()),
            |item| match item {
                WalletReadItem::MempoolSnapshot(value) => Ok(value),
                _ => Err(wrong_result()),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zrpc_wallet_read::ReadMethod;

    #[test]
    fn bridge_activity_only_reports_verified_completion_after_full_read() {
        let status = Arc::new(StdMutex::new(WalletBridgeStatus::default()));
        assert_eq!(
            status.lock().unwrap().last_outcome,
            BridgeReadOutcome::NotAttempted
        );
        {
            let _cancelled = ActivityGuard::begin(status.clone()).unwrap();
            let snapshot = *status.lock().unwrap();
            assert!(snapshot.active);
            assert_eq!(snapshot.last_outcome, BridgeReadOutcome::InProgress);
            assert_eq!(snapshot.last_ticket_spent, None);
        }
        let snapshot = *status.lock().unwrap();
        assert!(!snapshot.active);
        assert_eq!(snapshot.last_outcome, BridgeReadOutcome::Unavailable);
        assert_eq!(snapshot.last_ticket_spent, None);
        {
            let mut completed = ActivityGuard::begin(status.clone()).unwrap();
            completed
                .complete(WalletReadCompletion {
                    method: ReadMethod::GetLatestBlock,
                    delivered_items: 1,
                    ticket_spent: true,
                })
                .unwrap();
        }
        let snapshot = *status.lock().unwrap();
        assert!(!snapshot.active);
        assert_eq!(snapshot.last_outcome, BridgeReadOutcome::Completed);
        assert_eq!(snapshot.last_ticket_spent, Some(true));
    }

    #[test]
    fn transaction_absence_is_distinct_from_node_unavailability() {
        assert_eq!(
            status(SafeError::new(
                ErrorCode::WalletTransactionNotFound,
                "synthetic private detail",
            ))
            .code(),
            tonic::Code::NotFound,
        );
        assert_eq!(status(unavailable()).code(), tonic::Code::Unavailable);
    }
    use prost::Message;

    #[test]
    fn local_capability_rejects_missing_wrong_and_browser_metadata() {
        let expected = SecretBytes::new(b"private-one-run-token".to_vec());
        assert_eq!(
            authenticate(Request::new(()), &expected)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let mut wrong = Request::new(());
        wrong
            .metadata_mut()
            .insert("x-zrpc-capability", "wrong".parse().unwrap());
        assert_eq!(
            authenticate(wrong, &expected).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        let mut browser = Request::new(());
        browser.metadata_mut().insert(
            "x-zrpc-capability",
            "private-one-run-token".parse().unwrap(),
        );
        browser
            .metadata_mut()
            .insert("origin", "https://example.org".parse().unwrap());
        assert_eq!(
            authenticate(browser, &expected).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let mut okay = Request::new(());
        okay.metadata_mut().insert(
            "x-zrpc-capability",
            "private-one-run-token".parse().unwrap(),
        );
        assert!(authenticate(okay, &expected).is_ok());
    }

    #[test]
    fn pinned_zebra_compact_wire_preserves_ironwood_for_maintained_scanner() {
        use zcash_client_backend::proto::{
            compact_formats as maintained, service as maintained_service,
        };
        let tx = wire::CompactTx {
            index: 3,
            hash: vec![7; 32],
            ironwood_actions: vec![wire::CompactOrchardAction {
                nullifier: vec![1; 32],
                cmx: vec![2; 32],
                ephemeral_key: vec![3; 32],
                ciphertext: vec![4; 52],
            }],
            ..Default::default()
        };
        let scanned = maintained::CompactTx::decode(tx.encode_to_vec().as_slice()).unwrap();
        assert_eq!(scanned.index, 3);
        assert_eq!(scanned.txid, vec![7; 32]);
        assert_eq!(scanned.ironwood_actions.len(), 1);
        assert_eq!(scanned.ironwood_actions[0].nullifier, vec![1; 32]);
        let request = wire::BlockRange {
            start: Some(wire::BlockId {
                height: 5,
                hash: vec![],
            }),
            end: Some(wire::BlockId {
                height: 6,
                hash: vec![],
            }),
        };
        let maintained =
            maintained_service::BlockRange::decode(request.encode_to_vec().as_slice()).unwrap();
        assert_eq!(maintained.start.unwrap().height, 5);
        assert_eq!(maintained.end.unwrap().height, 6);
        assert!(maintained.pool_types.is_empty());
    }
}
