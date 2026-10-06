//! In-process Tonic transport for the same verified wallet reader services.

use super::*;
use std::{
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};
use tonic::{
    body::Body,
    codegen::{BoxFuture, Service, StdError, http},
    service::Routes,
    transport::Channel,
};

#[derive(Clone)]
enum Transport {
    Loopback(Channel),
    Embedded(Routes),
}

/// Transport shared by the local and embedded generated clients. Its
/// constructors are private: callers cannot replace the verified reader.
#[derive(Clone)]
pub struct WalletTransport(Transport);

impl WalletTransport {
    pub(super) fn loopback(channel: Channel) -> Self {
        Self(Transport::Loopback(channel))
    }

    fn embedded(routes: Routes) -> Self {
        Self(Transport::Embedded(routes.prepare()))
    }
}

impl Service<http::Request<Body>> for WalletTransport {
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.0 {
            Transport::Loopback(channel) => channel.poll_ready(cx).map_err(Into::into),
            Transport::Embedded(routes) => {
                <Routes as Service<http::Request<Body>>>::poll_ready(routes, cx).map_err(Into::into)
            }
        }
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        match &mut self.0 {
            Transport::Loopback(channel) => {
                let response = channel.call(request);
                Box::pin(async move { response.await.map_err(Into::into) })
            }
            Transport::Embedded(routes) => {
                let response = routes.call(request);
                Box::pin(async move { response.await.map_err(Into::into) })
            }
        }
    }
}

/// A maintained-scanner adapter with no listener, TCP connection, capability
/// file or wallet database. The capability and generated gRPC services stay
/// in memory; upstream reads still use `WalletReader`'s Tor, verification and
/// ticket path. Streaming uses the same bounded delivery and cancellation.
pub struct EmbeddedWalletAdapter(WalletAdapter);

impl EmbeddedWalletAdapter {
    pub fn new(reader: WalletReader) -> Result<Self, SafeError> {
        let (bridge, capability) = WalletBridge::new(reader)?;
        let read_capability = bridge.capability.clone();
        let snapshot_capability = bridge.capability.clone();
        let status_capability = bridge.capability.clone();
        let routes = Routes::new(CompactTxStreamerServer::with_interceptor(
            bridge.clone(),
            move |request| authenticate(request, &read_capability),
        ))
        .add_service(SnapshotReadServer::with_interceptor(
            bridge.clone(),
            move |request| authenticate(request, &snapshot_capability),
        ))
        .add_service(LocalStatusServer::with_interceptor(
            bridge,
            move |request| authenticate(request, &status_capability),
        ));
        Ok(Self(WalletAdapter::from_transport(
            WalletTransport::embedded(routes),
            capability,
        )))
    }

    /// Use either adapter with the same generated clients and maintained
    /// `sync::run` call; no transport-specific wallet logic is needed.
    pub fn into_adapter(self) -> WalletAdapter {
        self.0
    }
}

impl Deref for EmbeddedWalletAdapter {
    type Target = WalletAdapter;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EmbeddedWalletAdapter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    // Synthetic framing/authentication fixture only. It cannot create a
    // WalletReader, approve a quote or perform an upstream read.
    #[derive(Clone)]
    struct ScanReports;

    #[tonic::async_trait]
    impl LocalStatus for ScanReports {
        async fn report_scan_progress(
            &self,
            request: Request<local_status_wire::ScanProgress>,
        ) -> Result<Response<local_status_wire::ScanProgressAck>, Status> {
            checked_scan_progress(request.into_inner())?;
            Ok(Response::new(local_status_wire::ScanProgressAck {}))
        }
    }

    fn fixture() -> (WalletTransport, SecretBytes) {
        let capability = b"synthetic-memory-capability".to_vec();
        let expected = Arc::new(SecretBytes::new(capability.clone()));
        let service = LocalStatusServer::with_interceptor(ScanReports, move |request| {
            authenticate(request, &expected)
        });
        (
            WalletTransport::embedded(Routes::new(service)),
            SecretBytes::new(capability),
        )
    }

    fn progress() -> local_status_wire::ScanProgress {
        local_status_wire::ScanProgress {
            fully_scanned_height: 40,
            wallet_tip_height: 42,
            compact_scan_complete: false,
        }
    }

    #[tokio::test]
    async fn in_process_services_require_capability_and_reject_browser_origin() {
        let (transport, capability) = fixture();
        let mut unauthenticated =
            local_status_wire::local_status_client::LocalStatusClient::new(transport.clone());
        assert_eq!(
            unauthenticated
                .report_scan_progress(progress())
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated,
        );
        let adapter = WalletAdapter::from_transport(transport, capability);
        let mut authenticated =
            local_status_wire::local_status_client::LocalStatusClient::with_interceptor(
                adapter.transport.clone(),
                adapter.interceptor.clone(),
            );
        let mut browser = Request::new(progress());
        browser
            .metadata_mut()
            .insert("origin", "https://fixture.invalid".parse().unwrap());
        assert_eq!(
            authenticated
                .report_scan_progress(browser)
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied,
        );
        adapter
            .report_scan_progress(WalletScanProgress {
                fully_scanned_height: 40,
                wallet_tip_height: 42,
                compact_scan_complete: false,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn in_process_transport_preserves_generated_rpc_errors() {
        let (transport, capability) = fixture();
        let mut adapter = WalletAdapter::from_transport(transport, capability);
        let mut status =
            local_status_wire::local_status_client::LocalStatusClient::with_interceptor(
                adapter.transport.clone(),
                adapter.interceptor.clone(),
            );
        let mut invalid = progress();
        invalid.fully_scanned_height = 43;
        assert_eq!(
            status
                .report_scan_progress(invalid)
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument,
        );
        // The synthetic service has no submission or read route. The in-memory
        // router retains Tonic's unavailable-method response, without any
        // fallback to a network connection or an upstream wallet reader.
        assert_eq!(
            adapter
                .client()
                .send_transaction(wire::RawTransaction::default())
                .await
                .unwrap_err()
                .code(),
            Code::Unimplemented,
        );
        assert_eq!(
            adapter
                .maintained_scanner_client()
                .get_latest_block(zcash_client_backend::proto::service::ChainSpec::default())
                .await
                .unwrap_err()
                .code(),
            Code::Unimplemented,
        );
    }
}
