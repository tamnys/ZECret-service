//! Loopback dashboard. Live mode delegates only to the shared native client.
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use zrpc_client::inspection::{PreviewEndpointConfig, PrivateEndpointConfig};
use zrpc_client::{PrivateClient, Scenario, SimulationClient};
use zrpc_protocol::TestnetTransparentAddress;
use zrpc_verifier::{PhalaTrustedPolicy, ReleasePolicy};
use zrpc_wallet_sdk::bridge::{BridgeReadOutcome, WalletBridge, WalletBridgeStatus};

const MAX_BODY: usize = 16 * 1024; // Design §9 request bound.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'";

#[derive(Clone)]
pub struct LocalSession {
    host: String,
    origin: String,
    bootstrap: Arc<Mutex<Option<String>>>,
    capability: String,
    mode: Arc<DashboardMode>,
}

enum DashboardMode {
    Simulation,
    Live(LiveConfiguration),
    Preview(PreviewConfiguration),
    WalletBridge(WalletBridge),
}

enum LivePolicy {
    Strict(ReleasePolicy),
    PhalaTrusted(PhalaTrustedPolicy),
}

/// These are observations of the current local session, not a cached claim
/// about a future remote connection. A rejected attempt cannot prove which
/// earlier checks succeeded, so it reports them as unverified.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum LiveCheck {
    NotConnected,
    NotChecked,
    NotVerified,
    NotApproved,
}

#[derive(Serialize)]
struct LiveVerification {
    transport: LiveCheck,
    hardware: LiveCheck,
    workload: LiveCheck,
    channel_binding: LiveCheck,
    freshness: LiveCheck,
    release_approval: LiveCheck,
}

impl LiveVerification {
    fn initial() -> Self {
        Self {
            transport: LiveCheck::NotConnected,
            hardware: LiveCheck::NotChecked,
            workload: LiveCheck::NotChecked,
            channel_binding: LiveCheck::NotChecked,
            freshness: LiveCheck::NotChecked,
            release_approval: LiveCheck::NotApproved,
        }
    }

    fn rejected() -> Self {
        Self {
            transport: LiveCheck::NotVerified,
            hardware: LiveCheck::NotVerified,
            workload: LiveCheck::NotVerified,
            channel_binding: LiveCheck::NotVerified,
            freshness: LiveCheck::NotVerified,
            release_approval: LiveCheck::NotApproved,
        }
    }
}

/// Files and endpoint settings are loaded by the native CLI, not the browser.
pub struct LiveConfiguration {
    config: PrivateEndpointConfig,
    collateral: Vec<u8>,
    compose: Vec<u8>,
    policy: LivePolicy,
}

pub struct PreviewConfiguration {
    config: PreviewEndpointConfig,
    collateral: Vec<u8>,
    default_address: TestnetTransparentAddress,
}

impl PreviewConfiguration {
    pub fn new(
        config: PreviewEndpointConfig,
        collateral: Vec<u8>,
        default_address: TestnetTransparentAddress,
    ) -> Self {
        Self {
            config,
            collateral,
            default_address,
        }
    }
}

impl LiveConfiguration {
    pub fn new(
        config: PrivateEndpointConfig,
        collateral: Vec<u8>,
        compose: Vec<u8>,
        policy: ReleasePolicy,
    ) -> Self {
        Self {
            config,
            collateral,
            compose,
            policy: LivePolicy::Strict(policy),
        }
    }

    pub fn new_phala_trusted(
        config: PrivateEndpointConfig,
        collateral: Vec<u8>,
        compose: Vec<u8>,
        policy: PhalaTrustedPolicy,
    ) -> Self {
        Self {
            config,
            collateral,
            compose,
            policy: LivePolicy::PhalaTrusted(policy),
        }
    }
}

fn random_token() -> Result<String, &'static str> {
    let mut bytes = [0; 32]; // 256-bit local capability, using OS CSPRNG.
    getrandom::fill(&mut bytes).map_err(|_| "OS randomness unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl LocalSession {
    pub fn new(address: std::net::SocketAddr) -> Result<Self, &'static str> {
        if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
            return Err("dashboard requires an assigned 127.0.0.1 port");
        }
        Ok(Self {
            host: address.to_string(),
            origin: format!("http://{address}"),
            bootstrap: Arc::new(Mutex::new(Some(random_token()?))),
            capability: random_token()?,
            mode: Arc::new(DashboardMode::Simulation),
        })
    }
    pub fn new_live(
        address: std::net::SocketAddr,
        live: LiveConfiguration,
    ) -> Result<Self, &'static str> {
        let mut session = Self::new(address)?;
        session.mode = Arc::new(DashboardMode::Live(live));
        Ok(session)
    }
    pub fn new_preview(
        address: std::net::SocketAddr,
        preview: PreviewConfiguration,
    ) -> Result<Self, &'static str> {
        let mut session = Self::new(address)?;
        session.mode = Arc::new(DashboardMode::Preview(preview));
        Ok(session)
    }
    pub fn new_wallet_bridge(
        address: std::net::SocketAddr,
        bridge: WalletBridge,
    ) -> Result<Self, &'static str> {
        let mut session = Self::new(address)?;
        session.mode = Arc::new(DashboardMode::WalletBridge(bridge));
        Ok(session)
    }
    /// Deliver only to the deliberate local browser launch, never an application log.
    pub fn bootstrap_url(&self) -> Result<String, &'static str> {
        let guard = self
            .bootstrap
            .lock()
            .map_err(|_| "local session unavailable")?;
        Ok(format!(
            "{}/#{}",
            self.origin,
            guard.as_ref().ok_or("bootstrap consumed")?
        ))
    }
}

fn exactly(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}
fn denied() -> Response {
    (StatusCode::FORBIDDEN, "local request rejected").into_response()
}

async fn boundary(State(session): State<LocalSession>, request: Request, next: Next) -> Response {
    let api = request.uri().path().starts_with("/api/");
    let headers = request.headers();
    let origin_ok = if api || headers.contains_key(header::ORIGIN) {
        exactly(headers, "origin", &session.origin)
    } else {
        true
    };
    let valid = exactly(headers, "host", &session.host)
        && origin_ok
        && !headers.contains_key(header::UPGRADE)
        && (request.uri().query().is_none()
            || (matches!(session.mode.as_ref(), DashboardMode::Preview(_))
                && request.uri().path() == "/api/preview"))
        && (!api || request.method() == Method::POST);
    let authorized = if api && request.uri().path() != "/api/bootstrap" {
        exactly(
            headers,
            "authorization",
            &format!("Bearer {}", session.capability),
        )
    } else {
        true
    };
    let mut response = if valid && authorized {
        next.run(request).await
    } else {
        denied()
    };
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

async fn bootstrap(State(session): State<LocalSession>, headers: HeaderMap) -> Response {
    let Ok(mut token) = session.bootstrap.lock() else {
        return denied();
    };
    let Some(expected) = token.as_ref() else {
        return denied();
    };
    if !exactly(&headers, "authorization", &format!("Bearer {expected}")) {
        return denied();
    }
    *token = None;
    let mode = match session.mode.as_ref() {
        DashboardMode::Simulation => "simulation",
        DashboardMode::Live(live) => match live.policy {
            LivePolicy::Strict(_) => "live_unverified",
            LivePolicy::PhalaTrusted(_) => "phala_trusted_unverified",
        },
        DashboardMode::Preview(_) => "live_testnet_preview",
        DashboardMode::WalletBridge(_) => "wallet_bridge_status",
    };
    let platform = match session.mode.as_ref() {
        DashboardMode::Simulation => None,
        DashboardMode::Live(live) => Some(live.config.platform()),
        DashboardMode::Preview(preview) => Some(preview.config.platform()),
        DashboardMode::WalletBridge(_) => None,
    };
    Json(json!({"capability":session.capability,"mode":mode,"platform":platform})).into_response()
}
async fn query(State(session): State<LocalSession>, request: Request) -> Response {
    if matches!(
        session.mode.as_ref(),
        DashboardMode::Preview(_) | DashboardMode::WalletBridge(_)
    ) {
        return (
            StatusCode::NOT_FOUND,
            "browser query unavailable in this mode",
        )
            .into_response();
    }
    // Retain the local body stream without polling it. In live mode the Rust
    // client must approve the remote connection before it reads the request.
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    if !exactly(&headers, "content-type", "application/json") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json required",
        )
            .into_response();
    }
    if let DashboardMode::Live(live) = session.mode.as_ref() {
        if headers.contains_key("x-zrpc-scenario") {
            return (StatusCode::BAD_REQUEST, "scenario is simulation-only").into_response();
        }
        enum Session {
            Strict(zrpc_client::inspection::VerifiedRpcSession),
            PhalaTrusted(zrpc_client::inspection::PhalaTrustedRpcSession),
        }
        let verified = match &live.policy {
            LivePolicy::Strict(policy) => zrpc_client::inspection::connect_verified(
                &live.config,
                &live.collateral,
                &live.compose,
                policy,
            )
            .await
            .map(Session::Strict),
            LivePolicy::PhalaTrusted(policy) => zrpc_client::inspection::connect_phala_trusted(
                &live.config,
                &live.collateral,
                &live.compose,
                policy,
            )
            .await
            .map(Session::PhalaTrusted),
        };
        let session = match verified {
            Ok(session) => session,
            Err(error) => return Json(json!({"mode":"private_blocked","simulation":false,
                "private_accepted":false,"query_sent":false,"error":error,
                "platform":live.config.platform(),
                "verification":LiveVerification::rejected(),"chain_readiness":"not_checked","result":null})).into_response(),
        };
        let read_body = move || async move {
            to_bytes(body, MAX_BODY)
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|_| {
                    zrpc_protocol::SafeError::new(
                        zrpc_protocol::ErrorCode::RequestTooLarge,
                        "Private request body unavailable or too large.",
                    )
                })
        };
        let result = match session {
            Session::Strict(session) => session.query_from_body_async(read_body).await,
            Session::PhalaTrusted(session) => session.query_from_body_async(read_body).await,
        };
        return match result {
            Ok(result) => Json(
                json!({"mode":match live.policy { LivePolicy::Strict(_) => "private", LivePolicy::PhalaTrusted(_) => "phala_trusted" },"simulation":false,
                "private_accepted":matches!(live.policy,LivePolicy::Strict(_)),
                "phala_trusted_authorized":matches!(live.policy,LivePolicy::PhalaTrusted(_)),
                "trust_model":match live.policy { LivePolicy::Strict(_) => "independent_guest", LivePolicy::PhalaTrusted(_) => "phala_managed_guest_kms_runtime" },
                "platform":live.config.platform(),
                "verification":{"transport":"verified","hardware":"verified","application":"verified","key_binding":"verified","freshness":"verified","release":"approved"},
                "query_sent":true,"error":null,"result":result.result,"chain_context":result.chain_context}),
            )
            .into_response(),
            Err(error) if error.code == zrpc_protocol::ErrorCode::RequestTooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, "request body unavailable").into_response()
            }
            Err(error) if error.code == zrpc_protocol::ErrorCode::TorUnavailable => Json(
                json!({"mode":"private_blocked","simulation":false,
                "private_accepted":false,"query_sent":false,"error":error,"result":null}),
            ).into_response(),
            Err(error) if matches!(error.code,
                zrpc_protocol::ErrorCode::InvalidRequest |
                zrpc_protocol::ErrorCode::MethodNotAllowed |
                zrpc_protocol::ErrorCode::InvalidParameters) => Json(
                    json!({"mode":"private_verified_invalid_request","simulation":false,
                    "private_accepted":false,"query_sent":false,"error":error,"result":null}),
                ).into_response(),
            Err(error) => Json(
                json!({"mode":"private_error","simulation":false,"private_accepted":false,
                "query_sent":"unknown","error":error,"result":null}),
            )
            .into_response(),
        };
    }
    let scenario = headers
        .get("x-zrpc-scenario")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("fixture");
    let Ok(scenario) = scenario.parse::<Scenario>() else {
        return (StatusCode::BAD_REQUEST, "unknown simulation scenario").into_response();
    };
    let body = match to_bytes(body, MAX_BODY).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body unavailable").into_response();
        }
    };
    Json(SimulationClient::query(&body, scenario)).into_response()
}

async fn preview(State(session): State<LocalSession>, request: Request) -> Response {
    let DashboardMode::Preview(config) = session.mode.as_ref() else {
        return (StatusCode::NOT_FOUND, "preview unavailable").into_response();
    };
    let (parts, _body) = request.into_parts();
    let headers = &parts.headers;
    // No body is accepted or polled. Only an address validated by the shared
    // protocol parser can become a typed public Zebra query.
    if headers.contains_key(header::TRANSFER_ENCODING)
        || headers.get_all(header::CONTENT_LENGTH).iter().count() > 1
        || headers
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value != "0")
    {
        return (StatusCode::BAD_REQUEST, "preview takes no request body").into_response();
    }
    let address = match parts.uri.query() {
        Some(query) => match query
            .strip_prefix("address=")
            .and_then(|value| TestnetTransparentAddress::parse(value).ok())
        {
            Some(address) => address,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid testnet transparent address",
                )
                    .into_response();
            }
        },
        None => config.default_address.clone(),
    };
    match zrpc_client::inspection::preview_testnet(&config.config, &config.collateral, &address)
        .await
    {
        Ok(report) => Json(json!({"mode":"live_testnet_preview","simulation":false,
            "platform":config.config.platform(),"private_accepted":false,"query_sent":false,
            "privacy_verification":"unavailable","report":report,"error":null}))
        .into_response(),
        Err(error) => Json(json!({"mode":"live_testnet_preview","simulation":false,
            "platform":config.config.platform(),"private_accepted":false,"query_sent":false,
            "public_query_sent":false,
            "privacy_verification":"unavailable","report":null,"error":error}))
        .into_response(),
    }
}
async fn status(State(session): State<LocalSession>) -> Response {
    match session.mode.as_ref() {
        DashboardMode::Simulation => Json(json!(PrivateClient::new().verify())).into_response(),
        DashboardMode::Live(live) => Json(
            json!({"mode":match live.policy {LivePolicy::Strict(_)=>"live_unverified",LivePolicy::PhalaTrusted(_)=>"phala_trusted_unverified"},"simulation":false,"platform":live.config.platform(),
            "phala_trusted_authorized":false,
            "private_accepted":false,"query_sent":false,"verification":LiveVerification::initial(),
            "chain_readiness":"not_checked","result":null}),
        )
        .into_response(),
        DashboardMode::Preview(preview) => {
            Json(json!({"mode":"live_testnet_preview","simulation":false,
            "platform":preview.config.platform(),
            "private_accepted":false,"query_sent":false,"public_query_sent":false,
            "privacy_verification":"unavailable","report":null,
            "default_address":preview.default_address.as_str(),"error":null}))
            .into_response()
        }
        DashboardMode::WalletBridge(bridge) => match bridge.status() {
            Ok(snapshot) => Json(wallet_bridge_report(snapshot)).into_response(),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "wallet status unavailable")
                .into_response(),
        },
    }
}

fn wallet_bridge_report(snapshot: WalletBridgeStatus) -> serde_json::Value {
    let last_outcome = match snapshot.last_outcome {
        BridgeReadOutcome::NotAttempted => "not_attempted",
        BridgeReadOutcome::InProgress => "in_progress",
        BridgeReadOutcome::Completed => "upstream_read_completed",
        BridgeReadOutcome::Unavailable => "unavailable_or_interrupted",
    };
    json!({
        "mode":"wallet_bridge_status",
        "simulation":false,
        "platform":"phala-dstack",
        "privacy_profile":"phala_trusted",
        "browser_wallet_rpc_sent":false,
        "wallet_bridge":{
            "connection":if snapshot.active {"verifying_or_reading"} else {"no_active_session"},
            "last_read":last_outcome,
            "last_read_verification":if snapshot.last_outcome == BridgeReadOutcome::Completed {
                "passed_for_last_completed_read"
            } else {"not_established"},
            "last_ticket_spent":snapshot.last_ticket_spent,
            "node_sync":snapshot.last_node_observation.map(|node| json!({
                "source":"last_completed_verified_node_read",
                "node_reported_height":node.height,
                "node_estimated_height":node.estimated_height,
                "global_freshness":"not_established"
            })),
            "wallet_scan":snapshot.last_wallet_scan.map(|scan| json!({
                "source":"last_local_reader_report",
                "fully_scanned_height":scan.fully_scanned_height,
                "wallet_tip_height":scan.wallet_tip_height,
                "compact_scan_complete":scan.compact_scan_complete
            }))
        }
    })
}
async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../ui/local/index.html"),
    )
}
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../ui/local/dist/app.js"),
    )
}
async fn style() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../ui/local/style.css"),
    )
}

pub fn dashboard(session: LocalSession) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/style.css", get(style))
        .route("/api/bootstrap", post(bootstrap))
        .route("/api/query", post(query))
        .route("/api/preview", post(preview))
        .route("/api/status", post(status))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(session.clone(), boundary))
        .with_state(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;

    #[test]
    fn wallet_status_never_claims_a_current_verified_connection() {
        let idle = wallet_bridge_report(WalletBridgeStatus::default());
        assert_eq!(idle["wallet_bridge"]["connection"], "no_active_session");
        assert_eq!(
            idle["wallet_bridge"]["last_read_verification"],
            "not_established"
        );
        assert!(idle["wallet_bridge"]["last_ticket_spent"].is_null());
        let completed = wallet_bridge_report(WalletBridgeStatus {
            active: false,
            last_outcome: BridgeReadOutcome::Completed,
            last_ticket_spent: Some(true),
            ..WalletBridgeStatus::default()
        });
        assert_eq!(
            completed["wallet_bridge"]["last_read_verification"],
            "passed_for_last_completed_read"
        );
        assert_eq!(
            completed["wallet_bridge"]["connection"],
            "no_active_session"
        );
        assert!(completed["private_accepted"].is_null());
        assert!(completed["query_sent"].is_null());
        assert_eq!(completed["browser_wallet_rpc_sent"], false);
        let failed = wallet_bridge_report(WalletBridgeStatus {
            active: false,
            last_outcome: BridgeReadOutcome::Unavailable,
            last_ticket_spent: None,
            ..WalletBridgeStatus::default()
        });
        assert_eq!(
            failed["wallet_bridge"]["last_read_verification"],
            "not_established"
        );
        assert!(failed["wallet_bridge"]["last_ticket_spent"].is_null());
    }

    #[test]
    fn wallet_status_keeps_node_and_local_scan_progress_distinct() {
        let report = wallet_bridge_report(WalletBridgeStatus {
            last_node_observation: Some(zrpc_wallet_sdk::NodeObservation {
                height: 120,
                estimated_height: Some(125),
            }),
            last_wallet_scan: Some(zrpc_wallet_sdk::bridge::WalletScanProgress {
                fully_scanned_height: 118,
                wallet_tip_height: 120,
                compact_scan_complete: false,
            }),
            ..WalletBridgeStatus::default()
        });
        assert_eq!(
            report["wallet_bridge"]["node_sync"]["node_reported_height"],
            120
        );
        assert_eq!(
            report["wallet_bridge"]["node_sync"]["node_estimated_height"],
            125
        );
        assert_eq!(
            report["wallet_bridge"]["node_sync"]["global_freshness"],
            "not_established"
        );
        assert_eq!(
            report["wallet_bridge"]["wallet_scan"]["fully_scanned_height"],
            118
        );
        assert_eq!(
            report["wallet_bridge"]["wallet_scan"]["wallet_tip_height"],
            120
        );
        assert_eq!(
            report["wallet_bridge"]["wallet_scan"]["compact_scan_complete"],
            false
        );
        assert_eq!(report["wallet_bridge"]["connection"], "no_active_session");
        assert!(report["private_accepted"].is_null());
    }

    fn session() -> LocalSession {
        LocalSession::new("127.0.0.1:32123".parse().unwrap()).unwrap()
    }
    fn call(path: &str, host: &str, origin: &str, token: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("host", host)
            .header("origin", origin)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#,
            ))
            .unwrap()
    }
    #[tokio::test]
    async fn ui_authorization_and_core_parity() {
        let state = session();
        let app = dashboard(state.clone());
        for (host, origin, token) in [
            (
                "evil.test:32123",
                state.origin.as_str(),
                state.capability.as_str(),
            ),
            (
                state.host.as_str(),
                "https://evil.test",
                state.capability.as_str(),
            ),
            (state.host.as_str(), state.origin.as_str(), ""),
            (state.host.as_str(), "null", state.capability.as_str()),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(call("/api/query", host, origin, token))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let response = app
            .oneshot(call(
                "/api/query",
                &state.host,
                &state.origin,
                &state.capability,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let expected = SimulationClient::query(
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#,
            "fixture".parse().unwrap(),
        );
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result, serde_json::to_value(expected).unwrap());
    }
    #[tokio::test]
    async fn bootstrap_is_single_use_and_api_is_post_only() {
        let state = session();
        let app = dashboard(state.clone());
        let token = state.bootstrap.lock().unwrap().clone().unwrap();
        let first = app
            .clone()
            .oneshot(call("/api/bootstrap", &state.host, &state.origin, &token))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            app.clone()
                .oneshot(call("/api/bootstrap", &state.host, &state.origin, &token))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        *request.method_mut() = Method::GET;
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn excessive_body_and_duplicate_host_are_rejected() {
        let state = session();
        let app = dashboard(state.clone());
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        *request.body_mut() = Body::from(vec![b' '; MAX_BODY + 1]);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        request
            .headers_mut()
            .append(header::HOST, HeaderValue::from_static("evil.test"));
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn live_dashboard_uses_empty_reviewed_catalog_and_never_queries() {
        for platform in [
            zrpc_protocol::Backend::PhalaDstack,
            zrpc_protocol::Backend::GcpTdx,
        ] {
            let live = LiveConfiguration::new(
                PrivateEndpointConfig::for_platform(
                    platform,
                    "192.0.2.1",
                    443,
                    "/missing/local/tor",
                )
                .unwrap(),
                b"{}".to_vec(),
                if platform == zrpc_protocol::Backend::PhalaDstack {
                    b"{}".to_vec()
                } else {
                    Vec::new()
                },
                ReleasePolicy::default(),
            );
            let state = LocalSession::new_live("127.0.0.1:32123".parse().unwrap(), live).unwrap();
            let app = dashboard(state.clone());
            let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
            // Rejection must happen before the live handler reads even an
            // oversized private body. The simulation route still enforces its
            // normal local body limit.
            *request.body_mut() = Body::from(vec![b'X'; MAX_BODY + 1]);
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
            let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(report["mode"], "private_blocked");
            assert_eq!(report["query_sent"], false);
            assert_eq!(report["private_accepted"], false);
            assert_eq!(report["simulation"], false);
            assert_eq!(report["error"]["code"], "unknown_release");
            assert_eq!(report["platform"], serde_json::to_value(platform).unwrap());
            assert_eq!(report["verification"]["hardware"], "not_verified");
            assert_eq!(report["verification"]["workload"], "not_verified");
            assert_eq!(report["verification"]["channel_binding"], "not_verified");
            assert_eq!(report["verification"]["release_approval"], "not_approved");
        }
    }
    #[tokio::test]
    async fn phala_trusting_dashboard_rejects_before_reading_private_body() {
        let live = LiveConfiguration::new_phala_trusted(
            PrivateEndpointConfig::for_platform(
                zrpc_protocol::Backend::PhalaDstack,
                "192.0.2.1",
                443,
                "/missing/local/tor",
            )
            .unwrap(),
            b"{}".to_vec(),
            b"{}".to_vec(),
            PhalaTrustedPolicy::default(),
        );
        let state = LocalSession::new_live("127.0.0.1:32123".parse().unwrap(), live).unwrap();
        let app = dashboard(state.clone());
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        *request.body_mut() = Body::from(vec![b'X'; MAX_BODY + 1]);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["error"]["code"], "unknown_release");
        assert_eq!(report["query_sent"], false);
        assert_eq!(report["private_accepted"], false);
        let status = app
            .oneshot(call(
                "/api/status",
                &state.host,
                &state.origin,
                &state.capability,
            ))
            .await
            .unwrap();
        let status = to_bytes(status.into_body(), MAX_BODY).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["mode"], "phala_trusted_unverified");
        assert_eq!(status["phala_trusted_authorized"], false);
    }
    #[tokio::test]
    async fn preview_dashboard_rejects_request_bodies_and_private_query_route() {
        let config =
            PreviewEndpointConfig::for_phala("fixture.invalid", 443, "/missing/local/tor").unwrap();
        let preview = PreviewConfiguration::new(
            config,
            b"{}".to_vec(),
            TestnetTransparentAddress::parse(zrpc_protocol::PREVIEW_TESTNET_ADDRESS).unwrap(),
        );
        let state = LocalSession::new_preview("127.0.0.1:32123".parse().unwrap(), preview).unwrap();
        let app = dashboard(state.clone());
        let mut private = call("/api/query", &state.host, &state.origin, &state.capability);
        *private.body_mut() = Body::from("SYNTHETIC_PRIVATE_MARKER");
        assert_eq!(
            app.clone().oneshot(private).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let mut arbitrary = call(
            "/api/preview",
            &state.host,
            &state.origin,
            &state.capability,
        );
        arbitrary
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("2"));
        assert_eq!(
            app.clone().oneshot(arbitrary).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        for uri in [
            "/api/preview?address=t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            "/api/preview?address=tmArbitraryAddress",
            "/api/preview?method=sendrawtransaction",
            "/api/preview?address=tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3&method=getblockcount",
        ] {
            let invalid = call(uri, &state.host, &state.origin, &state.capability);
            assert_eq!(
                app.clone().oneshot(invalid).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
        }
        let supplied = call(
            "/api/preview?address=tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            &state.host,
            &state.origin,
            &state.capability,
        );
        let supplied_response = app.clone().oneshot(supplied).await.unwrap();
        assert_eq!(supplied_response.status(), StatusCode::OK);
        let supplied_body = to_bytes(supplied_response.into_body(), MAX_BODY)
            .await
            .unwrap();
        let supplied_report: serde_json::Value = serde_json::from_slice(&supplied_body).unwrap();
        assert_eq!(supplied_report["error"]["code"], "tor_unavailable");
        let empty = Request::builder()
            .method("POST")
            .uri("/api/preview")
            .header("host", &state.host)
            .header("origin", &state.origin)
            .header("authorization", format!("Bearer {}", state.capability))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(empty).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["mode"], "live_testnet_preview");
        assert_eq!(report["private_accepted"], false);
        assert_eq!(report["query_sent"], false);
        assert_eq!(report["public_query_sent"], false);
        assert!(report["report"].is_null());
        assert_eq!(report["error"]["code"], "tor_unavailable");
        assert!(!String::from_utf8_lossy(&body).contains("SYNTHETIC_PRIVATE_MARKER"));
    }
    #[tokio::test]
    async fn live_status_reports_separate_unverified_gates_without_network() {
        for platform in [
            zrpc_protocol::Backend::GcpTdx,
            zrpc_protocol::Backend::PhalaDstack,
        ] {
            let live = LiveConfiguration::new(
                PrivateEndpointConfig::for_platform(
                    platform,
                    "192.0.2.1",
                    443,
                    "/missing/local/tor",
                )
                .unwrap(),
                b"{}".to_vec(),
                if platform == zrpc_protocol::Backend::PhalaDstack {
                    b"{}".to_vec()
                } else {
                    Vec::new()
                },
                ReleasePolicy::default(),
            );
            let state = LocalSession::new_live("127.0.0.1:32123".parse().unwrap(), live).unwrap();
            let app = dashboard(state.clone());
            let response = app
                .oneshot(call(
                    "/api/status",
                    &state.host,
                    &state.origin,
                    &state.capability,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
            let report: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(report["mode"], "live_unverified");
            assert_eq!(report["platform"], serde_json::to_value(platform).unwrap());
            assert_eq!(report["private_accepted"], false);
            assert_eq!(report["query_sent"], false);
            assert_eq!(report["verification"]["transport"], "not_connected");
            for check in ["hardware", "workload", "channel_binding", "freshness"] {
                assert_eq!(report["verification"][check], "not_checked");
            }
            assert_eq!(report["verification"]["release_approval"], "not_approved");
        }
    }
    #[test]
    fn refuses_public_bind_address() {
        assert!(LocalSession::new("0.0.0.0:3000".parse().unwrap()).is_err());
        assert!(LocalSession::new("[::1]:3000".parse().unwrap()).is_err());
    }
}
