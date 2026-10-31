//! Loopback HTTP adapter. Never exposes bootstrap capabilities to callers.
use crate::{Authenticated, Error, Owner};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct HttpConfig {
    /// Exact HTTP Host authority, e.g. 127.0.0.1:8787.
    pub authority: String,
    /// Includes unauthenticated, malformed and denied requests. Per process.
    pub requests_per_minute: u64,
}

#[derive(Clone)]
struct Service {
    owner: Owner,
    config: HttpConfig,
    ingress: Arc<Mutex<(Instant, u64)>>,
}

fn response(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": {"code": code}}))).into_response()
}

fn mapped(error: Error) -> Response {
    let (status, code) = match error {
        Error::Authentication => (StatusCode::UNAUTHORIZED, "unauthorized"),
        Error::Revoked => (StatusCode::FORBIDDEN, "revoked"),
        Error::Quota => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
        Error::InvalidInput | Error::Configuration => (StatusCode::BAD_REQUEST, "invalid_request"),
        Error::UnknownAgent | Error::UnknownProposal => (StatusCode::NOT_FOUND, "not_found"),
        Error::Conflict | Error::AlreadyReviewed | Error::OperationConflict => {
            (StatusCode::CONFLICT, "conflict")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    response(status, code)
}

/// Validates local Host, denies browser Origins, and bounds ALL request attempts.
async fn guard(State(service): State<Service>, request: Request, next: Next) -> Response {
    let result = async {
        let allowed = match service.ingress.lock() {
            Ok(mut window) => {
                if window.0.elapsed() >= Duration::from_secs(60) {
                    *window = (Instant::now(), 0);
                }
                window.1 += 1;
                window.1 <= service.config.requests_per_minute
            }
            Err(_) => false,
        };
        if !allowed {
            return response(StatusCode::TOO_MANY_REQUESTS, "request_limit");
        }
        if request.headers().get_all(header::HOST).iter().count() != 1
            || request
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                != Some(service.config.authority.as_str())
        {
            return response(StatusCode::MISDIRECTED_REQUEST, "invalid_host");
        }
        if request.headers().contains_key(header::ORIGIN) {
            return response(StatusCode::FORBIDDEN, "origin_denied");
        }
        if request.uri().query().is_some() {
            return response(StatusCode::BAD_REQUEST, "query_not_supported");
        }
        match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await {
            Ok(response) => response,
            Err(_) => response(StatusCode::REQUEST_TIMEOUT, "timeout"),
        }
    }
    .await;
    let (mut parts, body) = result.into_parts();
    parts
        .headers
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    parts
        .headers
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    Response::from_parts(parts, body)
}

/// Generic JSON dispatch keeps deserialization errors and storage details private.
async fn dispatch(State(service): State<Service>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if path == "/health" {
        return Json(json!({"status":"ok"})).into_response();
    }
    if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        return response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Some(secret) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    else {
        return response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let authenticated = match service.owner.authenticate(secret).await {
        Ok(value) => value,
        Err(error) => return mapped(error),
    };
    if path == "/v1/me" {
        return Json(match authenticated {
            Authenticated::Owner(_) => json!({"role":"owner"}),
            Authenticated::Agent(agent) => json!({"role":"agent", "agent_id":agent.id()}),
        })
        .into_response();
    }
    if path.starts_with("/v1/admin/") && !matches!(&authenticated, Authenticated::Owner(_)) {
        return response(StatusCode::FORBIDDEN, "forbidden");
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_none_or(|h| h.split(';').next() != Some("application/json"))
    {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    let bytes = match axum::body::to_bytes(request.into_body(), 96 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return response(StatusCode::PAYLOAD_TOO_LARGE, "body_limit"),
    };
    let input: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return response(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    match operation(authenticated, &path, input).await {
        Ok(value) => Json(value).into_response(),
        Err(ApiError::Core(error)) => mapped(error),
        Err(ApiError::Invalid) => response(StatusCode::BAD_REQUEST, "invalid_request"),
        Err(ApiError::Forbidden) => response(StatusCode::FORBIDDEN, "forbidden"),
    }
}

enum ApiError {
    Core(Error),
    Invalid,
    Forbidden,
}
impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}
fn parse<T: serde::de::DeserializeOwned>(input: Value) -> Result<T, ApiError> {
    serde_json::from_value(input).map_err(|_| ApiError::Invalid)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    key: String,
    value: String,
    #[serde(default, deserialize_with = "provided_operation_id")]
    operation_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationId {
    id: String,
    #[serde(default, deserialize_with = "provided_operation_id")]
    operation_id: Option<String>,
}
fn provided_operation_id<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(value).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    ttl_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    agent_id: String,
    ttl_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    after: i64,
    limit: u32,
}

async fn operation(principal: Authenticated, path: &str, input: Value) -> Result<Value, ApiError> {
    match (principal, path) {
        (Authenticated::Agent(agent), "/v1/memory/remember") => {
            let body: Write = parse(input)?;
            match body.operation_id {
                Some(id) => agent.remember_once(&id, &body.key, &body.value).await?,
                None => agent.remember(&body.key, &body.value).await?,
            }
            Ok(json!({"ok":true}))
        }
        (Authenticated::Agent(agent), "/v1/memory/recall") => {
            let body: Key = parse(input)?;
            Ok(json!({"value":agent.recall(&body.key).await?}))
        }
        (Authenticated::Agent(agent), "/v1/proposals/create") => {
            let body: Write = parse(input)?;
            let id = match body.operation_id {
                Some(id) => agent.propose_once(&id, &body.key, &body.value).await?,
                None => agent.propose(&body.key, &body.value).await?,
            };
            Ok(json!({"id":id}))
        }
        (Authenticated::Agent(agent), "/v1/shared/read") => {
            let body: Key = parse(input)?;
            Ok(json!({"value":agent.read_shared(&body.key).await?}))
        }
        (Authenticated::Owner(owner), "/v1/shared/read") => {
            let body: Key = parse(input)?;
            Ok(json!({"value":owner.read_shared(&body.key).await?}))
        }
        (Authenticated::Owner(owner), "/v1/admin/agents") => {
            let body: Create = parse(input)?;
            if body.ttl_seconds == 0 || body.ttl_seconds > 30 * 86400 {
                return Err(ApiError::Invalid);
            }
            let (agent_id, credential) = owner
                .create_agent_credential(Duration::from_secs(body.ttl_seconds))
                .await?;
            Ok(
                json!({"agent_id":agent_id, "credential_id":credential.id(), "secret":credential.expose_secret()}),
            )
        }
        (Authenticated::Owner(owner), "/v1/admin/credentials/issue") => {
            let body: Issue = parse(input)?;
            let credential = owner
                .issue_agent_credential(&body.agent_id, Duration::from_secs(body.ttl_seconds))
                .await?;
            Ok(json!({"credential_id":credential.id(), "secret":credential.expose_secret()}))
        }
        (Authenticated::Owner(owner), "/v1/admin/credentials/revoke") => {
            let body: MutationId = parse(input)?;
            match body.operation_id {
                Some(id) => owner.revoke_credential_once(&id, &body.id).await?,
                None => owner.revoke_credential(&body.id).await?,
            }
            Ok(json!({"ok":true}))
        }
        (Authenticated::Owner(owner), "/v1/admin/agents/revoke") => {
            let body: MutationId = parse(input)?;
            match body.operation_id {
                Some(id) => owner.revoke_agent_once(&id, &body.id).await?,
                None => owner.revoke_agent(&body.id).await?,
            }
            Ok(json!({"ok":true}))
        }
        (Authenticated::Owner(owner), "/v1/admin/proposals/inspect") => {
            let body: Id = parse(input)?;
            Ok(json!({"proposal":owner.inspect(&body.id).await?}))
        }
        (Authenticated::Owner(owner), "/v1/admin/proposals/approve") => {
            let body: MutationId = parse(input)?;
            match body.operation_id {
                Some(id) => owner.approve_once(&id, &body.id).await?,
                None => owner.approve(&body.id).await?,
            }
            Ok(json!({"ok":true}))
        }
        (Authenticated::Owner(owner), "/v1/admin/proposals/reject") => {
            let body: MutationId = parse(input)?;
            match body.operation_id {
                Some(id) => owner.reject_once(&id, &body.id).await?,
                None => owner.reject(&body.id).await?,
            }
            Ok(json!({"ok":true}))
        }
        (Authenticated::Owner(owner), "/v1/admin/audit") => {
            let body: Audit = parse(input)?;
            Ok(json!({"events":owner.audit_page(body.after, body.limit).await?}))
        }
        (Authenticated::Agent(agent), "/v1/operations/status") => {
            let body: Id = parse(input)?;
            Ok(json!({"operation":agent.operation_status(&body.id).await?}))
        }
        (Authenticated::Owner(owner), "/v1/operations/status") => {
            let body: Id = parse(input)?;
            Ok(json!({"operation":owner.operation_status(&body.id).await?}))
        }
        _ => Err(ApiError::Forbidden),
    }
}

pub fn router(owner: Owner, config: HttpConfig) -> Router {
    let state = Service {
        owner,
        config,
        ingress: Arc::new(Mutex::new((Instant::now(), 0))),
    };
    Router::new()
        .route("/health", get(dispatch))
        .route("/v1/me", get(dispatch))
        .route("/v1/memory/remember", post(dispatch))
        .route("/v1/memory/recall", post(dispatch))
        .route("/v1/proposals/create", post(dispatch))
        .route("/v1/shared/read", post(dispatch))
        .route("/v1/operations/status", post(dispatch))
        .route("/v1/admin/agents", post(dispatch))
        .route("/v1/admin/credentials/issue", post(dispatch))
        .route("/v1/admin/credentials/revoke", post(dispatch))
        .route("/v1/admin/agents/revoke", post(dispatch))
        .route("/v1/admin/proposals/inspect", post(dispatch))
        .route("/v1/admin/proposals/approve", post(dispatch))
        .route("/v1/admin/proposals/reject", post(dispatch))
        .route("/v1/admin/audit", post(dispatch))
        .fallback(|| async { response(StatusCode::NOT_FOUND, "not_found") })
        .method_not_allowed_fallback(|| async {
            response(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(DefaultBodyLimit::max(96 * 1024))
        .layer(tower::limit::ConcurrencyLimitLayer::new(32))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Bound accepted connections and header/body lifetime, including slow clients
/// that never reach application middleware. Cleartext listeners MUST be loopback.
pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cleartext listener must be loopback",
        ));
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(128));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { drop(stream); continue; };
                let app = app.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .max_headers(32).max_buf_size(128*1024).keep_alive(false);
                    let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_util::service::TowerToHyperService::new(app));
                    let _ = tokio::time::timeout(Duration::from_secs(15), connection).await;
                });
            }
        }
    }
    if tokio::time::timeout(Duration::from_secs(15), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    Ok(())
}
