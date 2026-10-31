use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use dolphi::{
    Limits, Owner,
    http::{HttpConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

async fn call(
    app: &Router,
    path: &str,
    token: Option<&str>,
    input: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .uri(path)
        .header("host", "127.0.0.1:8787");
    request = if input.is_some() {
        request
            .method("POST")
            .header("content-type", "application/json")
    } else {
        request.method("GET")
    };
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(input.map_or(String::new(), |v| v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn app(owner: Owner) -> Router {
    router(
        owner,
        HttpConfig {
            authority: "127.0.0.1:8787".into(),
            requests_per_minute: 1000,
        },
    )
}

#[tokio::test]
async fn retry_routes_are_scoped_strict_and_return_stable_results() {
    let owner = Owner::open(":memory:").await.unwrap();
    let (a, token) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let (_, other) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let admin = owner
        .issue_owner_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let app = app(owner);
    let payload = json!({"key":"key","value":"value","operation_id":"http-retry"});
    let (status, first) = call(
        &app,
        "/v1/proposals/create",
        Some(token.expose_secret()),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(
            &app,
            "/v1/proposals/create",
            Some(token.expose_secret()),
            Some(payload)
        )
        .await
        .1,
        first
    );
    assert_eq!(
        call(
            &app,
            "/v1/proposals/create",
            Some(token.expose_secret()),
            Some(json!({"key":"key","value":"different","operation_id":"http-retry"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    for secret in [other.expose_secret(), admin.expose_secret()] {
        assert!(
            call(
                &app,
                "/v1/operations/status",
                Some(secret),
                Some(json!({"id":"http-retry"}))
            )
            .await
            .1["operation"]
                .is_null()
        );
    }
    let receipt = call(
        &app,
        "/v1/operations/status",
        Some(token.expose_secret()),
        Some(json!({"id":"http-retry"})),
    )
    .await
    .1;
    assert_eq!(receipt["operation"]["status"], "committed");
    assert_eq!(receipt["operation"]["result"], first);
    for operation_id in [Value::Null, json!(12), json!(""), json!("bad\n")] {
        assert_eq!(
            call(
                &app,
                "/v1/memory/remember",
                Some(token.expose_secret()),
                Some(json!({"key":"key","value":"value","operation_id":operation_id}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(
            &app,
            "/v1/operations/status",
            Some(other.expose_secret()),
            Some(json!({"id":"http-retry","agent_id":a}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "/v1/admin/agents",
            Some(admin.expose_secret()),
            Some(json!({"ttl_seconds":300,"operation_id":"unsupported"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn api_isolates_agents_and_requires_explicit_owner_review() {
    let owner = Owner::open(":memory:").await.unwrap();
    let administrator = owner
        .issue_owner_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let app = app(owner.clone());
    let (_, a) = call(
        &app,
        "/v1/admin/agents",
        Some(administrator.expose_secret()),
        Some(json!({"ttl_seconds":300})),
    )
    .await;
    let (_, b) = call(
        &app,
        "/v1/admin/agents",
        Some(administrator.expose_secret()),
        Some(json!({"ttl_seconds":300})),
    )
    .await;
    let a = a["secret"].as_str().unwrap();
    let b = b["secret"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "/v1/memory/remember",
            Some(a),
            Some(json!({"key":"secret","value":"alice"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "/v1/memory/recall",
            Some(b),
            Some(json!({"key":"secret"}))
        )
        .await
        .1["value"],
        Value::Null
    );
    let (_, proposal) = call(
        &app,
        "/v1/proposals/create",
        Some(a),
        Some(json!({"key":"stock","value":"12"})),
    )
    .await;
    let id = proposal["id"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "/v1/shared/read",
            Some(b),
            Some(json!({"key":"stock"}))
        )
        .await
        .1["value"],
        Value::Null
    );
    assert_eq!(
        call(
            &app,
            "/v1/admin/proposals/approve",
            Some(a),
            Some(json!({"id":id}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "/v1/admin/proposals/approve",
            Some(administrator.expose_secret()),
            Some(json!({"id":id}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "/v1/shared/read",
            Some(b),
            Some(json!({"key":"stock"}))
        )
        .await
        .1["value"]["value"],
        "12"
    );
    assert_eq!(
        call(
            &app,
            "/v1/admin/proposals/approve",
            Some(administrator.expose_secret()),
            Some(json!({"id":id}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn missing_forged_revoked_and_spoofed_identity_requests_fail() {
    let owner = Owner::open(":memory:").await.unwrap();
    let (id, token) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let app = app(owner.clone());
    for bearer in [None, Some("owner"), Some(id.as_str())] {
        assert_eq!(
            call(&app, "/v1/me", bearer, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(
            &app,
            "/v1/memory/remember",
            Some(token.expose_secret()),
            Some(json!({"key":"k","value":"v","agent_id":"victim"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for path in [
        "/v1/admin/agents",
        "/v1/admin/audit",
        "/v1/admin/credentials/issue",
        "/v1/admin/credentials/revoke",
        "/v1/admin/agents/revoke",
        "/v1/admin/proposals/inspect",
        "/v1/admin/proposals/approve",
        "/v1/admin/proposals/reject",
    ] {
        assert_eq!(
            call(&app, path, Some(token.expose_secret()), Some(json!({})))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    owner.revoke_credential(token.id()).await.unwrap();
    assert_eq!(
        call(&app, "/v1/me", Some(token.expose_secret()), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn host_origin_query_duplicate_auth_body_and_json_guards_fail_closed() {
    let owner = Owner::open(":memory:").await.unwrap();
    let (_, token) = owner
        .create_agent_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let app = app(owner);
    for (name, value, expected) in [
        ("host", "evil.example", StatusCode::MISDIRECTED_REQUEST),
        ("origin", "https://evil.example", StatusCode::FORBIDDEN),
    ] {
        let mut req = Request::builder()
            .method("GET")
            .uri("/v1/me")
            .header("host", "127.0.0.1:8787")
            .header("authorization", format!("Bearer {}", token.expose_secret()))
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(name, value.parse().unwrap());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
    }
    assert_eq!(
        call(
            &app,
            "/v1/me?token=secret",
            Some(token.expose_secret()),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for (body, expected) in [
        ("{".to_owned(), StatusCode::BAD_REQUEST),
        ("x".repeat(96 * 1024 + 1), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/memory/remember")
            .header("host", "127.0.0.1:8787")
            .header("authorization", format!("Bearer {}", token.expose_secret()))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
    }
    let req = Request::builder()
        .uri("/v1/me")
        .header("host", "127.0.0.1:8787")
        .header("authorization", "Bearer a")
        .header("authorization", "Bearer b")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn denied_attempts_consume_ingress_budget() {
    let app = router(
        Owner::open(":memory:").await.unwrap(),
        HttpConfig {
            authority: "127.0.0.1:8787".into(),
            requests_per_minute: 1,
        },
    );
    assert_eq!(
        call(&app, "/v1/me", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "/v1/me", None, None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn provisioning_failure_is_atomic_and_audit_pages_are_bounded() {
    let owner = Owner::open_with_limits(
        ":memory:",
        Limits {
            audit_events: 2,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let token = owner
        .issue_owner_credential(Duration::from_secs(300))
        .await
        .unwrap();
    let app = app(owner.clone());
    assert_eq!(
        call(
            &app,
            "/v1/admin/agents",
            Some(token.expose_secret()),
            Some(json!({"ttl_seconds":300}))
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(owner.audit().await.unwrap().len(), 1);
    owner.update_limits(Limits::default()).await.unwrap();
    let (_, first) = call(
        &app,
        "/v1/admin/audit",
        Some(token.expose_secret()),
        Some(json!({"after":0,"limit":1})),
    )
    .await;
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(
            &app,
            "/v1/admin/audit",
            Some(token.expose_secret()),
            Some(json!({"after":0,"limit":1001}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        owner
            .audit()
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "agent.created")
            .count(),
        0
    );
}
