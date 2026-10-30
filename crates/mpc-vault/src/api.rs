//! The HTTP layer: 127.0.0.1 only, bearer token, JSON in and out.
//! No logic lives here; every route calls the engine.
use crate::engine::*;
use crate::util::ct_eq;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, RawQuery, Request, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

pub struct Api {
    pub engine: Engine,
    pub token: Vec<u8>,
    pub port: u16,
    pub ui_dir: Option<PathBuf>,
}
type Shared = Arc<Api>;

fn respond(status: u16, body: Vec<u8>, content_type: &str) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("content-security-policy", HeaderValue::from_static(
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"));
    r
}

fn json_ok<T: Serialize>(status: u16, v: &T) -> Response {
    respond(status, serde_json::to_vec(v).unwrap_or_default(), "application/json")
}

fn error(status: u16, code: &str, message: &str, action: &str) -> Response {
    json_ok(status, &json!({"error": {"code": code, "message": message, "action": action}}))
}

fn fail(e: ApiError) -> Response { error(e.status, e.code, &e.message, &e.action) }

fn out<T: Serialize>(status: u16, r: Result<T, ApiError>) -> Response {
    match r { Ok(v) => json_ok(status, &v), Err(e) => fail(e) }
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|e| error(400, "bad_request", &format!("invalid JSON body: {e}"), "Send the JSON described in openapi.yaml."))
}

/// Host and Origin checks (DNS rebinding, cross-site requests), then the token.
async fn guard(AxState(api): AxState<Shared>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("").to_owned();
    let allowed = [format!("127.0.0.1:{}", api.port), format!("localhost:{}", api.port)];
    if !allowed.contains(&host) {
        return error(400, "bad_host", "the Host header is not this service's loopback address", "Connect to http://127.0.0.1 directly.");
    }
    if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        if origin != format!("http://{host}") {
            return error(403, "bad_origin", "cross-origin requests are refused", "Use the UI served by this service.");
        }
    }
    let path = req.uri().path();
    let public = path == "/health" || path == "/ui" || path.starts_with("/ui/");
    if !public {
        let given = bearer(req.headers());
        if !given.map_or(false, |g| ct_eq(g.as_bytes(), &api.token)) {
            return error(401, "unauthorized", "missing or wrong bearer token", "Send Authorization: Bearer <token> with the token from the service's token file.");
        }
    }
    next.run(req).await
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

fn query_param(q: &Option<String>, key: &str) -> Option<String> {
    q.as_deref()?.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v.to_owned())
}

pub fn router(api: Shared) -> Router {
    Router::new()
        .route("/health", get(|| async { json_ok(200, &json!({"ok": true, "banner": BANNER})) }))
        .route("/vaults", get(list_vaults).post(create_vault))
        .route("/vaults/{id}", get(get_vault))
        .route("/proposals/preview", post(preview))
        .route("/proposals/import", post(import))
        .route("/proposals", get(list_proposals).post(create_proposal))
        .route("/proposals/{id}", get(get_proposal))
        .route("/proposals/{id}/plan", get(get_plan))
        .route("/proposals/{id}/approve", post(approve))
        .route("/proposals/{id}/reject", post(reject))
        .route("/proposals/{id}/refresh", post(refresh))
        .route("/proposals/{id}/broadcast", post(broadcast))
        .route("/events", get(events))
        .route("/ui", get(|| async { Response::builder().status(302).header(header::LOCATION, "/ui/").body(Body::empty()).unwrap() }))
        .route("/ui/", get(|s: AxState<Shared>| static_file(s, Path(String::new()))))
        .route("/ui/{*path}", get(static_file))
        .fallback(|| async { error(404, "not_found", "no such route", "See openapi.yaml.") })
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn_with_state(api.clone(), guard))
        .with_state(api)
}

async fn list_vaults(AxState(a): AxState<Shared>) -> Response { json_ok(200, &json!({"vaults": a.engine.list_vaults()})) }

async fn create_vault(AxState(a): AxState<Shared>, body: Bytes) -> Response {
    #[derive(serde::Deserialize)]
    struct Req { name: String, chain: String }
    match parse::<Req>(&body) { Ok(r) => out(201, a.engine.create_vault(&r.name, &r.chain).await), Err(e) => e }
}

async fn get_vault(AxState(a): AxState<Shared>, Path(id): Path<String>) -> Response { out(200, a.engine.get_vault(&id).await) }

async fn preview(AxState(a): AxState<Shared>, body: Bytes) -> Response {
    match parse::<NewProposal>(&body) {
        Ok(r) => out(200, a.engine.preview(&r).await.map(|p| json!({"summary": p.summary, "message_sha256": p.message_sha256, "message_len": p.message_len}))),
        Err(e) => e,
    }
}

async fn create_proposal(AxState(a): AxState<Shared>, body: Bytes) -> Response {
    match parse::<NewProposal>(&body) { Ok(r) => out(201, a.engine.create_proposal(&r).await), Err(e) => e }
}

async fn import(AxState(a): AxState<Shared>, body: Bytes) -> Response {
    #[derive(serde::Deserialize)]
    struct Req { vault_id: String, plan: Value, expires_in_secs: Option<u64> }
    match parse::<Req>(&body) { Ok(r) => out(201, a.engine.import_proposal(&r.vault_id, r.plan, r.expires_in_secs).await), Err(e) => e }
}

async fn list_proposals(AxState(a): AxState<Shared>, RawQuery(q): RawQuery) -> Response {
    let state = match query_param(&q, "state") {
        None => None,
        Some(s) => match serde_json::from_value::<State>(json!(s)) {
            Ok(s) => Some(s),
            Err(_) => return error(400, "bad_request", "unknown state filter", "Use one of the states in openapi.yaml."),
        },
    };
    out(200, a.engine.list_proposals(query_param(&q, "vault_id").as_deref(), state).map(|p| json!({"proposals": p})))
}

async fn get_proposal(AxState(a): AxState<Shared>, Path(id): Path<String>) -> Response { out(200, a.engine.get_proposal(&id)) }
async fn get_plan(AxState(a): AxState<Shared>, Path(id): Path<String>) -> Response { out(200, a.engine.plan_of(&id)) }

async fn approve(AxState(a): AxState<Shared>, Path(id): Path<String>, body: Bytes) -> Response {
    #[derive(serde::Deserialize)]
    struct Req { confirm: bool, message_sha256: String }
    match parse::<Req>(&body) { Ok(r) => out(202, a.engine.approve(&id, r.confirm, &r.message_sha256).await), Err(e) => e }
}

async fn reject(AxState(a): AxState<Shared>, Path(id): Path<String>, body: Bytes) -> Response {
    #[derive(serde::Deserialize, Default)]
    struct Req { reason: Option<String> }
    let req = if body.is_empty() { Req::default() } else { match parse::<Req>(&body) { Ok(r) => r, Err(e) => return e } };
    out(200, a.engine.reject(&id, req.reason.as_deref()))
}

async fn refresh(AxState(a): AxState<Shared>, Path(id): Path<String>) -> Response { out(200, a.engine.refresh(&id).await) }
async fn broadcast(AxState(a): AxState<Shared>, Path(id): Path<String>) -> Response { out(202, a.engine.broadcast(&id).await) }

async fn events(AxState(a): AxState<Shared>, RawQuery(q): RawQuery) -> Response {
    let after = query_param(&q, "after").and_then(|v| v.parse().ok()).unwrap_or(0);
    let limit = query_param(&q, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(200).clamp(1, 500);
    json_ok(200, &json!({"events": a.engine.events(after, limit)}))
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8", "css" => "text/css; charset=utf-8", "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json", "svg" => "image/svg+xml", "png" => "image/png", "ico" => "image/x-icon",
        "txt" | "md" => "text/plain; charset=utf-8", _ => "application/octet-stream",
    }
}

/// Static UI files. Only plain path components; no dotfiles, no symlinks out of the directory.
async fn static_file(AxState(a): AxState<Shared>, Path(path): Path<String>) -> Response {
    let Some(root) = &a.ui_dir else { return error(404, "not_found", "no UI directory is configured", "Set ui_dir in the service config.") };
    let rel = if path.is_empty() { "index.html".to_owned() } else { path };
    if rel.split('/').any(|c| c.is_empty() || c.starts_with('.') || c.contains('\\')) {
        return error(404, "not_found", "no such file", "Check the path.");
    }
    let Ok(base) = root.canonicalize() else { return error(404, "not_found", "the UI directory is missing", "Check ui_dir.") };
    let Ok(full) = base.join(&rel).canonicalize() else { return error(404, "not_found", "no such file", "Check the path.") };
    if !full.starts_with(&base) || !full.is_file() { return error(404, "not_found", "no such file", "Check the path."); }
    match std::fs::read(&full) {
        Ok(bytes) => respond(200, bytes, content_type(&rel)),
        Err(_) => error(404, "not_found", "no such file", "Check the path."),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response { fail(self) }
}
