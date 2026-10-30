//! The HTTP surface over the demo wiring (mock chain, simulated group).
use holochain_mpc_vault::api::{router, Api};
use holochain_mpc_vault::demo;
use holochain_mpc_vault::util::SystemClock;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

fn tmp() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

struct Server { port: u16, _dirs: Vec<tempfile::TempDir> }

async fn start(ui: Option<std::path::PathBuf>, dirs: Vec<tempfile::TempDir>) -> Server {
    let data = tmp();
    let d = demo::start(data.path(), Arc::new(SystemClock), Duration::from_millis(300)).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let api = Arc::new(Api { engine: d.engine, token: TOKEN.as_bytes().to_vec(), port, ui_dir: ui });
    tokio::spawn(async move { axum::serve(listener, router(api)).await.unwrap() });
    let mut dirs = dirs;
    dirs.push(data);
    Server { port, _dirs: dirs }
}

struct Reply { status: u16, body: String }
impl Reply { fn json(&self) -> Value { serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body)) } }

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).build().into()
}

fn request(s: &Server, method: &str, path: &str, token: Option<&str>, body: Option<Value>, extra: &[(&str, &str)]) -> Reply {
    let url = format!("http://127.0.0.1:{}{path}", s.port);
    let a = agent();
    macro_rules! build { ($r:expr) => {{
        let mut r = $r;
        if let Some(t) = token { r = r.header("authorization", format!("Bearer {t}")); }
        for (k, v) in extra { r = r.header(*k, *v); }
        r
    }}}
    let mut resp = if method == "GET" {
        build!(a.get(&url)).call().unwrap()
    } else {
        let b = body.map(|b| serde_json::to_vec(&b).unwrap()).unwrap_or_default();
        build!(a.post(&url).header("content-type", "application/json")).send(&b[..]).unwrap()
    };
    Reply { status: resp.status().as_u16(), body: resp.body_mut().read_to_string().unwrap() }
}

async fn call(s: &Server, method: &'static str, path: &str, body: Option<Value>) -> Reply {
    let (port, path) = (s.port, path.to_owned());
    let s2 = Server { port, _dirs: vec![] };
    tokio::task::spawn_blocking(move || request(&s2, method, &path, Some(TOKEN), body, &[])).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_host_and_origin_are_enforced() {
    let s = start(None, vec![]).await;
    let port = s.port;
    tokio::task::spawn_blocking(move || {
        let s = Server { port, _dirs: vec![] };
        let h = request(&s, "GET", "/health", None, None, &[]);
        assert_eq!(h.status, 200);
        assert_eq!(h.json()["banner"], "Development build. Devnet only. Not production custody.");
        for (path, method) in [("/vaults", "GET"), ("/proposals", "GET"), ("/events", "GET"), ("/proposals", "POST"), ("/proposals/x/approve", "POST")] {
            let none = request(&s, method, path, None, Some(json!({})), &[]);
            assert_eq!(none.status, 401, "{method} {path}");
            assert_eq!(none.json()["error"]["code"], "unauthorized");
            assert!(none.json()["error"]["action"].as_str().unwrap().len() > 5, "errors say what to do");
            assert_eq!(request(&s, "GET", path, Some("wrong-token-wrong-token-wrong-token-xx"), None, &[]).status, 401);
        }
        assert_eq!(request(&s, "GET", "/vaults", Some(TOKEN), None, &[]).status, 200);
        let bad_host = request(&s, "GET", "/vaults", Some(TOKEN), None, &[("host", "evil.example")]);
        assert_eq!((bad_host.status, bad_host.json()["error"]["code"].as_str().unwrap().to_owned()), (400, "bad_host".to_owned()));
        let cross = request(&s, "GET", "/vaults", Some(TOKEN), None, &[("origin", "http://evil.example")]);
        assert_eq!(cross.status, 403);
        let same = request(&s, "GET", "/vaults", Some(TOKEN), None, &[("origin", &format!("http://127.0.0.1:{port}"))]);
        assert_eq!(same.status, 200);
        let big = request(&s, "POST", "/proposals/import", Some(TOKEN), Some(json!({"vault_id": "x", "plan": "a".repeat(200_000)})), &[]);
        assert_eq!(big.status, 413);
        assert_eq!(request(&s, "GET", "/nope", Some(TOKEN), None, &[]).json()["error"]["code"], "not_found");
        assert_eq!(request(&s, "POST", "/vaults", Some(TOKEN), Some(json!({"name": 5})), &[]).status, 400);
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn full_flow_over_http() {
    let s = start(None, vec![]).await;
    let vaults = call(&s, "GET", "/vaults", None).await.json();
    let vault = &vaults["vaults"][0];
    assert_eq!((vault["threshold"].as_u64(), vault["members"].as_array().unwrap().len()), (Some(2), 3));
    let id = vault["id"].as_str().unwrap().to_owned();
    let detail = call(&s, "GET", &format!("/vaults/{id}"), None).await.json();
    assert_eq!(detail["balance"]["raw"], "5000000000");
    assert!(detail["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("not implemented")));

    let req = json!({"vault_id": id, "recipient": "09".repeat(32), "amount": "2500000", "memo": "invoice 7"});
    let pre = call(&s, "POST", "/proposals/preview", Some(req.clone())).await;
    assert_eq!(pre.status, 200);
    assert_eq!(pre.json()["summary"]["amount"]["display"], "2.5 MOCK");
    assert_eq!(call(&s, "GET", "/proposals", None).await.json()["proposals"].as_array().unwrap().len(), 0);

    let created = call(&s, "POST", "/proposals", Some(req)).await;
    assert_eq!(created.status, 201);
    let p = created.json();
    let pid = p["id"].as_str().unwrap().to_owned();
    assert_eq!((p["state"].as_str(), p["integrity"]["status"].as_str(), p["summary"]["memo"].as_str()), (Some("proposed"), Some("verified"), Some("invoice 7")));
    assert_eq!(p["confirmations"], json!({"count": 0, "required": 2, "approvers": [], "observed_at": p["confirmations"]["observed_at"]}));

    let wrong = call(&s, "POST", &format!("/proposals/{pid}/approve"), Some(json!({"confirm": true, "message_sha256": "00".repeat(32)}))).await;
    assert_eq!((wrong.status, wrong.json()["error"]["code"].as_str().unwrap().to_owned()), (409, "hash_mismatch".to_owned()));
    let ok = call(&s, "POST", &format!("/proposals/{pid}/approve"),
        Some(json!({"confirm": true, "message_sha256": p["message_sha256"]}))).await;
    assert_eq!(ok.status, 202);
    assert_eq!(ok.json()["local_task"], "approving");

    let end = Instant::now() + Duration::from_secs(20);
    let done = loop {
        let v = call(&s, "GET", &format!("/proposals/{pid}"), None).await.json();
        if v["state"] == "confirmed" { break v; }
        assert!(Instant::now() < end, "stuck: {v}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(done["confirmations"]["count"], 2);
    assert!(done["signature"].as_str().unwrap().len() == 128 && done["broadcast"]["uncertain"] == false);
    let plan = call(&s, "GET", &format!("/proposals/{pid}/plan"), None).await.json();
    assert_eq!(plan["schema"], 1);
    let again = call(&s, "POST", &format!("/proposals/{pid}/broadcast"), None).await;
    assert_eq!((again.status, again.json()["error"]["code"].as_str().unwrap().to_owned()), (409, "broadcast_attempted".to_owned()));
    let by_state = call(&s, "GET", "/proposals?state=confirmed", None).await.json();
    assert_eq!(by_state["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(call(&s, "GET", "/proposals?state=bogus", None).await.status, 400);
    let events = call(&s, "GET", "/events?after=0&limit=500", None).await.json();
    let seqs: Vec<u64> = events["events"].as_array().unwrap().iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]) && !seqs.is_empty());
    let rejected = call(&s, "POST", &format!("/proposals/{pid}/reject"), None).await;
    assert_eq!(rejected.status, 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn static_ui_cannot_escape_its_directory() {
    use std::os::unix::fs::symlink;
    let outer = tmp();
    std::fs::write(outer.path().join("secret.txt"), "top secret").unwrap();
    let ui = outer.path().join("ui");
    std::fs::create_dir(&ui).unwrap();
    std::fs::write(ui.join("index.html"), "<h1>vault</h1>").unwrap();
    std::fs::write(ui.join(".hidden"), "x").unwrap();
    symlink(outer.path().join("secret.txt"), ui.join("link.txt")).unwrap();
    let s = start(Some(ui), vec![outer]).await;
    let port = s.port;
    tokio::task::spawn_blocking(move || {
        let s = Server { port, _dirs: vec![] };
        let idx = request(&s, "GET", "/ui/", None, None, &[]);
        assert_eq!((idx.status, idx.body.as_str()), (200, "<h1>vault</h1>"));
        assert_eq!(request(&s, "GET", "/ui/index.html", None, None, &[]).status, 200);
        for bad in ["/ui/.hidden", "/ui/link.txt", "/ui/../secret.txt", "/ui/%2e%2e/secret.txt", "/ui/a/../../secret.txt", "/ui/missing.js"] {
            let r = request(&s, "GET", bad, None, None, &[]);
            assert!(r.status == 404 || r.status == 400, "{bad} -> {}", r.status);
            assert!(!r.body.contains("top secret"));
        }
    }).await.unwrap();
}

/// The router and `openapi.yaml` must list the same operations.
#[tokio::test(flavor = "multi_thread")]
async fn router_matches_the_contract() {
    let yaml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml")).unwrap();
    let mut ops = Vec::new();
    let (mut in_paths, mut path) = (false, String::new());
    for line in yaml.lines() {
        if line == "paths:" { in_paths = true; continue; }
        if in_paths && !line.is_empty() && !line.starts_with(' ') { break; }
        if !in_paths { continue; }
        if let Some(p) = line.strip_prefix("  /").and_then(|l| l.strip_suffix(':')) { path = format!("/{p}"); }
        else if let Some(m) = line.strip_prefix("    ").and_then(|l| l.strip_suffix(':')).filter(|m| ["get", "post"].contains(m)) {
            ops.push((m.to_uppercase(), path.clone()));
        }
    }
    assert!(ops.len() >= 15, "parsed {ops:?}");
    let s = start(None, vec![]).await;
    for (method, path) in ops {
        let concrete = path.replace("{id}", "missing");
        let m: &'static str = if method == "GET" { "GET" } else { "POST" };
        let r = call(&s, m, &concrete, Some(json!({}))).await;
        let body = r.json();
        let routed = !(r.status == 404 && body["error"]["message"] == "no such route");
        assert!(routed, "{method} {path} is in openapi.yaml but not routed");
        assert!(r.status != 405, "{method} {path} wrong method");
    }
    // And the reverse: a method the contract does not list is not routed.
    assert_eq!(call(&s, "POST", "/vaults/x", Some(json!({}))).await.status, 405);
    assert_eq!(call(&s, "GET", "/proposals/x/approve", None).await.status, 405);
}
