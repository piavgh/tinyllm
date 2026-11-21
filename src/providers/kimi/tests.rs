use super::{
    auth::{fixture_expiry, save_fixture},
    models::Region,
    *,
};
use crate::{
    config::ProviderConfig,
    models::{ApiEvent, ResponseBody},
};
use axum::{Json, Router, body::Body, http::Uri, response::IntoResponse, routing::any};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

type Calls = Arc<Mutex<Vec<(String, HeaderMap)>>>;

struct Fixture {
    base: String,
    calls: Calls,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn paths(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    fn headers(&self, index: usize) -> HeaderMap {
        self.calls.lock().unwrap()[index].1.clone()
    }

    fn count(&self, path: &str) -> usize {
        self.paths().iter().filter(|seen| *seen == path).count()
    }
}

async fn fixture(message_statuses: Vec<u16>) -> Fixture {
    let calls = Calls::default();
    let messages = Arc::new(Mutex::new(0usize));

    let app = Router::new().fallback(any({
        let calls = calls.clone();
        move |uri: Uri, headers: HeaderMap, body: axum::body::Bytes| {
            let calls = calls.clone();
            let messages = messages.clone();
            let statuses = message_statuses.clone();
            async move {
                let path = uri.path().to_owned();
                calls.lock().unwrap().push((path.clone(), headers));
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

                if path.ends_with("/models") {
                    return Json(json!({"data":[{"id":"k3"}]})).into_response();
                }

                if path == "/api/oauth/token" {
                    return Json(json!({
                        "access_token":"a2","refresh_token":"r2","expires_in":3600
                    }))
                    .into_response();
                }

                if path.ends_with("/messages") {
                    let mut seen = messages.lock().unwrap();
                    let status = statuses[(*seen).min(statuses.len() - 1)];
                    *seen += 1;

                    if status != 200 {
                        return (
                            StatusCode::from_u16(status).unwrap(),
                            Json(json!({"error":{"message":"rejected"}})),
                        )
                            .into_response();
                    }
                }

                if body["stream"] == true {
                    let wire = format!(
                        "data: {}\n\ndata: {}\n\n",
                        json!({"type":"message_start","message":{"model":"k3"}}),
                        json!({"type":"message_stop"})
                    );
                    return ([("content-type", "text/event-stream")], Body::from(wire))
                        .into_response();
                }

                Json(json!({"model":"k3","status":"completed","content":[]})).into_response()
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Fixture { base, calls, task }
}

fn directory() -> PathBuf {
    std::env::temp_dir().join(format!("tinyllm-kimi-{}", uuid::Uuid::new_v4()))
}

fn context(user_agent: Option<&str>) -> RequestContext {
    let mut headers = HeaderMap::new();

    if let Some(user_agent) = user_agent {
        headers.insert("user-agent", user_agent.parse().unwrap());
    }

    RequestContext {
        request_id: "req-local".into(),
        provider: "kimi".into(),
        model: "k3".into(),
        public_model: "kimi/k3".into(),
        headers,
        query: None,
    }
}

fn request(format: ApiFormat, stream: bool) -> ApiRequest {
    ApiRequest::parse(
        format,
        json!({
            "model": "kimi/k3",
            "stream": stream,
            "max_tokens": 16,
            "messages": [{"role":"user","content":"hello"}],
        }),
    )
    .unwrap()
}

fn config(auth: Value, base_url: Option<String>, region: Region) -> Config {
    serde_json::from_value(json!({
        "auth": auth,
        "base_url": base_url,
        "region": region.as_str(),
        "models": {"k3": {}},
    }))
    .unwrap()
}

fn provider(config: Config) -> KimiProvider {
    let server = Server::default();

    KimiProvider::new(config, http::client(&server).unwrap(), server).unwrap()
}

fn subscription_auth(dir: &Path) -> Value {
    json!({"type":"Subscription","options":{"credentials_dir":dir}})
}

fn saved_subscription(expires_at: u64, region: Region) -> (Value, PathBuf) {
    let dir = directory();
    save_fixture(&dir, "a1", "r1", expires_at, "dev-1", region);

    (subscription_auth(&dir), dir)
}

async fn send_all(provider: &KimiProvider) {
    for format in [
        ApiFormat::Anthropic,
        ApiFormat::ChatCompletions,
        ApiFormat::Responses,
    ] {
        provider
            .execute(request(format, false), context(None))
            .await
            .unwrap();
    }
}

fn assert_calls(fixture: &Fixture, paths: [&str; 3], bearer: &str, device: bool) {
    assert_eq!(fixture.paths(), paths);

    for index in 0..3 {
        let headers = fixture.headers(index);
        assert_eq!(headers["authorization"], bearer);
        assert_eq!(headers.contains_key("x-msh-platform"), device);

        if device {
            assert_eq!(headers["x-msh-device-id"], "dev-1");
            assert_eq!(headers["x-msh-platform"], "tinyllm");
        }
    }
}

#[tokio::test]
async fn kimi_routes_each_format_per_auth_type() {
    let moonshot = fixture(vec![200]).await;
    let provider_moonshot = provider(config(
        json!({"type":"MoonshotApiKey","options":"moon-key"}),
        Some(moonshot.base.clone()),
        Region::Global,
    ));

    send_all(&provider_moonshot).await;
    assert_calls(
        &moonshot,
        [
            "/anthropic/v1/messages",
            "/v1/chat/completions",
            "/v1/responses",
        ],
        "Bearer moon-key",
        false,
    );

    let console = fixture(vec![200]).await;
    let provider_console = provider(config(
        json!({"type":"ApiKey","options":"console-key"}),
        Some(format!("{}/coding", console.base)),
        Region::Global,
    ));

    send_all(&provider_console).await;
    assert_calls(
        &console,
        [
            "/coding/v1/messages",
            "/coding/v1/chat/completions",
            "/coding/v1/responses",
        ],
        "Bearer console-key",
        false,
    );

    let sub = fixture(vec![200]).await;
    let (auth, dir) = saved_subscription(fixture_expiry(), Region::Global);
    let provider_sub = provider(config(
        auth,
        Some(format!("{}/coding", sub.base)),
        Region::Global,
    ));

    send_all(&provider_sub).await;
    assert_calls(
        &sub,
        [
            "/coding/v1/messages",
            "/coding/v1/chat/completions",
            "/coding/v1/responses",
        ],
        "Bearer a1",
        true,
    );

    for fixture in [moonshot, console, sub] {
        fixture.task.abort();
    }

    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn kimi_default_hosts_follow_region_and_auth_type() {
    let mut dirs = Vec::new();

    for (region, code, platform) in [
        (
            Region::Global,
            "https://api.kimi.ai/coding",
            "https://api.moonshot.ai",
        ),
        (
            Region::China,
            "https://api.kimi.com/coding",
            "https://api.moonshot.cn",
        ),
    ] {
        let (subscription, dir) = saved_subscription(fixture_expiry(), region);
        dirs.push(dir);

        for auth in [json!({"type":"ApiKey","options":"k"}), subscription] {
            let provider = provider(config(auth, None, region));

            assert_eq!(provider.messages.as_str(), format!("{code}/v1/messages"));
            assert_eq!(
                provider.chat.as_str(),
                format!("{code}/v1/chat/completions")
            );
            assert_eq!(provider.catalog.as_str(), format!("{code}/v1/models"));
        }

        let provider = provider(config(
            json!({"type":"MoonshotApiKey","options":"k"}),
            None,
            region,
        ));

        assert_eq!(
            provider.messages.as_str(),
            format!("{platform}/anthropic/v1/messages")
        );
        assert_eq!(
            provider.chat.as_str(),
            format!("{platform}/v1/chat/completions")
        );
        assert_eq!(provider.catalog.as_str(), format!("{platform}/v1/models"));
    }

    for dir in dirs {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn kimi_user_agent_follows_cliproxyapi() {
    let upstream = fixture(vec![200]).await;
    let provider = provider(config(
        json!({"type":"MoonshotApiKey","options":"k"}),
        Some(upstream.base.clone()),
        Region::Global,
    ));

    let client_agent = "claude-cli/2.1.300 (external, cli)";

    provider
        .execute(
            request(ApiFormat::Anthropic, false),
            context(Some(client_agent)),
        )
        .await
        .unwrap();
    provider
        .execute(request(ApiFormat::Anthropic, false), context(None))
        .await
        .unwrap();
    provider
        .execute(
            request(ApiFormat::ChatCompletions, false),
            context(Some("claude-cli/2.1.300")),
        )
        .await
        .unwrap();

    assert_eq!(upstream.headers(0)["user-agent"], client_agent);
    assert!(
        upstream.headers(1)["user-agent"]
            .to_str()
            .unwrap()
            .starts_with("tinyllm/")
    );
    assert!(
        upstream.headers(2)["user-agent"]
            .to_str()
            .unwrap()
            .starts_with("tinyllm/")
    );

    upstream.task.abort();
}

#[tokio::test]
async fn kimi_subscription_retries_only_one_401() {
    let upstream = fixture(vec![401, 200]).await;
    let (auth, dir) = saved_subscription(fixture_expiry(), Region::Global);
    let mut retrying = provider(config(auth, Some(upstream.base.clone()), Region::Global));
    retrying.set_auth_host(upstream.base.clone());

    retrying
        .execute(request(ApiFormat::Anthropic, false), context(None))
        .await
        .unwrap();

    assert_eq!(upstream.headers(0)["authorization"], "Bearer a1");
    assert_eq!(upstream.headers(2)["authorization"], "Bearer a2");
    assert_eq!(upstream.count("/v1/messages"), 2);

    upstream.task.abort();
    std::fs::remove_dir_all(dir).unwrap();

    let upstream = fixture(vec![401, 401]).await;
    let (auth, dir) = saved_subscription(fixture_expiry(), Region::Global);
    let mut failing = provider(config(auth, Some(upstream.base.clone()), Region::Global));
    failing.set_auth_host(upstream.base.clone());

    let error = failing
        .execute(request(ApiFormat::Anthropic, false), context(None))
        .await
        .err()
        .unwrap();

    assert_eq!(error.status, StatusCode::BAD_GATEWAY);
    assert_eq!(upstream.count("/v1/messages"), 2);
    assert_eq!(upstream.count("/api/oauth/token"), 1);

    upstream.task.abort();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn kimi_streams_messages_sse() {
    let upstream = fixture(vec![200]).await;
    let provider = provider(config(
        json!({"type":"MoonshotApiKey","options":"k"}),
        Some(upstream.base.clone()),
        Region::Global,
    ));

    let output = provider
        .execute(request(ApiFormat::Anthropic, true), context(None))
        .await
        .unwrap();
    let ResponseBody::Stream(events) = output.body else {
        panic!("expected SSE")
    };
    let types = events
        .map(|event| match event.unwrap() {
            ApiEvent::Anthropic(value) => value["type"].as_str().unwrap().to_owned(),
            _ => panic!("expected Anthropic"),
        })
        .collect::<Vec<_>>()
        .await;

    assert_eq!(types, ["message_start", "message_stop"]);

    upstream.task.abort();
}

#[tokio::test]
async fn kimi_catalog_uses_models_path_and_identity_headers() {
    let upstream = fixture(vec![200]).await;
    let (auth, dir) = saved_subscription(fixture_expiry(), Region::Global);
    let provider = provider(config(auth, Some(upstream.base.clone()), Region::Global));

    let models = provider.upstream_models().await.unwrap();

    assert_eq!(models[0].id, "k3");
    assert_eq!(upstream.paths(), ["/v1/models"]);
    assert_eq!(upstream.headers(0)["x-msh-device-id"], "dev-1");

    upstream.task.abort();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn kimi_api_key_catalogs_carry_no_identity_headers() {
    for auth in [
        json!({"type":"ApiKey","options":"k"}),
        json!({"type":"MoonshotApiKey","options":"k"}),
    ] {
        let upstream = fixture(vec![200]).await;
        let provider = provider(config(auth, Some(upstream.base.clone()), Region::Global));

        provider.upstream_models().await.unwrap();

        let headers = upstream.headers(0);
        assert_eq!(headers["authorization"], "Bearer k");
        assert!(
            headers
                .keys()
                .all(|name| !name.as_str().starts_with("x-msh-"))
        );

        upstream.task.abort();
    }
}

fn load(dir: &Path, text: &str) -> eyre::Result<crate::config::Config> {
    let path = dir.join("config.toml");
    std::fs::write(&path, format!("[server]\nstate_dir = 'state'\n{text}")).unwrap();

    crate::config::Config::load(&path)
}

fn kimi_of(config: &crate::config::Config) -> &Config {
    let ProviderConfig::Kimi(kimi) = &config.providers["kimi"] else {
        panic!("wrong provider variant")
    };

    kimi
}

#[test]
fn kimi_config_loads_defaults_and_rejects_bad_settings() {
    let dir = directory();
    std::fs::create_dir_all(&dir).unwrap();

    let config = load(
        &dir,
        "[providers.kimi]\ntype = 'kimi'\n[providers.kimi.auth]\ntype = 'Subscription'\n",
    )
    .unwrap();
    let kimi = kimi_of(&config);
    let models::KimiAuth::Subscription(options) = &kimi.auth else {
        panic!("wrong auth variant")
    };
    assert_eq!(options.credentials_dir, dir.join("state/auth/kimi"));
    assert_eq!(kimi.region, Region::Global);

    let config = load(
        &dir,
        "[providers.kimi]\ntype = 'kimi'\nregion = 'china'\n\
         [providers.kimi.auth]\ntype = 'ApiKey'\noptions = 'k'\n",
    )
    .unwrap();
    assert_eq!(kimi_of(&config).region, Region::China);

    assert!(
        load(
            &dir,
            "[providers.kimi]\ntype = 'kimi'\nuser_agent = 'x'\n\
             [providers.kimi.auth]\ntype = 'ApiKey'\noptions = 'k'\n",
        )
        .is_err()
    );

    let error = load(
        &dir,
        "[providers.kimi]\ntype = 'kimi'\nbase_url = 'https://api.kimi.com/coding'\n\
         [providers.kimi.auth]\ntype = 'Subscription'\n",
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("Kimi Code API"));

    assert!(
        load(
            &dir,
            "[providers.kimi]\ntype = 'kimi'\nbase_url = 'https://example.com'\n\
             [providers.kimi.auth]\ntype = 'ApiKey'\noptions = 'k'\n",
        )
        .is_err()
    );
    assert!(
        load(
            &dir,
            "[providers.kimi]\ntype = 'kimi'\nbase_url = 'https://example.com'\n\
             [providers.kimi.auth]\ntype = 'MoonshotApiKey'\noptions = 'k'\n",
        )
        .is_ok()
    );

    let error = load(
        &dir,
        "[providers.kimi]\ntype = 'kimi'\n[providers.kimi.auth]\ntype = 'Subscription'\n\
         [providers.kimi.auth.options]\ncredentials_dir = 'state/../kimi'\n",
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("must not contain '..'"),
        "{error}"
    );

    let error = load(
        &dir,
        "[providers.kimi]\ntype = 'kimi'\n[providers.kimi.auth]\ntype = 'Subscription'\n\
         [providers.kimi.auth.options]\ncredentials_dir = 'state/auth'\n",
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("shared auth root"), "{error}");

    std::fs::remove_dir_all(dir).unwrap();
}
