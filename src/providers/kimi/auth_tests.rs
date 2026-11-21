use super::*;
use crate::providers::kimi::models::SubscriptionOptions;
use axum::{Form, Json, Router, routing::post};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

type Seen = Arc<std::sync::Mutex<Vec<(HashMap<String, String>, HeaderMap)>>>;

fn directory() -> PathBuf {
    std::env::temp_dir().join(format!("tinyllm-kimi-auth-{}", uuid::Uuid::new_v4()))
}

async fn server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (url, task)
}

fn subscription(path: &Path) -> KimiAuth {
    KimiAuth::Subscription(SubscriptionOptions {
        credentials_dir: path.into(),
    })
}

fn saved(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path.join("kimi.json")).unwrap()).unwrap()
}

fn code(complete: Option<&str>, plain: Option<&str>) -> DeviceCode {
    DeviceCode {
        device_code: "dc".into(),
        user_code: "UC".into(),
        verification_uri: plain.map(Into::into),
        verification_uri_complete: complete.map(Into::into),
        expires_in: None,
        interval: None,
    }
}

fn login_session(path: &Path, host: String) -> Session {
    let mut session = Session::open(path, Region::Global).unwrap();
    session.set_auth_host(host);
    session.set_poll_floor(Duration::from_millis(10));
    session
}

fn device_route(body: Value) -> axum::routing::MethodRouter {
    post(move || {
        let body = body.clone();
        async move { Json(body) }
    })
}

fn token_route(seen: Seen, answers: Vec<(u16, Value)>) -> axum::routing::MethodRouter {
    let index = Arc::new(AtomicUsize::new(0));
    post(
        move |headers: HeaderMap, Form(form): Form<HashMap<String, String>>| {
            let seen = seen.clone();
            let (status, body) =
                answers[index.fetch_add(1, Ordering::SeqCst).min(answers.len() - 1)].clone();
            async move {
                seen.lock().unwrap().push((form, headers));
                (StatusCode::from_u16(status).unwrap(), Json(body))
            }
        },
    )
}

fn pending() -> (u16, Value) {
    (200, json!({"error":"authorization_pending"}))
}

#[tokio::test]
async fn device_login_polls_until_approved_and_saves_private_credentials() {
    let seen: Seen = Default::default();
    let device_seen: Seen = Default::default();
    let (host, task) = server(
        Router::new()
            .route(
                "/api/oauth/device_authorization",
                post({
                    let device_seen = device_seen.clone();
                    move |headers: HeaderMap, Form(form): Form<HashMap<String, String>>| {
                        let device_seen = device_seen.clone();
                        async move {
                            device_seen.lock().unwrap().push((form, headers));
                            Json(json!({
                                "device_code":"dc","user_code":"UC",
                                "verification_uri_complete":"https://example.test/a?c=UC",
                                "expires_in":600,"interval":0
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/oauth/token",
                token_route(
                    seen.clone(),
                    vec![
                        pending(),
                        (400, json!({"error":"authorization_pending"})),
                        (
                            200,
                            json!({"access_token":"a1","refresh_token":"r1","expires_in":3600.0}),
                        ),
                    ],
                ),
            ),
    )
    .await;

    let path = directory();
    let session = login_session(&path, host);
    session.login(true).await.unwrap();

    let file = saved(&path);
    assert_eq!(file["access_token"], "a1");
    assert_eq!(file["refresh_token"], "r1");
    assert_eq!(file["region"], "global");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(session.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    for (form, _) in seen.iter() {
        assert_eq!(form["grant_type"], DEVICE_GRANT);
        assert_eq!(form["client_id"], "17e5f671-d194-4dfb-9706-5516cb48c098");
    }

    let device_seen = device_seen.lock().unwrap();
    assert_eq!(
        device_seen[0].0["client_id"],
        "17e5f671-d194-4dfb-9706-5516cb48c098"
    );

    for (_, headers) in seen.iter().chain(device_seen.iter()) {
        assert_eq!(headers["x-msh-platform"], "tinyllm");
        assert_eq!(
            headers["x-msh-device-id"],
            file["device_id"].as_str().unwrap()
        );
    }

    task.abort();
    drop(session);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn device_login_stops_on_access_denied_or_empty_answer() {
    for (answer, expected) in [
        (json!({"error":"access_denied"}), "access_denied"),
        (json!({}), "omitted"),
    ] {
        let seen: Seen = Default::default();
        let (host, task) = server(
            Router::new()
                .route(
                    "/api/oauth/device_authorization",
                    device_route(
                        json!({"device_code":"dc","user_code":"UC","expires_in":600,"interval":0}),
                    ),
                )
                .route(
                    "/api/oauth/token",
                    token_route(seen.clone(), vec![(200, answer)]),
                ),
        )
        .await;

        let path = directory();
        let session = login_session(&path, host);

        let error = session.login(true).await.unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        assert_eq!(seen.lock().unwrap().len(), 1);

        task.abort();
        drop(session);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn device_login_stops_when_code_expires() {
    let seen: Seen = Default::default();
    let (host, task) = server(
        Router::new()
            .route(
                "/api/oauth/device_authorization",
                device_route(
                    json!({"device_code":"dc","user_code":"UC","expires_in":0.05,"interval":0}),
                ),
            )
            .route("/api/oauth/token", token_route(seen, vec![pending()])),
    )
    .await;

    let path = directory();
    let session = login_session(&path, host);

    let error = tokio::time::timeout(Duration::from_secs(2), session.login(true))
        .await
        .unwrap()
        .unwrap_err()
        .to_string();
    assert!(error.contains("expired"), "{error}");

    task.abort();
    drop(session);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn login_url_prefers_server_urls_then_region_page() {
    assert_eq!(
        login_url(
            &code(Some("https://a/c"), Some("https://a")),
            Region::Global
        ),
        "https://a/c"
    );
    assert_eq!(
        login_url(&code(None, Some("https://a")), Region::Global),
        "https://a"
    );
    assert_eq!(
        login_url(&code(None, None), Region::Global),
        "https://www.kimi.ai/code/authorize_device?user_code=UC"
    );
    assert_eq!(
        login_url(&code(None, None), Region::China),
        "https://www.kimi.com/code/authorize_device?user_code=UC"
    );
}

#[tokio::test]
async fn refresh_near_expiry_keeps_device_and_old_refresh_token() {
    let seen: Seen = Default::default();
    let (host, task) = server(Router::new().route(
        "/api/oauth/token",
        token_route(
            seen.clone(),
            vec![(200, json!({"access_token":"a-new","expires_in":3600.5}))],
        ),
    ))
    .await;

    let path = directory();
    save_fixture(&path, "a-old", "r-old", 1, "dev-1", Region::Global);
    let mut auth = Auth::open(&subscription(&path), Region::Global).unwrap();
    auth.set_auth_host(host);

    let (token, headers) = auth.access(None).await.unwrap();
    assert_eq!(token, "a-new");
    assert_eq!(headers["x-msh-device-id"], "dev-1");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0["grant_type"], "refresh_token");
    assert_eq!(
        seen[0].0["client_id"],
        "17e5f671-d194-4dfb-9706-5516cb48c098"
    );
    assert_eq!(seen[0].0["refresh_token"], "r-old");
    assert_eq!(seen[0].1["x-msh-device-id"], "dev-1");

    let file = saved(&path);
    assert_eq!(file["access_token"], "a-new");
    assert_eq!(file["refresh_token"], "r-old");
    assert_eq!(file["device_id"], "dev-1");

    task.abort();
    drop(auth);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn unknown_expiry_refreshes_only_after_rejection() {
    let seen: Seen = Default::default();
    let (host, task) = server(Router::new().route(
        "/api/oauth/token",
        token_route(seen.clone(), vec![(200, json!({"access_token":"a-new"}))]),
    ))
    .await;

    let path = directory();
    save_fixture(&path, "a-old", "r-old", 0, "dev-1", Region::Global);
    let mut auth = Auth::open(&subscription(&path), Region::Global).unwrap();
    auth.set_auth_host(host);

    assert_eq!(auth.access(None).await.unwrap().0, "a-old");
    assert_eq!(seen.lock().unwrap().len(), 0);

    assert_eq!(auth.access(Some("a-old")).await.unwrap().0, "a-new");
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(saved(&path)["expires_at"], 0);

    task.abort();
    drop(auth);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn refresh_rejected_asks_for_login() {
    let (host, task) = server(Router::new().route(
        "/api/oauth/token",
        post(|| async { StatusCode::UNAUTHORIZED }),
    ))
    .await;

    let path = directory();
    save_fixture(&path, "a-old", "r-old", 1, "dev-1", Region::Global);
    let mut auth = Auth::open(&subscription(&path), Region::Global).unwrap();
    auth.set_auth_host(host);

    let error = auth.access(None).await.unwrap_err().to_string();
    assert!(error.contains("run tinyllm kimi login again"), "{error}");

    task.abort();
    drop(auth);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn refresh_invalid_grant_asks_for_login_at_any_status() {
    for status in [400, 200] {
        let (host, task) = server(Router::new().route(
            "/api/oauth/token",
            token_route(
                Default::default(),
                vec![(status, json!({"error":"invalid_grant"}))],
            ),
        ))
        .await;

        let path = directory();
        save_fixture(&path, "a-old", "r-old", 1, "dev-1", Region::Global);

        let mut auth = Auth::open(&subscription(&path), Region::Global).unwrap();
        auth.set_auth_host(host);

        let error = auth.access(None).await.unwrap_err().to_string();
        assert!(error.contains("run tinyllm kimi login again"), "{error}");

        task.abort();
        drop(auth);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn device_login_survives_huge_interval() {
    let (host, task) = server(
        Router::new()
            .route(
                "/api/oauth/device_authorization",
                device_route(
                    json!({"device_code":"dc","user_code":"UC","expires_in":0.05,"interval":1e20}),
                ),
            )
            .route(
                "/api/oauth/token",
                token_route(Default::default(), vec![pending()]),
            ),
    )
    .await;

    let path = directory();
    let session = login_session(&path, host);

    let error = tokio::time::timeout(Duration::from_secs(2), session.login(true))
        .await
        .unwrap()
        .unwrap_err()
        .to_string();
    assert!(error.contains("expired"), "{error}");

    task.abort();
    drop(session);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn saved_region_must_match() {
    let path = directory();
    save_fixture(&path, "a", "r", fixture_expiry(), "dev-1", Region::China);
    let error = Auth::open(&subscription(&path), Region::Global)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("region china"), "{error}");
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn corrupt_or_old_credentials_ask_for_login() {
    for content in [
        r#"{"access_token":"a","refresh_token":"r","expires_at":1}"#,
        r#"{"access_token":"a","refresh_token":"r","expires_at":1,"device_id":"dev-1"}"#,
    ] {
        let path = directory();
        drop(Session::open(&path, Region::Global).unwrap());

        let file = path.join("kimi.json");
        std::fs::write(&file, content).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = Auth::open(&subscription(&path), Region::Global)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("run tinyllm kimi login again"), "{error}");
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn missing_credentials_and_logout_are_handled() {
    let path = directory();
    let error = Auth::open(&subscription(&path), Region::Global)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("run tinyllm kimi login"), "{error}");

    let session = Session::open(&path, Region::Global).unwrap();
    session
        .save(&Credentials {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_at: fixture_expiry(),
            device_id: "dev-1".into(),
            region: Region::Global,
        })
        .unwrap();
    session.logout().unwrap();
    session.logout().unwrap();

    assert!(session.load().unwrap().is_none());
    drop(session);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn second_session_on_same_directory_is_refused() {
    let path = directory();
    let first = Session::open(&path, Region::Global).unwrap();
    let error = Session::open(&path, Region::Global)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("in use"), "{error}");
    drop(first);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn session_defaults_to_region_oauth_host() {
    let path = directory();
    let china = Session::open(&path, Region::China).unwrap();
    assert_eq!(china.auth_host, "https://auth.kimi.com");
    drop(china);

    let global = Session::open(&path, Region::Global).unwrap();
    assert_eq!(global.auth_host, "https://auth.kimi.ai");
    drop(global);

    std::fs::remove_dir_all(path).unwrap();
}
