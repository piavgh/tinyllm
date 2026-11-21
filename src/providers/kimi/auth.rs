use super::{
    identity::device_headers,
    models::{KimiAuth, Region},
};
use eyre::{OptionExt, Result, WrapErr, bail};
use futures::StreamExt;
use reqwest::{StatusCode, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

const CLIENT_ID: &str = "17e5f671-d194-4dfb-9706-5516cb48c098";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_AUTH_BYTES: usize = 64 * 1024;
const REFRESH_LEAD: u64 = 300;
const MAX_DEVICE_SECONDS: f64 = 900.0;
const LOGIN_AGAIN: &str = "run tinyllm kimi login again";

pub enum Auth {
    MoonshotApiKey(String),
    ApiKey(String),
    Subscription(Arc<Session>),
}

impl Auth {
    pub fn open(config: &KimiAuth, region: Region) -> Result<Self> {
        match config {
            KimiAuth::MoonshotApiKey(_) => Ok(Self::MoonshotApiKey(config.api_key()?.to_owned())),
            KimiAuth::ApiKey(_) => Ok(Self::ApiKey(config.api_key()?.to_owned())),
            KimiAuth::Subscription(options) => {
                let session = Session::open(&options.credentials_dir, region)?;
                let credentials = session
                    .load()?
                    .ok_or_eyre("no Kimi subscription credentials; run tinyllm kimi login")?;
                device_headers(&credentials.device_id)?;

                Ok(Self::Subscription(Arc::new(session)))
            }
        }
    }

    pub fn is_subscription(&self) -> bool {
        matches!(self, Self::Subscription(_))
    }

    #[cfg(test)]
    pub(crate) fn set_auth_host(&mut self, host: String) {
        if let Self::Subscription(session) = self {
            Arc::get_mut(session).unwrap().auth_host = host;
        }
    }

    pub async fn access(&self, rejected: Option<&str>) -> Result<(String, HeaderMap)> {
        match self {
            Self::MoonshotApiKey(key) | Self::ApiKey(key) => Ok((key.clone(), HeaderMap::new())),
            Self::Subscription(session) => {
                let state = session.credentials.clone().lock_owned().await;
                let session = session.clone();
                let rejected = rejected.map(str::to_owned);

                tokio::spawn(async move { session.access(state, rejected.as_deref()).await })
                    .await
                    .wrap_err_with(|| "Kimi subscription refresh task failed")?
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Credentials {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    device_id: String,
    region: Region,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<f64>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    expires_in: Option<f64>,
    interval: Option<f64>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn valid_secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTH_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn expires_at(expires_in: Option<f64>) -> u64 {
    match expires_in {
        Some(seconds) if seconds > 0.0 => now().saturating_add(seconds as u64),
        _ => 0,
    }
}

fn login_url(code: &DeviceCode, region: Region) -> String {
    code.verification_uri_complete
        .clone()
        .or_else(|| code.verification_uri.clone())
        .unwrap_or_else(|| format!("{}?user_code={}", region.login_page(), code.user_code))
}

impl Credentials {
    fn from_response(
        response: TokenResponse,
        previous_refresh: Option<&str>,
        device_id: &str,
        region: Region,
    ) -> Result<Self> {
        let credentials = Self {
            access_token: response
                .access_token
                .ok_or_eyre("Kimi OAuth response omitted the access token")?,
            refresh_token: response
                .refresh_token
                .or_else(|| previous_refresh.map(str::to_owned))
                .ok_or_eyre(
                    "Kimi OAuth response omitted the refresh token; login cannot be saved",
                )?,
            expires_at: expires_at(response.expires_in),
            device_id: device_id.to_owned(),
            region,
        };
        credentials.validate()?;

        Ok(credentials)
    }

    fn validate(&self) -> Result<()> {
        if !valid_secret(&self.access_token)
            || !valid_secret(&self.refresh_token)
            || self.device_id.is_empty()
            || device_headers(&self.device_id).is_err()
        {
            bail!("Kimi subscription credentials contain an empty or invalid field");
        }

        Ok(())
    }
}

pub struct Session {
    directory: PathBuf,
    _lock: File,
    credentials: Arc<Mutex<CredentialState>>,
    client: reqwest::Client,
    region: Region,
    auth_host: String,
    poll_floor: Duration,
}

#[derive(Default)]
struct CredentialState {
    current: Option<Credentials>,
    unsaved: bool,
}

impl Session {
    pub fn open(directory: &Path, region: Region) -> Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }

        builder
            .create(directory)
            .wrap_err_with(|| "cannot create Kimi subscription credential directory")?;
        private_path(directory, true)?;

        let lock_path = directory.join("kimi.lock");
        match std::fs::symlink_metadata(&lock_path) {
            Ok(_) => private_path(&lock_path, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let lock = options
            .open(lock_path)
            .wrap_err_with(|| "cannot open Kimi subscription credential lock")?;
        lock.try_lock().map_err(|_| {
            eyre::eyre!(
                "Kimi subscription credentials are in use; stop the other tinyllm process before login/logout"
            )
        })?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("tinyllm/", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            directory: directory.into(),
            _lock: lock,
            credentials: Arc::new(Mutex::new(CredentialState::default())),
            client,
            region,
            auth_host: region.oauth_host().into(),
            poll_floor: Duration::from_secs(5),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_auth_host(&mut self, host: String) {
        self.auth_host = host;
    }

    #[cfg(test)]
    pub(crate) fn set_poll_floor(&mut self, floor: Duration) {
        self.poll_floor = floor;
    }

    fn path(&self) -> PathBuf {
        self.directory.join("kimi.json")
    }

    fn load(&self) -> Result<Option<Credentials>> {
        let path = self.path();

        if !path.try_exists()? {
            return Ok(None);
        }
        private_path(&path, false)?;

        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_AUTH_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;

        if bytes.len() > MAX_AUTH_BYTES {
            bail!("Kimi subscription credential file exceeds 64 KiB");
        }

        let invalid = || eyre::eyre!("invalid Kimi subscription credential file; {LOGIN_AGAIN}");
        let credentials: Credentials = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        credentials.validate().map_err(|_| invalid())?;

        if credentials.region != self.region {
            bail!(
                "Kimi credentials were saved for region {}; {LOGIN_AGAIN}",
                credentials.region.as_str()
            );
        }

        Ok(Some(credentials))
    }

    fn save(&self, credentials: &Credentials) -> Result<()> {
        credentials.validate()?;

        let bytes = serde_json::to_vec(credentials)?;

        if bytes.len() > MAX_AUTH_BYTES {
            bail!("Kimi subscription credentials exceed 64 KiB");
        }

        let temporary = self
            .directory
            .join(format!(".kimi.{}.tmp", uuid::Uuid::new_v4().simple()));
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, self.path())?;

            #[cfg(unix)]
            File::open(&self.directory)?.sync_all()?;

            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }

        result.wrap_err_with(|| "cannot persist Kimi subscription credentials")
    }

    async fn access(
        &self,
        mut state: OwnedMutexGuard<CredentialState>,
        rejected: Option<&str>,
    ) -> Result<(String, HeaderMap)> {
        if state.current.is_none() {
            state.current = Some(
                self.load()?
                    .ok_or_eyre("no Kimi subscription credentials; run tinyllm kimi login")?,
            );
        }

        if state.unsaved {
            self.save(state.current.as_ref().unwrap())?;
            state.unsaved = false;
        }

        let credentials = state.current.as_ref().unwrap();

        if (credentials.expires_at != 0 && credentials.expires_at <= now() + REFRESH_LEAD)
            || rejected == Some(credentials.access_token.as_str())
        {
            let response = self
                .client
                .post(format!("{}/api/oauth/token", self.auth_host))
                .headers(device_headers(&credentials.device_id)?)
                .form(&[
                    ("client_id", CLIENT_ID),
                    ("grant_type", "refresh_token"),
                    ("refresh_token", credentials.refresh_token.as_str()),
                ])
                .send()
                .await
                .map_err(|_| eyre::eyre!("cannot connect to Kimi for subscription refresh"))?;
            let (status, body) = read_token(response).await?;

            let dead_grant = body
                .as_ref()
                .is_some_and(|body| body.error.as_deref() == Some("invalid_grant"));
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN || dead_grant {
                bail!(
                    "Kimi subscription refresh was rejected (HTTP {}); {LOGIN_AGAIN}",
                    status.as_u16()
                );
            }

            if !status.is_success() {
                bail!(
                    "Kimi subscription refresh failed (HTTP {})",
                    status.as_u16()
                );
            }

            let body = body.ok_or_eyre("invalid Kimi OAuth response")?;
            let refreshed = Credentials::from_response(
                body,
                Some(&credentials.refresh_token),
                &credentials.device_id,
                credentials.region,
            )?;

            state.current = Some(refreshed);
            state.unsaved = true;
            self.save(state.current.as_ref().unwrap())?;
            state.unsaved = false;
        }

        let credentials = state.current.as_ref().unwrap();

        Ok((
            credentials.access_token.clone(),
            device_headers(&credentials.device_id)?,
        ))
    }

    pub async fn login(&self, headless: bool) -> Result<()> {
        let device_id = uuid::Uuid::new_v4().to_string();
        let headers = device_headers(&device_id)?;

        let response = self
            .client
            .post(format!("{}/api/oauth/device_authorization", self.auth_host))
            .headers(headers.clone())
            .form(&[("client_id", CLIENT_ID)])
            .send()
            .await
            .map_err(|_| eyre::eyre!("cannot connect to Kimi for device login"))?;

        let (status, bytes) = read_body(response).await?;

        if !status.is_success() {
            bail!(
                "Kimi device authorization failed (HTTP {})",
                status.as_u16()
            );
        }

        let code: DeviceCode = serde_json::from_slice(&bytes)
            .map_err(|_| eyre::eyre!("invalid Kimi device authorization response"))?;

        let url = login_url(&code, self.region);
        println!(
            "Open this URL in your browser to sign in:\n\n{url}\n\nCode: {}\n",
            code.user_code
        );

        if url.starts_with("https://") {
            crate::providers::browser::open(&url, headless);
        }

        let wait = code
            .expires_in
            .unwrap_or(MAX_DEVICE_SECONDS)
            .min(MAX_DEVICE_SECONDS);

        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(wait.max(0.0));
        let interval =
            Duration::from_secs_f64(code.interval.unwrap_or(5.0).clamp(0.0, MAX_DEVICE_SECONDS));
        let pause = interval.max(self.poll_floor);

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                bail!("Kimi device code expired; {LOGIN_AGAIN}");
            }
            tokio::time::sleep(pause.min(deadline - now)).await;

            let response = self
                .client
                .post(format!("{}/api/oauth/token", self.auth_host))
                .headers(headers.clone())
                .form(&[
                    ("client_id", CLIENT_ID),
                    ("device_code", code.device_code.as_str()),
                    ("grant_type", DEVICE_GRANT),
                ])
                .send()
                .await
                .map_err(|_| eyre::eyre!("cannot connect to Kimi for device login"))?;
            let body = read_token(response)
                .await?
                .1
                .ok_or_eyre("invalid Kimi OAuth response")?;

            match body.error.as_deref() {
                Some("authorization_pending" | "slow_down") => continue,
                Some(error) => bail!("Kimi login failed: {error}"),
                None => {}
            }

            let credentials = Credentials::from_response(body, None, &device_id, self.region)?;

            return self.save(&credentials);
        }
    }

    pub fn logout(&self) -> Result<()> {
        match std::fs::remove_file(self.path()) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(&self.directory)?.sync_all()?;

                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).wrap_err_with(|| "cannot remove local Kimi subscription credentials")
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn save_fixture(
    directory: &Path,
    access: &str,
    refresh: &str,
    expires_at: u64,
    device_id: &str,
    region: Region,
) {
    let session = Session::open(directory, region).unwrap();
    session
        .save(&Credentials {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_at,
            device_id: device_id.into(),
            region,
        })
        .unwrap();
}

#[cfg(test)]
pub(crate) fn fixture_expiry() -> u64 {
    now() + 3600
}

fn private_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        bail!("subscription credential paths must be regular files/directories, not symlinks");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("subscription credentials must be private: directory mode 0700, files 0600");
        }
    }

    Ok(())
}

async fn read_body(response: reqwest::Response) -> Result<(StatusCode, Vec<u8>)> {
    let status = response.status();
    let mut chunks = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| eyre::eyre!("OAuth response interrupted"))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_AUTH_BYTES {
            bail!("OAuth response exceeds 64 KiB");
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok((status, bytes))
}

async fn read_token(response: reqwest::Response) -> Result<(StatusCode, Option<TokenResponse>)> {
    let (status, bytes) = read_body(response).await?;

    Ok((status, serde_json::from_slice(&bytes).ok()))
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
