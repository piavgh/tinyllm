pub mod auth;
pub mod identity;
pub mod models;

pub use models::Config;

use self::auth::Auth;
use crate::{
    Result,
    config::Server,
    error::Error,
    models::{ApiFormat, ApiRequest, ModelInfo, ProviderOutput, RequestContext},
    providers::{Provider, http, http::Auth as HttpAuth},
};
use axum::http::{HeaderMap, StatusCode};
use reqwest::{Client, Url};

pub struct KimiProvider {
    config: Config,
    auth: Auth,
    client: Client,
    messages: Url,
    chat: Url,
    responses: Url,
    catalog: Url,
    limit: usize,
}

impl KimiProvider {
    pub fn new(config: Config, client: Client, server: Server) -> eyre::Result<Self> {
        let auth = Auth::open(&config.auth, config.region)?;

        let base = config
            .base_url
            .as_deref()
            .unwrap_or(if config.auth.uses_code_api() {
                config.region.code_api()
            } else {
                config.region.platform_api()
            });

        let messages = if config.auth.uses_code_api() {
            "/v1/messages"
        } else {
            "/anthropic/v1/messages"
        };

        Ok(Self {
            messages: http::endpoint(base, messages)?,
            chat: http::endpoint(base, "/v1/chat/completions")?,
            responses: http::endpoint(base, "/v1/responses")?,
            catalog: http::endpoint(base, "/v1/models")?,
            auth,
            config,
            client,
            limit: server.max_response_bytes,
        })
    }

    async fn access(&self, rejected: Option<&str>) -> Result<(String, HeaderMap)> {
        self.auth
            .access(rejected)
            .await
            .map_err(|error| Error::upstream(error.to_string()))
    }

    fn catalog_request(&self, key: &str, headers: HeaderMap) -> Result<reqwest::RequestBuilder> {
        Ok(HttpAuth::Bearer(key)
            .apply(self.client.get(self.catalog.clone()))?
            .headers(headers))
    }

    #[cfg(test)]
    pub(crate) fn set_auth_host(&mut self, host: String) {
        self.auth.set_auth_host(host);
    }
}

#[async_trait::async_trait]
impl Provider for KimiProvider {
    fn models(&self) -> Vec<ModelInfo> {
        self.config
            .models
            .keys()
            .map(|id| ModelInfo {
                id: id.clone(),
                display_name: id.clone(),
            })
            .collect()
    }

    async fn upstream_models(&self) -> Result<Vec<ModelInfo>> {
        let (mut key, headers) = self.access(None).await?;
        let mut response = http::list(self.catalog_request(&key, headers)?).await?;

        if self.auth.is_subscription() && response.status() == StatusCode::UNAUTHORIZED {
            drop(response);
            let headers;

            (key, headers) = self.access(Some(&key)).await?;
            response = http::list(self.catalog_request(&key, headers)?).await?;
        }

        Ok(http::listed(
            &http::catalog(response, &key, self.limit).await?,
        ))
    }

    fn convert_reasoning_effort(&self, _model: &str, _effort: &str) -> Result<String> {
        Err(Error::invalid(
            "kimi models take native thinking controls; reasoning_effort is not converted",
        ))
    }

    async fn execute(
        &self,
        request: ApiRequest,
        context: RequestContext,
    ) -> Result<ProviderOutput> {
        let url = match request.format {
            ApiFormat::Anthropic => &self.messages,
            ApiFormat::ChatCompletions => &self.chat,
            ApiFormat::Responses => &self.responses,
        };
        let client_agent = context
            .headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .filter(|_| request.format == ApiFormat::Anthropic)
            .map(str::to_owned);

        let mut prepared = http::prepare(url.clone(), request, context, client_agent.as_deref())?;

        let (mut key, headers) = self.access(None).await?;
        *prepared.headers_mut() = headers;

        let mut response =
            http::send(&self.client, &prepared, HttpAuth::Bearer(&key), None).await?;

        if self.auth.is_subscription() && response.status() == StatusCode::UNAUTHORIZED {
            drop(response);
            let headers;

            (key, headers) = self.access(Some(&key)).await?;
            *prepared.headers_mut() = headers;
            response = http::send(&self.client, &prepared, HttpAuth::Bearer(&key), None).await?;
        }

        http::receive(response, prepared, &key, self.limit).await
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
