use eyre::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    #[default]
    Global,
    China,
}

impl Region {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::China => "china",
        }
    }

    pub fn code_api(self) -> &'static str {
        match self {
            Self::Global => "https://api.kimi.ai/coding",
            Self::China => "https://api.kimi.com/coding",
        }
    }

    pub fn oauth_host(self) -> &'static str {
        match self {
            Self::Global => "https://auth.kimi.ai",
            Self::China => "https://auth.kimi.com",
        }
    }

    pub fn platform_api(self) -> &'static str {
        match self {
            Self::Global => "https://api.moonshot.ai",
            Self::China => "https://api.moonshot.cn",
        }
    }

    pub fn login_page(self) -> &'static str {
        match self {
            Self::Global => "https://www.kimi.ai/code/authorize_device",
            Self::China => "https://www.kimi.com/code/authorize_device",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub auth: KimiAuth,
    #[serde(default)]
    pub region: Region,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub models: BTreeMap<String, Model>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", content = "options", deny_unknown_fields)]
pub enum KimiAuth {
    MoonshotApiKey(String),
    ApiKey(String),
    Subscription(SubscriptionOptions),
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionOptions {
    pub credentials_dir: PathBuf,
}

/// Discovery only: native controls travel with the request, so there is nothing to set.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {}

impl KimiAuth {
    pub fn is_subscription(&self) -> bool {
        matches!(self, Self::Subscription(_))
    }

    pub fn uses_code_api(&self) -> bool {
        !matches!(self, Self::MoonshotApiKey(_))
    }

    pub fn api_key(&self) -> Result<&str> {
        match self {
            Self::MoonshotApiKey(key) | Self::ApiKey(key)
                if !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_graphic()) =>
            {
                Ok(key)
            }
            Self::MoonshotApiKey(_) | Self::ApiKey(_) => bail!(
                "kimi.auth.options must be a nonempty API key without whitespace or control characters"
            ),
            Self::Subscription(_) => {
                bail!("subscription authentication requires tinyllm kimi login")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn region_defaults_to_global_and_maps_hosts() {
        assert_eq!(Region::default(), Region::Global);
        assert_eq!(Region::Global.code_api(), "https://api.kimi.ai/coding");
        assert_eq!(Region::Global.platform_api(), "https://api.moonshot.ai");
        assert_eq!(Region::China.code_api(), "https://api.kimi.com/coding");
        assert_eq!(Region::China.oauth_host(), "https://auth.kimi.com");
        assert_eq!(Region::China.platform_api(), "https://api.moonshot.cn");
        assert_eq!(Region::China.as_str(), "china");

        let parsed: Region = serde_json::from_value(json!("china")).unwrap();
        assert_eq!(parsed, Region::China);
    }

    #[test]
    fn both_key_types_expose_their_key_and_subscription_does_not() {
        let auth: KimiAuth =
            serde_json::from_value(json!({"type":"MoonshotApiKey","options":"moon"})).unwrap();
        assert_eq!(auth.api_key().unwrap(), "moon");
        assert!(!auth.uses_code_api());

        let auth: KimiAuth =
            serde_json::from_value(json!({"type":"ApiKey","options":"code"})).unwrap();
        assert_eq!(auth.api_key().unwrap(), "code");
        assert!(auth.uses_code_api());

        let auth: KimiAuth =
            serde_json::from_value(json!({"type":"Subscription","options":{}})).unwrap();
        assert!(auth.api_key().is_err() && auth.is_subscription() && auth.uses_code_api());

        let auth: KimiAuth =
            serde_json::from_value(json!({"type":"ApiKey","options":"bad key"})).unwrap();
        assert!(auth.api_key().is_err());
    }
}
