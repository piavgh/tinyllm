use eyre::Result;
use reqwest::header::{HeaderMap, HeaderValue};
use std::{process::Command, sync::OnceLock};

pub fn device_headers(device_id: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    headers.insert("x-msh-platform", HeaderValue::from_static("tinyllm"));
    headers.insert(
        "x-msh-version",
        HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    headers.insert("x-msh-device-name", HeaderValue::from_str(hostname())?);
    headers.insert(
        "x-msh-device-model",
        HeaderValue::from_str(&device_model())?,
    );
    headers.insert("x-msh-device-id", HeaderValue::from_str(device_id)?);

    Ok(headers)
}

fn sanitize(value: &str) -> String {
    let kept: String = value
        .bytes()
        .filter(|byte| (0x20..=0x7e).contains(byte))
        .map(char::from)
        .collect();
    let kept = kept.trim();

    if kept.is_empty() {
        "unknown".to_owned()
    } else {
        kept.to_owned()
    }
}

fn hostname() -> &'static str {
    static HOSTNAME: OnceLock<String> = OnceLock::new();

    HOSTNAME.get_or_init(|| {
        Command::new("uname")
            .arg("-n")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map_or_else(
                || "unknown".to_owned(),
                |output| sanitize(&String::from_utf8_lossy(&output.stdout)),
            )
    })
}

fn device_model() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        other => other,
    };

    format!("{os} {}", std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_printable_ascii_only() {
        assert_eq!(sanitize("Hà-Nội Mac\n"), "H-Ni Mac");
        assert_eq!(sanitize("ộ"), "unknown");
        assert_eq!(sanitize("  box  "), "box");
    }

    #[test]
    fn device_headers_identify_tinyllm_and_reject_bad_ids() {
        let headers = device_headers("dev-1").unwrap();
        assert_eq!(headers["x-msh-platform"], "tinyllm");
        assert_eq!(headers["x-msh-version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(headers["x-msh-device-id"], "dev-1");
        assert!(
            headers.contains_key("x-msh-device-name") && headers.contains_key("x-msh-device-model")
        );
        assert!(device_headers("bad\nid").is_err());
    }
}
