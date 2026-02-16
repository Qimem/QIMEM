use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AuthConfig {
    pub jwt_secret: Option<String>,
    pub mfa_totp_secret: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl Settings {
    pub fn load() -> Self {
        let mut settings: Self = config::Config::builder()
            .add_source(config::Environment::with_prefix("QIMEM").separator("__"))
            .build()
            .ok()
            .and_then(|cfg| cfg.try_deserialize().ok())
            .unwrap_or_default();

        if settings.server.host.trim().is_empty() {
            settings.server.host = default_host();
        }
        if settings.server.port == 0 {
            settings.server.port = default_port();
        }

        settings
    }
}
