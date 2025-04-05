use clap::Parser;
use config::Config;
use serde_derive::Deserialize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct SettingArgs {
    config: Option<String>,
}

impl SettingArgs {
    pub fn config_or_default(self) -> String {
        self.config.unwrap_or("conf/default.toml".to_string())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Tls {
    pub enabled: bool,
    pub cert_dir: String,
    pub country: String,
    pub organization: String,
    pub common_name: String,
    pub sans: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Redis {
    pub enabled: bool,
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: Server,
    pub redis: Redis,
}

impl Settings {
    pub fn new(conf_file: String) -> anyhow::Result<Self> {
        let settings = Config::builder()
            .add_source(config::File::with_name(&conf_file))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;
        let instance = settings.try_deserialize::<Self>()?;
        Ok(instance)
    }
}
