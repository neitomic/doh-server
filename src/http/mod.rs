use base64::engine::{general_purpose, Engine};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
    name: Option<String>,
}

impl DnsQueryParams {
    pub fn as_qname(self) -> anyhow::Result<String> {
        if let Some(dns) = self.dns {
            let decoded = general_purpose::URL_SAFE_NO_PAD
                .decode(dns)
                .map_err(anyhow::Error::msg)?;
            return String::from_utf8(decoded).map_err(anyhow::Error::msg);
        }

        if let Some(name) = self.name {
            return Ok(name);
        }

        return Err(anyhow::anyhow!("Either dns or name is required!"));
    }
}
