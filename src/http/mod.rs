use base64::engine::{general_purpose, Engine};
use serde::Deserialize;

use crate::dns::query::{DnsQuestion, QueryType};

#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
    name: Option<String>,
    r#type: Option<String>,
    r#do: Option<String>,
    cd: Option<String>,
}

impl DnsQueryParams {
    pub fn to_dns_question(self) -> anyhow::Result<DnsQuestion> {
        if let Some(dns) = self.dns {
            let decoded = general_purpose::URL_SAFE_NO_PAD
                .decode(dns)
                .map_err(anyhow::Error::msg)?;
            return String::from_utf8(decoded)
                .map_err(anyhow::Error::msg)
                .map(|qname| DnsQuestion {
                    name: qname,
                    qtype: QueryType::A,
                });
        }

        if let Some(name) = self.name {
            if let Some(qtype) = self.r#type {
                return Ok(DnsQuestion {
                    name: name,
                    qtype: QueryType::from_str(qtype),
                });
            } else {
                return Ok(DnsQuestion {
                    name: name,
                    qtype: QueryType::A,
                });
            }
        }

        return Err(anyhow::anyhow!("Either dns or name is required!"));
    }
}
