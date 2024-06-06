use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::engine::{general_purpose, Engine};
use serde::Deserialize;

use crate::dns::{
    buffer::BytePacketBuffer,
    query::{DnsQuestion, QueryType},
    record::DnsPacket,
};

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
            let decoded = general_purpose::URL_SAFE_NO_PAD.decode(dns)?;
            let question = String::from_utf8(decoded).map(|qname| DnsQuestion {
                name: qname,
                qtype: QueryType::A,
            })?;
            return Ok(question);
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

pub enum DnsResponse {
    DnsJson(Vec<u8>),
    DnsMessage(Vec<u8>),
    BadRequest(),
}

impl DnsResponse {
    pub fn from_packet(headers: HeaderMap, result: &mut DnsPacket) -> anyhow::Result<DnsResponse> {
        let accept_content_type: String = headers.get(header::ACCEPT).map_or(
            "application/dns-message".to_string(),
            |accept: &header::HeaderValue| accept.to_str().unwrap().to_lowercase(),
        );

        match accept_content_type.as_str() {
            "application/dns-message" => {
                let mut buffer: BytePacketBuffer = BytePacketBuffer::new();
                result.write(&mut buffer).unwrap();

                let len = buffer.pos();
                let data = buffer.get_range(0, len)?;
                Ok(DnsResponse::DnsMessage(data.to_vec()))
            }
            "application/dns-json" => {
                let json_result = result.as_json();
                Ok(DnsResponse::DnsJson(
                    serde_json::to_vec(&json_result).unwrap(),
                ))
            }
            _ => Ok(DnsResponse::BadRequest()),
        }
    }
}

impl IntoResponse for DnsResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            DnsResponse::DnsJson(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/dns-json")],
                body,
            )
                .into_response(),
            DnsResponse::DnsMessage(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/dns-message")],
                body,
            )
                .into_response(),
            DnsResponse::BadRequest() => StatusCode::BAD_REQUEST.into_response(),
        }
    }
}
