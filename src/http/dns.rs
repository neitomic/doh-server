use crate::dns::buffer::{BytePacketBuffer, MAX_SIZE};
use crate::dns::query::{DnsQuestion, QueryType};
use crate::dns::record::DnsPacket;
use crate::dns::recursive_lookup;
use crate::http::ApiContext;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use serde_derive::Deserialize;

pub(crate) fn router() -> Router<ApiContext> {
    Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post))
}

async fn handle_get(
    State(state): State<ApiContext>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> impl IntoResponse {
    let question = params.to_dns_question().unwrap();
    let socket = state.udp_socket_pool.acquire().await;
    let mut result = recursive_lookup(
        socket.as_ref(),
        state.redis_conn.clone(),
        &question.name,
        question.qtype,
    )
    .await
    .unwrap();
    DnsResponse::from_packet(headers, &mut result).unwrap()
}

async fn handle_post(
    State(state): State<ApiContext>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut buf: [u8; MAX_SIZE] = [0; MAX_SIZE];
    let bytes = body.as_ref();
    buf[..bytes.len()].copy_from_slice(bytes);

    let mut req_buffer: BytePacketBuffer = BytePacketBuffer { buf, pos: 0 };
    let packet = DnsPacket::from_buffer(&mut req_buffer).unwrap();
    // todo: handle multiple questions
    if let Some(q) = packet.questions.first() {
        let socket = state.udp_socket_pool.acquire().await;
        let mut result = recursive_lookup(socket.as_ref(), state.redis_conn, &q.name, q.qtype)
            .await
            .unwrap();
        DnsResponse::from_packet(headers, &mut result).unwrap()
    } else {
        DnsResponse::BadRequest()
    }
}

#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
    name: Option<String>,
    r#type: Option<String>,
    // r#do: Option<String>,
    // cd: Option<String>,
}

impl DnsQueryParams {
    pub fn to_dns_question(self) -> anyhow::Result<DnsQuestion> {
        if let Some(dns) = self.dns {
            let decoded = URL_SAFE_NO_PAD.decode(dns)?;
            let question = String::from_utf8(decoded).map(|qname| DnsQuestion {
                name: qname,
                qtype: QueryType::A,
            })?;
            return Ok(question);
        }

        if let Some(name) = self.name {
            return if let Some(qtype) = self.r#type {
                Ok(DnsQuestion {
                    name,
                    qtype: QueryType::from_str(qtype),
                })
            } else {
                Ok(DnsQuestion {
                    name,
                    qtype: QueryType::A,
                })
            };
        }

        Err(anyhow::anyhow!("Either dns or name is required!"))
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
