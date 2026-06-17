use crate::dns::buffer::{BytePacketBuffer, MAX_SIZE};
use crate::dns::query::{DnsQuestion, QueryType};
use crate::dns::record::DnsPacket;
use crate::dns::{preserve_response_id, recursive_lookup};
use crate::http::ApiContext;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, options, post};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use serde_derive::Deserialize;

pub fn router() -> Router<ApiContext> {
    Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post))
        .route("/dns-query", options(handle_options))
}

async fn handle_get(
    State(state): State<ApiContext>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> impl IntoResponse {
    let request = match params.to_dns_request() {
        Ok(request) => request,
        Err(_) => return DnsResponse::BadRequest().into_response(),
    };

    let socket = state.udp_socket_pool.acquire().await;
    let mut result = match recursive_lookup(
        socket.as_ref(),
        state.redis_conn.clone(),
        &request.question.name,
        request.question.qtype,
    )
    .await
    {
        Ok(r) => r,
        Err(_) => return DnsResponse::BadRequest().into_response(),
    };

    if let Some(request_id) = request.id {
        preserve_response_id(&mut result, request_id);
    }

    match DnsResponse::from_packet(headers, &mut result) {
        Ok(response) => response.into_response(),
        Err(_) => DnsResponse::BadRequest().into_response(),
    }
}

async fn handle_post(
    State(state): State<ApiContext>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !is_dns_message_content_type(&headers) {
        return DnsResponse::UnsupportedMediaType().into_response();
    }

    // Validate body size
    if body.len() > MAX_SIZE {
        return DnsResponse::BadRequest().into_response();
    }

    let mut buf: [u8; MAX_SIZE] = [0; MAX_SIZE];
    let bytes = body.as_ref();
    buf[..bytes.len()].copy_from_slice(bytes);

    let mut req_buffer: BytePacketBuffer = BytePacketBuffer { buf, pos: 0 };
    let packet = match DnsPacket::from_buffer(&mut req_buffer) {
        Ok(p) => p,
        Err(_) => return DnsResponse::BadRequest().into_response(),
    };
    let request_id = packet.header.id;

    // Handle multiple questions (browsers typically send one)
    if let Some(q) = packet.questions.first() {
        let socket = state.udp_socket_pool.acquire().await;
        let mut result =
            match recursive_lookup(socket.as_ref(), state.redis_conn, &q.name, q.qtype).await {
                Ok(r) => r,
                Err(_) => return DnsResponse::BadRequest().into_response(),
            };

        preserve_response_id(&mut result, request_id);

        match DnsResponse::from_packet(headers, &mut result) {
            Ok(response) => response.into_response(),
            Err(_) => DnsResponse::BadRequest().into_response(),
        }
    } else {
        DnsResponse::BadRequest().into_response()
    }
}

async fn handle_options() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
            (header::ACCESS_CONTROL_MAX_AGE, "86400"),
        ],
        "",
    )
}

fn is_dns_message_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .and_then(|content_type| content_type.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/dns-message")
        })
}

#[derive(Debug, Deserialize)]
pub struct DnsQueryParams {
    pub dns: Option<String>,
    pub name: Option<String>,
    pub r#type: Option<String>,
    // r#do: Option<String>,
    // cd: Option<String>,
}

pub struct DnsRequest {
    pub id: Option<u16>,
    pub question: DnsQuestion,
}

impl DnsQueryParams {
    pub fn to_dns_request(self) -> anyhow::Result<DnsRequest> {
        if let Some(dns) = self.dns {
            // Handle base64url-encoded DNS message
            let decoded = URL_SAFE_NO_PAD.decode(dns)?;
            if decoded.len() < 12 {
                return Err(anyhow::anyhow!("DNS message too short"));
            }

            let mut buffer = BytePacketBuffer::from_bytes(&decoded);
            let packet = DnsPacket::from_buffer(&mut buffer)?;

            if let Some(question) = packet.questions.first() {
                return Ok(DnsRequest {
                    id: Some(packet.header.id),
                    question: question.clone(),
                });
            } else {
                return Err(anyhow::anyhow!("No questions in DNS message"));
            }
        }

        if let Some(name) = self.name {
            if name.is_empty() || name.len() > 253 {
                return Err(anyhow::anyhow!("Invalid domain name"));
            }

            return if let Some(qtype) = self.r#type {
                Ok(DnsRequest {
                    id: None,
                    question: DnsQuestion {
                        name,
                        qtype: QueryType::from_str(qtype),
                    },
                })
            } else {
                Ok(DnsRequest {
                    id: None,
                    question: DnsQuestion {
                        name,
                        qtype: QueryType::A,
                    },
                })
            };
        }

        Err(anyhow::anyhow!("Either dns or name parameter is required!"))
    }
}

pub enum DnsResponse {
    DnsJson(Vec<u8>),
    DnsMessage(Vec<u8>),
    BadRequest(),
    UnsupportedMediaType(),
}

impl DnsResponse {
    pub fn from_packet(headers: HeaderMap, result: &mut DnsPacket) -> anyhow::Result<DnsResponse> {
        // Parse Accept header to determine preferred content type
        let accept_header = headers
            .get(header::ACCEPT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/dns-message");

        // Check if client accepts dns-message (preferred for browsers)
        let accepts_dns_message =
            accept_header.contains("application/dns-message") || accept_header.contains("*/*");

        // Check if client specifically requests dns-json
        let accepts_dns_json = accept_header.contains("application/dns-json");

        if accepts_dns_message {
            let mut buffer: BytePacketBuffer = BytePacketBuffer::new();
            result.write(&mut buffer)?;

            let len = buffer.pos();
            let data = buffer.get_range(0, len)?;
            Ok(DnsResponse::DnsMessage(data.to_vec()))
        } else if accepts_dns_json {
            let json_result = result.as_json();
            Ok(DnsResponse::DnsJson(serde_json::to_vec(&json_result)?))
        } else {
            // Default to dns-message for browsers
            let mut buffer: BytePacketBuffer = BytePacketBuffer::new();
            result.write(&mut buffer)?;

            let len = buffer.pos();
            let data = buffer.get_range(0, len)?;
            Ok(DnsResponse::DnsMessage(data.to_vec()))
        }
    }
}

impl IntoResponse for DnsResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            DnsResponse::DnsJson(body) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/dns-json"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
                ],
                body,
            )
                .into_response(),
            DnsResponse::DnsMessage(body) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/dns-message"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
                ],
                body,
            )
                .into_response(),
            DnsResponse::BadRequest() => (
                StatusCode::BAD_REQUEST,
                [
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
                ],
                "Bad Request",
            )
                .into_response(),
            DnsResponse::UnsupportedMediaType() => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                [
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
                ],
                "Unsupported Media Type",
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn accepts_dns_message_content_type_with_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message; charset=utf-8"),
        );

        assert!(is_dns_message_content_type(&headers));
    }

    #[test]
    fn rejects_missing_or_wrong_content_type() {
        assert!(!is_dns_message_content_type(&HeaderMap::new()));

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));

        assert!(!is_dns_message_content_type(&headers));
    }

    #[test]
    fn parses_dns_query_id_from_get_wire_message() {
        let mut packet = DnsPacket::new();
        packet.header.id = 42;
        packet
            .questions
            .push(DnsQuestion::new("example.com".to_string(), QueryType::A));

        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer).unwrap();
        let len = buffer.pos();
        let dns = URL_SAFE_NO_PAD.encode(buffer.get_range(0, len).unwrap());

        let request = DnsQueryParams {
            dns: Some(dns),
            name: None,
            r#type: None,
        }
        .to_dns_request()
        .unwrap();

        assert_eq!(request.id, Some(42));
        assert_eq!(request.question.name, "example.com");
        assert_eq!(request.question.qtype, QueryType::A);
    }
}
