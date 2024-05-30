pub mod dns;
pub mod http;

use axum::http::header;
use axum::routing::post;
use axum::{
    body::Bytes,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use dns::record::DnsPacket;
use dns::{buffer::BytePacketBuffer, recursive_lookup};
use http::DnsQueryParams;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post));

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handle_get(headers: HeaderMap, Query(params): Query<DnsQueryParams>) -> impl IntoResponse {
    let question = params.to_dns_question().unwrap();
    let mut result = recursive_lookup(&question.name, question.qtype).unwrap();
    handle_resp(headers, &mut result)
}

async fn handle_post(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let mut buf: [u8; 512] = [0; 512];
    let bytes = body.as_ref();
    buf[..bytes.len()].copy_from_slice(bytes);

    let mut req_buffer = BytePacketBuffer { buf: buf, pos: 0 };
    let packet = DnsPacket::from_buffer(&mut req_buffer).unwrap();
    if let Some(q) = packet.questions.first() {
        let mut result = recursive_lookup(&q.name, q.qtype).unwrap();
        return handle_resp(headers, &mut result).into_response();
    } else {
        return bad_request().into_response();
    }
}

fn bad_request() -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/dns-message")],
        Vec::new(),
    )
}

fn handle_resp(headers: HeaderMap, result: &mut DnsPacket) -> impl IntoResponse {
    if let Some(accept) = headers.get(header::ACCEPT) {
        match accept.to_str().unwrap().to_lowercase().as_str() {
            "application/dns-message" => {
                let mut buffer: BytePacketBuffer = BytePacketBuffer::new();
                result.write(&mut buffer).unwrap();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/dns-message")],
                    buffer.buf.to_vec(),
                );
            }
            "application/dns-json" => {
                let json_result = result.as_json();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/dns-message")],
                    serde_json::to_vec(&json_result).unwrap(),
                );
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    [(header::CONTENT_TYPE, "application/dns-message")],
                    Vec::new(),
                )
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/dns-message")],
            Vec::new(),
        );
    }
}
