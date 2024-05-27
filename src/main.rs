pub mod dns;
pub mod http;

use axum::http::header;
use axum::{
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
    let app = Router::new().route("/", get(handle_get));

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handle_get(headers: HeaderMap, Query(params): Query<DnsQueryParams>) -> impl IntoResponse {
    let qname: String = params.as_qname().unwrap();
    let mut result = recursive_lookup(&qname, dns::query::QueryType::A).unwrap();
    handle_resp(headers, &mut result)
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
