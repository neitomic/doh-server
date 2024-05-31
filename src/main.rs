pub mod dns;
pub mod http;

use axum::routing::post;
use axum::{
    body::Bytes, extract::Query, http::HeaderMap, response::IntoResponse, routing::get, Router,
};
use dns::record::DnsPacket;
use dns::{buffer::BytePacketBuffer, recursive_lookup};
use http::{DnsQueryParams, DnsResponse};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handle_get(headers: HeaderMap, Query(params): Query<DnsQueryParams>) -> impl IntoResponse {
    let question = params.to_dns_question().unwrap();
    let mut result = recursive_lookup(&question.name, question.qtype).unwrap();
    DnsResponse::from_packet(headers, &mut result).unwrap()
}

async fn handle_post(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let mut buf: [u8; 512] = [0; 512];
    let bytes = body.as_ref();
    buf[..bytes.len()].copy_from_slice(bytes);

    let mut req_buffer: BytePacketBuffer = BytePacketBuffer { buf: buf, pos: 0 };
    let packet = DnsPacket::from_buffer(&mut req_buffer).unwrap();
    // todo: handle multiple questions
    if let Some(q) = packet.questions.first() {
        let mut result = recursive_lookup(&q.name, q.qtype).unwrap();
        DnsResponse::from_packet(headers, &mut result).unwrap()
    } else {
        DnsResponse::BadRequest()
    }
}
