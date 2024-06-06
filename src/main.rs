pub mod dns;
pub mod http;
pub mod tls;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::routing::post;
use axum::{
    body::Bytes, extract::Query, http::HeaderMap, response::IntoResponse, routing::get, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use dns::record::DnsPacket;
use dns::{buffer::BytePacketBuffer, recursive_lookup};
use http::{DnsQueryParams, DnsResponse};

#[tokio::main]
async fn main() {
    let dir = PathBuf::from("test");
    let cert: tls::Cert;

    if let Some(existing_cert) = tls::Cert::load_if_exists(dir.as_path(), "name").unwrap() {
        cert = existing_cert;
    } else {
        let ca = tls::generate_ca("country", "organization").unwrap();
        cert = tls::generate_cert(&ca, "cn", vec![]).unwrap();
    }

    let config = RustlsConfig::from_pem(cert.cert_pem().into_bytes(), cert.key_pem().into_bytes())
        .await
        .unwrap();

    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post));

    // run https server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
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
