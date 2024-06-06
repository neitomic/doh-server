pub mod dns;
pub mod http;
pub mod tls;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use axum::routing::post;
use axum::{
    body::Bytes, extract::Query, http::HeaderMap, response::IntoResponse, routing::get, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use config::Config;
use dns::record::DnsPacket;
use dns::{buffer::BytePacketBuffer, recursive_lookup};
use http::{DnsQueryParams, DnsResponse};
use rcgen::SanType;
use serde_derive::Deserialize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    config: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Server {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct Tls {
    cert_dir: String,
    cert_name: String,
}

#[derive(Debug, Deserialize)]
struct Settings {
    server: Server,
    tls: Tls,
}

impl Settings {
    pub fn new(conf_file: String) -> anyhow::Result<Self> {
        let settings = Config::builder()
            .add_source(config::File::with_name(&conf_file))
            .add_source(config::Environment::with_prefix("APP"))
            .build()
            .unwrap();
        let instance = settings.try_deserialize::<Self>()?;
        Ok(instance)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let conf_file = args.config.unwrap_or("conf/default.toml".to_string());
    let settings = Settings::new(conf_file).unwrap();

    let dir = PathBuf::from(settings.tls.cert_dir);
    let cert_name = settings.tls.cert_name;
    let cert: tls::Cert;

    if let Some(existing_cert) = tls::Cert::load_if_exists(dir.as_path(), &cert_name).unwrap() {
        cert = existing_cert;
    } else {
        let ca = tls::generate_ca("vn", "neitomic").unwrap();
        cert = tls::generate_cert(
            &ca,
            "dns.local",
            vec![
                SanType::IpAddress("127.0.0.1".parse().unwrap()),
                SanType::DnsName("dns.local".try_into().unwrap()),
            ],
        )
        .unwrap();
        ca.write(dir.as_path(), "ca").unwrap();
        cert.write(dir.as_path(), &cert_name).unwrap();
    }

    let config = RustlsConfig::from_pem(cert.cert_pem().into_bytes(), cert.key_pem().into_bytes())
        .await
        .unwrap();

    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post));

    // run https server
    let addr = SocketAddr::new(settings.server.host.parse().unwrap(), settings.server.port);
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
