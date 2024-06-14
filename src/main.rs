pub mod dns;
pub mod http;
pub mod tls;

use std::net::SocketAddr;
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
    enabled: bool,
    cert_dir: String,
    country: String,
    organization: String,
    common_name: String,
    sans: Vec<String>,
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

    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post));

    let addr = SocketAddr::new(settings.server.host.parse().unwrap(), settings.server.port);

    if settings.tls.enabled {
        let cert = gen_cert(settings.tls).unwrap();
        let config: RustlsConfig =
            RustlsConfig::from_pem(cert.cert_pem().into_bytes(), cert.key_pem().into_bytes())
                .await
                .unwrap();
        println!("serving HTTPS server on {}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        println!("serving HTTP server on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    }
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

fn gen_cert(settings: Tls) -> anyhow::Result<tls::Cert> {
    let dir = PathBuf::from(settings.cert_dir);
    let cert_name = settings.common_name;

    if let Some(existing_cert) = tls::Cert::load_if_exists(dir.as_path(), &cert_name)? {
        println!("using existing certificate");
        Ok(existing_cert)
    } else {
        println!("generating new CA and certificate");
        let ca = tls::generate_ca(&settings.country, &settings.organization)?;
        let cert = tls::generate_cert(&ca, &cert_name, settings.sans)?;
        ca.write(dir.as_path(), "ca").unwrap();
        cert.write(dir.as_path(), &cert_name).unwrap();
        Ok(cert)
    }
}
