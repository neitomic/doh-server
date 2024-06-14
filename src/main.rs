pub mod dns;
pub mod http;
pub mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
use tokio::signal;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "doh_server=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    let args = Args::parse();
    let conf_file = args.config.unwrap_or("conf/default.toml".to_string());
    let settings: Settings = Settings::new(conf_file).unwrap();

    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post))
        .layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(10)),
        ));

    let addr = SocketAddr::new(settings.server.host.parse().unwrap(), settings.server.port);

    if settings.tls.enabled {
        let cert = gen_cert(settings.tls).unwrap();
        let config: RustlsConfig =
            RustlsConfig::from_pem(cert.cert_pem().into_bytes(), cert.key_pem().into_bytes())
                .await
                .unwrap();
        info!("serving HTTPS server on {}", addr);

        let handle = axum_server::Handle::new();
        let shutdown_signal_fut = shutdown_signal();

        let server_fut = axum_server::bind_rustls(addr, config)
            .handle(handle.clone())
            .serve(app.into_make_service());

        tokio::select! {
            () = shutdown_signal_fut =>
                handle.graceful_shutdown(Some(Duration::from_secs(30))),
            res = server_fut => res.unwrap(),
        }
        info!("HTTPS Server is stopping");
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        info!("serving HTTP server on {}", listener.local_addr().unwrap());
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();

        info!("HTTP Server is stopping");
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
        info!("using existing certificate");
        Ok(existing_cert)
    } else {
        info!("generating new CA and certificate");
        let ca = tls::generate_ca(&settings.country, &settings.organization)?;
        let cert = tls::generate_cert(&ca, &cert_name, settings.sans)?;
        ca.write(dir.as_path(), "ca").unwrap();
        cert.write(dir.as_path(), &cert_name).unwrap();
        Ok(cert)
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
