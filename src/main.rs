pub mod dns;
pub mod http;
pub mod tls;
pub mod cache;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::extract::State;
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
use std::sync::Arc;
use axum::body::Body;
use axum::http::Request;
use redis::aio::MultiplexedConnection;
use redis::Client;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_utils::Pool;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;
use crate::dns::buffer::MAX_SIZE;

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
struct Redis {
    enabled: bool,
    url: String,
}

#[derive(Debug, Deserialize)]
struct Settings {
    server: Server,
    tls: Tls,
    redis: Redis,
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

#[derive(Clone)]
struct AppState {
    socket_pool: Pool<Arc<UdpSocket>>,
    redis_conn: Arc<Mutex<MultiplexedConnection>>,
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

    let mut sockets = Vec::new();
    for _ in 1..10 {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        sockets.push(Arc::new(socket));
    }
    let socket_pool: Pool<Arc<UdpSocket>> = Pool::from_vec(sockets);
    let client = Client::open(settings.redis.url).unwrap();
    let redis_conn: MultiplexedConnection = client.get_multiplexed_async_connection().await.unwrap();
    let app_state = AppState {
        socket_pool,
        redis_conn: Arc::new(Mutex::new(redis_conn)),
    };
    let app = Router::new()
        .route("/dns-query", get(handle_get))
        .route("/dns-query", post(handle_post))
        .with_state(app_state)
        .layer((
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = Uuid::new_v4();
                tracing::span!(
                    Level::DEBUG,
                    "request",
                    method = display(request.method()),
                    uri = display(request.uri()),
                    version = debug(request.version()),
                    request_id = display(request_id),
                    headers = debug(request.headers()),
                )
            }),
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

async fn handle_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> impl IntoResponse {
    let question = params.to_dns_question().unwrap();
    let socket = state.socket_pool.acquire().await;
    let mut result = recursive_lookup(socket.as_ref(), state.redis_conn.clone(), &question.name, question.qtype).await.unwrap();
    DnsResponse::from_packet(headers, &mut result).unwrap()
}

async fn handle_post(
    State(state): State<AppState>,
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
        let socket = state.socket_pool.acquire().await;
        let mut result = recursive_lookup(socket.as_ref(), state.redis_conn, &q.name, q.qtype).await.unwrap();
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
