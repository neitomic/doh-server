mod dns;

use crate::dns::{
    buffer::BytePacketBuffer,
    query::{DnsQuestion, QueryType},
    record::DnsPacket,
};
use crate::settings::{Server, Settings, Tls};
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::Request;
use axum::routing::{get, post};
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::engine::{general_purpose, Engine};
use config::Config;
use redis::aio::MultiplexedConnection;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio_utils::Pool;

use crate::tls;
use tower_http::{
    catch_panic::CatchPanicLayer, sensitive_headers::SetSensitiveHeadersLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct ApiContext {
    udp_socket_pool: Pool<Arc<UdpSocket>>,
    redis_conn: Arc<Mutex<MultiplexedConnection>>,
}

pub async fn serve(
    server_settings: Server,
    sockets: Pool<Arc<UdpSocket>>,
    redis: MultiplexedConnection,
) -> anyhow::Result<()> {
    let api_context = ApiContext {
        udp_socket_pool: sockets,
        redis_conn: Arc::new(Mutex::new(redis)),
    };

    let app = api_router(api_context);
    let addr = SocketAddr::new(server_settings.host.parse()?, server_settings.port);
    if server_settings.tls.enabled {
        let cert = gen_cert(server_settings.tls)?;
        let config: RustlsConfig =
            RustlsConfig::from_pem(cert.cert_pem().into_bytes(), cert.key_pem().into_bytes())
                .await?;
        info!("serving HTTPS server on {}", addr);

        let handle = axum_server::Handle::new();
        let shutdown_signal_fut = shutdown_signal();

        let server_fut = axum_server::bind_rustls(addr, config)
            .handle(handle.clone())
            .serve(app.into_make_service());

        tokio::select! {
            () = shutdown_signal_fut =>
                handle.graceful_shutdown(Some(Duration::from_secs(30))),
            res = server_fut => res?,
        }
    } else {
        let listener = TcpListener::bind(addr).await?;
        info!("serving HTTP server on {}", listener.local_addr()?);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

fn api_router(api_context: ApiContext) -> Router {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "doh_server=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    Router::new()
        .merge(dns::router())
        .layer((
            SetSensitiveHeadersLayer::new([AUTHORIZATION]),
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
            CatchPanicLayer::new(),
        ))
        .with_state(api_context)
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
        ca.write(dir.as_path(), "ca")?;
        cert.write(dir.as_path(), &cert_name)?;
        Ok(cert)
    }
}

async fn shutdown_signal() {
    use tokio::signal;

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
