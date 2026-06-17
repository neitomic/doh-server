use anyhow::Result;
use axum::http::{header, StatusCode};
use axum_test::TestServer;
use doh_server::http::dns;
use redis::Client;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_utils::Pool;

#[tokio::test]
async fn test_doh_server_basic() -> Result<()> {
    // Create UDP socket pool
    let mut sockets = Vec::new();
    for _ in 0..2 {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        sockets.push(Arc::new(socket));
    }
    let socket_pool: Pool<Arc<UdpSocket>> = Pool::from_vec(sockets);

    // Try to create Redis connection, but handle failure gracefully
    let redis_conn = match Client::open("redis://127.0.0.1/") {
        Ok(client) => {
            match client.get_multiplexed_async_connection().await {
                Ok(conn) => Arc::new(Mutex::new(conn)),
                Err(_) => {
                    // Skip Redis-dependent tests if Redis is not available
                    println!("Redis not available, skipping test");
                    return Ok(());
                }
            }
        }
        Err(_) => {
            println!("Redis not available, skipping test");
            return Ok(());
        }
    };

    let api_context = doh_server::http::ApiContext {
        udp_socket_pool: socket_pool,
        redis_conn,
    };

    let app = dns::router().with_state(api_context);
    let server = TestServer::new(app)?;

    // Test basic GET endpoint
    let response = server
        .get("/dns-query?name=google.com&type=A")
        .add_header(header::ACCEPT, "application/dns-message")
        .await;

    // The response might be OK or BAD_REQUEST depending on DNS resolution
    // but the endpoint should be accessible
    assert!(response.status_code() == StatusCode::OK || response.status_code() == StatusCode::BAD_REQUEST);

    Ok(())
}