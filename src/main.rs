pub mod cache;
pub mod dns;
pub mod http;
pub mod settings;
pub mod tls;

use crate::settings::{SettingArgs, Settings};
use clap::Parser;
use redis::aio::MultiplexedConnection;
use redis::Client;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_utils::Pool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let args = SettingArgs::parse();
    let settings: Settings = Settings::new(args.config_or_default())?;

    let mut sockets = Vec::new();
    for _ in 1..10 {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        sockets.push(Arc::new(socket));
    }
    let socket_pool: Pool<Arc<UdpSocket>> = Pool::from_vec(sockets);
    let client = Client::open(settings.redis.url)?;
    let redis_conn: MultiplexedConnection = client.get_multiplexed_async_connection().await?;

    http::serve(settings.server, socket_pool, redis_conn).await?;

    Ok(())
}
