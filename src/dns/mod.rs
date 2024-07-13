use std::net::{Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use crate::dns::result::ResultCode;

use self::{
    buffer::BytePacketBuffer,
    query::{DnsQuestion, QueryType},
    record::DnsPacket,
};
use anyhow::Result;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, SetExpiry, SetOptions};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;
use crate::cache::OptionalValue;

pub mod buffer;
pub mod header;
pub mod query;
pub mod record;
pub mod result;

async fn lookup_cache(redis: Arc<Mutex<MultiplexedConnection>>, qname: &str, qtype: QueryType) -> Result<Option<DnsPacket>> {
    let mut conn = redis.lock().await;
    let mut cached: OptionalValue<BytePacketBuffer> = conn.get(format!("{}_{:?}", qname, qtype)).await?;
    if let OptionalValue::Some(ref mut buffer) = cached {
        debug!("found response for {}:{:?} from cache", qname, qtype);
        let packet = DnsPacket::from_buffer(buffer)?;
        Ok(Some(packet))
    } else {
        Ok(None)
    }
}

async fn lookup_ns_cached(redis: Arc<Mutex<MultiplexedConnection>>, qname: &str) -> Result<Option<DnsPacket>> {
    let keys = postfixes(qname);
    let mut conn = redis.lock().await;

    for key in keys {
        let mut cached: OptionalValue<BytePacketBuffer> = conn.get(format!("{key}_nameserver")).await?;
        if let OptionalValue::Some(ref mut buffer) = cached {
            debug!("found cached NS for {} from cache with nameserver {}", qname, key);
            let packet = DnsPacket::from_buffer(buffer)?;
            return Ok(Some(packet));
        }
    }
    Ok(None)
}

async fn cache_ns(redis: Arc<Mutex<MultiplexedConnection>>, qname: &str, packet: &mut DnsPacket) -> Result<()> {
    let mut conn = redis.lock().await;
    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer)?;
    let ns = packet.get_ns(qname).next();
    if let Some((domain, _)) = ns {
        let ttl = packet.ttl() as usize;
        debug!("storing cache NS for {} with nameserver {} and ttl {}", qname, domain, ttl);
        let mut options = SetOptions::default();
        options.with_expiration(SetExpiry::EX(ttl));
        let _ = conn.set_options(format!("{domain}_nameserver"), buffer, options).await?;
    } else {
        debug!("store cache NS for {} but NS not found", qname);
    }
    Ok(())
}

async fn cache(redis: Arc<Mutex<MultiplexedConnection>>, qname: &str, qtype: QueryType, packet: &mut DnsPacket) -> Result<()> {
    let mut conn = redis.lock().await;
    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer)?;
    let ttl = packet.ttl() as usize;
    debug!("storing cache for {}:{:?} with ttl {}", qname, qtype, ttl);
    let mut options = SetOptions::default();
    options.with_expiration(SetExpiry::EX(ttl));
    let _ = conn.set_options(format!("{}_{:?}", qname, qtype), buffer, options).await?;
    Ok(())
}

pub async fn lookup(
    socket: &UdpSocket,
    qname: &str,
    qtype: QueryType,
    server: (Ipv4Addr, u16),
) -> Result<DnsPacket> {
    let mut packet: DnsPacket = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    timeout(
        Duration::from_millis(1000),
        socket.send_to(&req_buffer.buf[0..req_buffer.pos], server),
    ).await??;

    let mut res_buffer = BytePacketBuffer::new();
    timeout(
        Duration::from_millis(1000),
        socket.recv_from(&mut res_buffer.buf),
    ).await??;
    DnsPacket::from_buffer(&mut res_buffer)
}

pub async fn recursive_lookup(socket: &UdpSocket, redis: Arc<Mutex<MultiplexedConnection>>, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut ns: Ipv4Addr = "198.41.0.4".parse::<Ipv4Addr>()?;

    if let Some(cached) = lookup_cache(redis.clone(), qname, qtype).await? {
        return Ok(cached);
    }

    if let Some(cached_ns) = lookup_ns_cached(redis.clone(), qname).await? {
        ns = cached_ns.get_resolved_ns(qname).unwrap(); // since we only cache packet that have resolved ns
    }

    loop {
        debug!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);

        let mut response: DnsPacket = lookup(socket, qname, qtype, server).await?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            cache(redis.clone(), qname, qtype, &mut response).await?;
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        cache_ns(redis.clone(), qname, &mut response).await?;
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        debug!("got unresolved namespace {}, looking it up", new_ns_name);
        let recursive_response = Box::pin(recursive_lookup(socket, redis.clone(), &new_ns_name, QueryType::A)).await?;
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}


pub fn postfixes(qname: &str) -> Vec<String> {
    let mut result = Vec::new();
    let split = qname.rsplit(".");
    let mut postfix: String = "".to_owned();
    for p in split {
        let mut part = if postfix.is_empty() {
            format!("{p}")
        } else {
            format!("{p}.")
        };
        part.push_str(postfix.as_str());
        postfix = part;

        let elem = postfix.clone();
        result.push(elem);
    }
    result.reverse();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postfixes() {
        let vec = postfixes("mail.google.com");

        assert_eq!(vec!("mail.google.com", "google.com", "com"), vec)
    }
}