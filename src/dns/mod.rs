use std::net::{Ipv4Addr};
use std::time::Duration;
use crate::dns::result::ResultCode;

use self::{
    buffer::BytePacketBuffer,
    query::{DnsQuestion, QueryType},
    record::DnsPacket,
};
use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;

pub mod buffer;
pub mod header;
pub mod query;
pub mod record;
pub mod result;

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

pub async fn recursive_lookup(socket: &UdpSocket, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut ns: Ipv4Addr = "198.41.0.4".parse::<Ipv4Addr>()?;
    loop {
        debug!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response: DnsPacket = lookup(socket, qname, qtype, server).await?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        debug!("got unresolved namespace {}, looking it up", new_ns_name);
        let recursive_response = Box::pin(recursive_lookup(socket, &new_ns_name, QueryType::A)).await?;
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}
