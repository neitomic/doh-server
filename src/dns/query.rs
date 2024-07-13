use crate::dns::buffer::BytePacketBuffer;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, Serialize, Deserialize)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    SOA,   // 6
    MX,    //15
    AAAA,  // 28
    HTTPS, // 65
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::HTTPS => 65,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            65 => QueryType::HTTPS,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn from_str(name: String) -> QueryType {
        match name.to_uppercase().as_str() {
            "A" => QueryType::A,
            "NS" => QueryType::NS,
            "CNAME" => QueryType::CNAME,
            "SOA" => QueryType::SOA,
            "MX" => QueryType::MX,
            "AAAA" => QueryType::AAAA,
            "HTTPS" => QueryType::HTTPS,
            _ => QueryType::UNKNOWN(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?; // class
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}
