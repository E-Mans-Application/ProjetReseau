use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::net::{self, IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use super::parse::Buffer;

#[derive(Eq, Hash, Debug, Clone)]
pub struct Addr {
    addr: net::Ipv6Addr,
    port: u16,
}

impl PartialEq for Addr {
    fn eq(&self, other: &Self) -> bool {
        self.port == other.port &&
            ((self.addr == net::Ipv6Addr::UNSPECIFIED && other.addr == net::Ipv6Addr::LOCALHOST) ||
            (other.addr == net::Ipv6Addr::UNSPECIFIED && self.addr == net::Ipv6Addr::LOCALHOST)  || 
            self.addr == other.addr)
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(
            &self
                .to_socket_addrs()
                .map_err(|_err| std::fmt::Error)?
                .next()
                .ok_or(std::fmt::Error)?,
            f,
        )
    }
}

impl net::ToSocketAddrs for Addr {
    type Iter = std::option::IntoIter<net::SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        (self.addr, self.port).to_socket_addrs()
    }
}

impl Addr {
    pub(super) const LENGTH_IN_BYTES: usize = 18; // 16 (IPv6) + 2 (port)

    pub(super) fn try_parse(buf: &mut Buffer) -> Option<Self> {
        let addr = buf.next_u128()?;
        let addr = net::Ipv6Addr::from(addr);

        let port = buf.next_u16()?;

        Some(Self { addr, port })
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.addr.octets());
        bytes.extend(self.port.to_be_bytes());
        bytes
    }
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        let port = value.port();
        let addr = value.ip();
        let addr = match addr {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        };
        Self { addr, port }
    }
}

impl TryFrom<&str> for Addr {
    type Error = std::net::AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let socket_addr = SocketAddr::from_str(value)?;
        Ok(Self::from(socket_addr))
    }
}

impl TryFrom<(&str, u16)> for Addr {
    type Error = std::net::AddrParseError;

    fn try_from(value: (&str, u16)) -> Result<Self, Self::Error> {
        let socket_addr = SocketAddr::new(IpAddr::from_str(value.0)?, value.1);
        Ok(Self::from(socket_addr))
    }
}
