//! This modules contains the structure `Addr`.
//! The structure was removed from module `util`
//! because it was becoming too big.

use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{self, IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use super::parse::Buffer;

/// An opaque wrapper representing an Ipv6 address.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Addr {
    addr: net::Ipv6Addr,
    port: u16,
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
    // Deprecated (no longer used).
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        Into::<SocketAddr>::into((self.addr, self.port)).to_socket_addrs()
    }
}

impl From<Addr> for SocketAddr {
    fn from(value: Addr) -> Self {
        SocketAddr::new(IpAddr::V6(value.addr), value.port)
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

    pub(super) fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn ip(&self) -> net::Ipv6Addr {
        self.addr
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
