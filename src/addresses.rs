use std::fmt::Debug;
use std::net::{self, ToSocketAddrs};

use crate::util::BytesConcat;

#[derive(Clone, Copy, Hash, Debug)]
pub(crate) struct Addr {
    addr: net::Ipv6Addr,
    port: u16,
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_socket_addrs().fmt(f)
    }
}

impl net::ToSocketAddrs for Addr {
    type Iter = std::option::IntoIter<net::SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        return (self.addr, self.port).to_socket_addrs();
    }
}

impl Addr {
    pub fn from_bytes(recv: &[u8]) -> Option<Addr> {
        if recv.len() != 18 {
            // 16 (IPv6) + 2 (port)
            return None;
        }

        let (addr, port) = recv.split_at(16);

        let addr_bytes = [0u8; 16];
        addr_bytes.clone_from_slice(addr);

        let addr = net::Ipv6Addr::from(addr_bytes);
        let port = (port[0], port[1]).concat();

        Some(Addr { addr, port })
    }
}
