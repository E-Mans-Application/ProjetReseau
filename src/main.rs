use std::net::UdpSocket;

use protocol::LocalPeerSocket;

mod addresses;
mod datetime;
mod error;
mod parse;
mod protocol;
mod util;

pub fn run_client(state: &mut LocalPeerSocket, port: u16) -> std::io::Result<()> {
    let socket = UdpSocket::bind(("::1", port))?;
    while true {}
    Ok(())
}

fn main() {
    let mut state = LocalState::new();
}
