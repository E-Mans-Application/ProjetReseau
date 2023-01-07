#![feature(try_trait_v2)]
#![feature(option_result_contains)]

use protocol::LocalState;
use std::net::UdpSocket;

mod addresses;
mod protocol;
mod util;

pub fn run_client(state: &mut LocalState, port: u16) -> std::io::Result<()> {
    let socket = UdpSocket::bind(("::1", port))?;
    Ok(())
}

fn main() {
    let mut state = LocalState::new();
}
