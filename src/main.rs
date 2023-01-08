#![feature(hash_drain_filter)]
#![feature(is_some_and)]
#![feature(result_option_inspect)]

extern crate clap;
extern crate crossbeam;

use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock, RwLockReadGuard};

use self::clap::Parser;

mod addresses;
mod datetime;
mod error;
mod parse;
mod raw;
mod util;

#[derive(Parser)]
struct Cli {
    port: u16,
    first_neighbour: String,
}

pub(crate) fn use_client<F>(port: u16, first_neighbour: String, f: F) -> std::io::Result<()>
where
    F: for<'arena> Fn(&RwLock<raw::LocalUser<'arena>>) -> std::io::Result<()>,
{
    let alloc = bumpalo::Bump::new();

    crossbeam::scope(|s| {
        let should_run = Arc::new(RwLock::new(true));
        let client = Arc::new(RwLock::new(raw::LocalUser::new(
            &alloc,
            port,
            first_neighbour,
        )?));

        let should_run2 = Arc::clone(&should_run);
        let client2 = Arc::clone(&client);

        let handle = s.spawn(move |_| loop {
            match (should_run2.try_write(), client2.try_write()) {
                (Ok(v), _) if !*v => break,
                (_, Ok(mut client2)) => client2.routine(),
                (_, Err(_)) => (),
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        loop {
            match f(&client) {
                Ok(()) => (),
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        print!("exit");

        loop {
            match should_run.try_write() {
                Ok(mut value) => {
                    *value = false;
                    break;
                }
                Err(_) => (),
            }
        }

        handle.join().map_err(|_| Error::from(ErrorKind::Other))?;
        Ok(())
    })
    .unwrap()
}

fn main() -> std::io::Result<()> {
    let args = Cli::parse();

    let stdin = std::io::stdin();
    use_client(args.port, args.first_neighbour, |client| {
        let mut line = String::new();
        stdin.read_line(&mut line)?;
        client.read().unwrap().send_data(line);

        Ok(())
    })
}
