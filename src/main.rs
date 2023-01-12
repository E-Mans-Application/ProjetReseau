#![feature(
    is_some_and,
    option_result_contains,
    map_try_insert,
    io_error_more,
    result_flattening
)]
#![deny(
    clippy::complexity,
    clippy::correctness,
    clippy::nursery,
    clippy::pedantic,
    clippy::perf,
    clippy::restriction,
    clippy::style,
    clippy::suspicious
)]
#![allow(
    clippy::as_conversions,
    clippy::single_char_lifetime_names,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::use_self,
    clippy::shadow_reuse,
    clippy::unseparated_literal_suffix,
    clippy::implicit_return,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::missing_trait_methods,
    clippy::wildcard_enum_match_arm,
    clippy::indexing_slicing,
    clippy::integer_arithmetic,
    clippy::arithmetic_side_effects,
    clippy::significant_drop_in_scrutinee,
    clippy::integer_division,
    clippy::use_debug,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    clippy::pattern_type_mismatch
)]
#![warn(
    clippy::arithmetic_side_effects,
    clippy::significant_drop_in_scrutinee,
    clippy::unwrap_used,
    clippy::non_send_fields_in_send_ty
)]

extern crate clap;
extern crate crossbeam;
extern crate ctrlc;

use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use error::UseClientError;
use util::VerboseLevel;

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
    #[arg(short, long)]
    verbose: Option<String>,
}

/// This method allows simple and safe use of a `LocalUser`.
/// As unsafe implementations of Sync and Send traits are forced for the type `LocalUser`,
/// it should be used between threads with care.
///
/// f is a closure that takes a `ReadOnlyRwLock` containing the `LocalUser` object.
/// f will be called repeatedly (in the current thread) until it returns an Err value,
/// which will then be returned by this function.
/// f can block as long as needed, but it should not lock the client for a long time.
///
/// `ReadOnlyRwLock` ensures that only the thread-safe methods `get_logger` and `send_data`
/// can be called from the closure.
///
/// # Errors
/// Return an Err value if the closure or the `LocalUser`'s thread panic.
/// Otherwise, returns an Ok value containing the error returned by the last
/// call to the closure.

pub fn use_client<T, F>(
    port: u16,
    first_neighbour: &str,
    verbose_level: VerboseLevel,
    f: F,
) -> Result<T, error::UseClientError>
where
    F: for<'arena> FnOnce(raw::ReadOnlyRwLock<raw::LocalUser<'arena>>) -> T,
{
    let alloc = bumpalo::Bump::new();

    crossbeam::scope(|s| -> std::result::Result<T, error::UseClientError> {
        let should_run = Arc::new(AtomicBool::new(true));
        let client = Arc::new(RwLock::new(raw::LocalUser::new(
            &alloc,
            port,
            first_neighbour,
            verbose_level,
        )?));

        let running = Arc::clone(&should_run);
        let client2 = Arc::clone(&client);

        let handle = s.spawn(move |_| loop {
            match client2.try_write() {
                c if !running.load(Ordering::SeqCst) => {
                    if let Ok(mut client_u) = c {
                        client_u.shutdown();
                    }
                    break;
                }
                Ok(mut client2) => client2.routine(),
                Err(_) => (),
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        let result = f(raw::ReadOnlyRwLock::from(Arc::clone(&client)));

        should_run.store(false, Ordering::SeqCst);
        handle.join()?;

        Ok(result)
    })
    .map_err(UseClientError::from)
    .flatten()
}

fn main() -> Result<(), error::UseClientError> {
    let args = Cli::parse();
    let verbose_level = args
        .verbose
        .ok_or(())
        .and_then(|s| VerboseLevel::from_str(&s))
        .unwrap_or_default();

    use_client(args.port, &args.first_neighbour, verbose_level, |client| {
        loop {
            let mut rl = rustyline::Editor::<()>::new()?;
            let readline = rl.readline("");
            match readline {
                Ok(line) => {
                    client.read().unwrap().send_data(&line);
                }
                Err(_err) => return Ok(()),
            }
        }
    })
    .flatten()
}