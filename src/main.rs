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
    clippy::integer_division,
    clippy::use_debug,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    clippy::pattern_type_mismatch,
    clippy::nursery
)]

extern crate clap;
extern crate crossbeam;
extern crate derive_more;
extern crate rand;

use api::{
    logging::{Printer, VerboseLevel},
    use_client,
};
use std::str::FromStr;
use toplevel::TopLevelError;

use self::clap::Parser;

mod api;
mod sync;
mod toplevel;
mod priority_map;

#[derive(Parser)]
struct Cli {
    port: u16,
    first_neighbour: String,
    #[arg(short, long)]
    nickname: Option<String>,
    #[arg(short, long)]
    verbose: Option<String>,
}

fn main() -> Result<(), toplevel::TopLevelError> {
    let args = Cli::parse();
    let verbose_level = args
        .verbose
        .ok_or(())
        .and_then(|s| VerboseLevel::from_str(&s))
        .unwrap_or_default();

    let mut rl = rustyline::Editor::<()>::new()?;
    let mut printer = rl.create_external_printer()?;
    printer.print(format!("Verbose level: {verbose_level}\n"));

    use_client(
        args.port,
        &args.first_neighbour,
        args.nickname,
        printer,
        verbose_level,
        |sender, logger| loop {
            let readline = rl.readline("");
            match readline {
                Ok(line) => {
                    if let Err(err) = sender.send(line) {
                        logger.error(lazy_format!(
                            "Error when transmitting data to local server: {err}"
                        ));
                    }
                }
                Err(_err) =>  return,
            }
        },
    )
    .map_err(TopLevelError::from)
}
