//! Alternative collections types to those of the standard library.

#![feature(map_try_insert)]
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
    clippy::nursery,
    clippy::pub_use
)]

mod queued_map;
pub use queued_map::QueuedMap;
