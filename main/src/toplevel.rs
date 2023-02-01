//! This module contains implementation-specific top-level objects.
//!
//! Those objects are used for communication between the terminal or the UI and
//! the objects of the API.
//!
use std::error::Error;

use derive_more::{Display, From};

impl<T: rustyline::ExternalPrinter> crate::api::logging::Printer for T {
    fn print(&mut self, value: String) {
        if let Err(err) = self.print(value) {
            eprintln!("{err}");
        }
    }
}

/// Any top-level error that can be returned by function `main`.
/// This is depending on the choice of toplevel libraries.
///
/// Currently, the project uses [`rustyline`] for the UI.
#[derive(From, Display)]
pub enum TopLevelError {
    /// See [`crate::api::error::UseClientError`]
    UseClientError(crate::api::error::UseClientError),
    /// See [`rustyline::error::ReadlineError`]
    RustyLineError(rustyline::error::ReadlineError),
}

impl std::fmt::Debug for TopLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

impl Error for TopLevelError {}
