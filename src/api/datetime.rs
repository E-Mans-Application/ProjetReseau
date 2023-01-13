//! This module encapsulates date time API calls, in such a way that
//! the date time API may be changed without affecting the rest
//! of the program.

extern crate chrono;

use std::time::SystemTime;

pub type DateTime = SystemTime;

/// Returns a constant value, guaranteed to be very
/// distant in time from any value returned by the function
/// `now`.
pub const fn never() -> DateTime {
    SystemTime::UNIX_EPOCH
}

/// Returns the current system time.
pub fn now() -> DateTime {
    SystemTime::now()
}

/// Returns the elapsed time (in milliseconds) from the
/// given instant. The instant likely comes from a previous call to `now`.
pub fn millis_since(instant: DateTime) -> u128 {
    let date_now = now();
    let duration = date_now.duration_since(instant).unwrap_or_default();
    duration.as_millis()
}

/// Formats the current system date and time with the
/// format dd/MM/YY HH:mm:ss
/// Used only by verbose messages.
pub fn now_formatted() -> String {
    let datetime: chrono::prelude::DateTime<chrono::offset::Local> = now().into();
    format!("{0}", datetime.format("%d/%m/%Y %T"))
}
