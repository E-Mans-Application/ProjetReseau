//! This module encapsulates date time API calls, in such a way that
//! the date time API may be changed without affecting the rest
//! of the program.
//!

extern crate chrono;

use std::time::SystemTime;

pub type DateTime = SystemTime;

pub const fn never() -> DateTime {
    SystemTime::UNIX_EPOCH
}

pub fn now() -> DateTime {
    SystemTime::now()
}

pub fn millis_since(instant: DateTime) -> u128 {
    let date_now = now();
    let duration = date_now.duration_since(instant).unwrap_or_default();
    duration.as_millis()
}

pub fn now_formatted() -> String {
    let datetime: chrono::prelude::DateTime<chrono::offset::Local> = now().into();
    format!("{0}", datetime.format("%d/%m/%Y %T"))
}
