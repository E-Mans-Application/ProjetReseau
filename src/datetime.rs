//! This module encapsulates date time API calls, in such a way that
//! the date time API may be changed without affecting the rest
//! of the program.

use std::time::{Duration, SystemTime};

pub(crate) type DateTime = SystemTime;

pub(crate) fn never() -> DateTime {
    SystemTime::UNIX_EPOCH
}

pub(crate) fn now() -> DateTime {
    SystemTime::now()
}

pub(crate) fn secs_since(instant: DateTime) -> u64 {
    let date_now = now();
    let duration = date_now
        .duration_since(instant)
        .unwrap_or(Duration::default());
    duration.as_secs()
}
