//! This module encapsulates date time API calls, in such a way that
//! the date time API may be changed without affecting the rest
//! of the program.

use self::chrono::TimeZone;
extern crate chrono;

/// Alias for the type that represents milliseconds.
pub type MillisType = i64;

/// A wrapper around a value representing a date and time.
/// Only the functions used by the program are implemented, this
/// is not intended to replace [`std::time::SystemTime`] but
/// only to hide implementation details.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct DateTime(i64);

/// A wrapper around a value representing a duration.
/// Only the functions used by the program are implemented, this
/// is not intended to replace [`std::time::Duration`] but
/// only to hide implementation details.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Duration(i64);

impl DateTime {
    /// Returns a constant value, guaranteed to be very
    /// distant in time from any value returned by the function
    /// `now`.
    pub const fn never() -> Self {
        Self(i64::MIN)
    }

    /// Returns the current system time.
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp_millis())
    }

    /// Returns the elapsed time (in milliseconds) between this instance and the
    /// given instant. The instant likely comes from a previous call to `now`.
    /// If this instance is earlier than `instant`, a negative value is returned.
    ///
    /// The value is clamped in case of overflow.
    pub fn millis_since(self, instant: Self) -> MillisType {
        if let Some(result) = self.0.checked_sub(instant.0) {
            result
        } else if self > instant {
            i64::MAX
        } else {
            i64::MIN
        }
    }

    /// Returns the result of `self + duration`.
    ///
    /// The value is clamped in case of overflow.
    pub fn checked_add(self, duration: Duration) -> Self {
        if let Some(result) = self.0.checked_add(duration.0) {
            Self(result)
        } else if duration.0 > 0 {
            Self(i64::MAX)
        } else {
            Self(i64::MIN)
        }
    }

    /// Formats the current system date and time with the format dd/MM/YY HH:mm:ss
    ///
    /// Used only by verbose messages.
    pub fn formatted(self) -> String {
        match chrono::Utc.timestamp_millis_opt(self.0) {
            chrono::LocalResult::Single(dt) => {
                format!("{}", dt.with_timezone(&chrono::Local).format("%d/%m/%Y %T"))
            }
            _ => "<invalid date>".to_owned(),
        }
    }
}

impl Duration {
    /// Creates a new `Duration` object corresponding to the given number of milliseconds.
    pub const fn from_millis(millis: MillisType) -> Self {
        Self(millis)
    }

    /// Returns the result of `self * by`.
    ///
    /// The result is clamped in case of overflow.
    pub fn checked_mul(self, by: Duration) -> Self {
        if let Some(result) = self.0.checked_mul(by.0) {
            Self(result)

        // overflow implies both are non null
        } else if by.0.signum() == self.0.signum() {
            Self(i64::MAX)
        } else {
            Self(i64::MIN)
        }
    }
}
