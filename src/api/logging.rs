//! This module contains objects used for logging.
//! They are public to allow the closure in `use_client` to
//! log events.

/* #region VerboseLevel */

use derive_more::{Display, From};
use std::sync::Mutex;

use super::datetime;

/// This enum allows to control how verbose the program should be.
/// This enum may not be exhaustive, the position of the levels may change.
/// Only the relative order between the levels is reliable.
/// In command-line arguments, prefer using the string representation to numeric values.
#[derive(PartialEq, Eq, PartialOrd, Ord, From, Clone, Copy, Debug, Display, Default)]
#[repr(u8)]
pub enum VerboseLevel {
    /// This level is guaranteed to be lower than that of any event.
    /// It is also guaranteed to correspond to the numeric value 0.
    /// It is used to disable logging of all events.
    Disabled = 0,
    /// Verbose level of severe (but not critical) internal errors.
    #[display(fmt = "\x1b[1;31mInternal error\x1b[0m")]
    InternalError,
    /// Verbose level of non-critical events that should not have occurred
    /// and require further investigation.
    #[display(fmt = "\x1b[1;93mWarning\x1b[0m")]
    Warning,
    /// Verbose level of unexpected events that may not require special action.
    /// Those events are likely to be the remote's fault.
    #[display(fmt = "\x1b[1;34mAnomaly\x1b[0m")]
    #[default]
    Anomaly,
    /// Verbose level of important information that may interest the user, even
    /// when not debugging.
    #[display(fmt = "\x1b[1mImportant\x1b[0m")]
    Important,
    /// Verbose level of events that are noticeable but should be silenced in
    /// non-debug runs.
    Information,
    /// High verbose level corresponding to real-time logging of
    /// the actions undertaken  by the program.
    /// Using this level (or a higher one) will cause printing of a lot of messages.
    Trace,
    /// High Verbose level that enables logging of various low-level events, such
    /// as unprocessed network events. This level also includes Trace events.
    Debug,
    /// This level is guaranteed to be higher than that of any event.
    /// It is used to enable logging of all events.
    Full,
}

impl From<VerboseLevel> for u8 {
    fn from(value: VerboseLevel) -> Self {
        value as Self
    }
}

impl From<u8> for VerboseLevel {
    fn from(mut value: u8) -> Self {
        if value > Self::Full.into() {
            value = Self::Full.into();
        }
        // # Safety: it is guaranteed that 0 <= value <= Full
        unsafe { std::mem::transmute(value) }
    }
}

impl VerboseLevel {
    const DISABLED_STR: &str = "disabled";
    const ERROR_STR: &str = "internal-error";
    const WARNING_STR: &str = "warning";
    const ANOMALY_STR: &str = "anomaly";
    const IMPORTANT_STR: &str = "important";
    const INFORMATION_STR: &str = "information";
    const TRACE_STR: &str = "trace";
    const DEBUG_STR: &str = "debug";
    const FULL_STR: &str = "full";
}

impl std::str::FromStr for VerboseLevel {
    type Err = ();
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            Self::DISABLED_STR | "off" => Ok(Self::Disabled),
            Self::ERROR_STR | "error" | "err" => Ok(Self::InternalError),
            Self::WARNING_STR | "warn" => Ok(Self::Warning),
            Self::ANOMALY_STR => Ok(Self::Anomaly),
            Self::IMPORTANT_STR => Ok(Self::Important),
            Self::INFORMATION_STR | "info" => Ok(Self::Information),
            Self::TRACE_STR => Ok(Self::Trace),
            Self::DEBUG_STR => Ok(Self::Debug),
            Self::FULL_STR | "all" => Ok(Self::Full),
            _ => input.parse::<u8>().map(Self::from).map_err(|_err| ()),
        }
    }
}

/* #endregion */

/* #region EventLog */

/// A thread-safe event logger.
/// The methods use trait `ToStringOnce` (see below), that is implemented by all
/// `ToString` objects, and by the struct `LazyFormat` (see below)
pub struct EventLog {
    max_level: VerboseLevel,
    barrier: Mutex<()>,
}

impl EventLog {
    /// Creates a new EventLog, that shall log only the events that have at
    /// most verbose level `max_level`.
    pub const fn new(max_level: VerboseLevel) -> Self {
        Self {
            max_level: max_level,
            barrier: Mutex::new(()),
        }
    }

    pub fn log_event<T: ToStringOnce>(&self, severity: VerboseLevel, msg: T) {
        if self.barrier.lock().is_ok() {
            // Synchronization
            if severity <= self.max_level {
                // For now, the logger sends the event to stderr.
                eprintln!(
                    "[{0}] {1}: {2}",
                    datetime::now_formatted(),
                    severity,
                    msg.to_string_once()
                );
            }
        } else {
            eprintln!("Fatal: Program memory is corrupt due to a previous error. Exiting.");
            std::process::exit(6)
        }
    }

    // The following are self-explanatory convenience methods.

    pub fn error<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::InternalError, msg);
    }
    pub fn warning<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Warning, msg);
    }
    pub fn anomaly<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Anomaly, msg);
    }
    pub fn important<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Important, msg);
    }
    pub fn information<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Information, msg);
    }
    pub fn trace<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Trace, msg);
    }
    pub fn debug<T: ToStringOnce>(&self, msg: T) {
        self.log_event(VerboseLevel::Debug, msg);
    }
}

/* #endregion */

/* #region Convenience macros + lazy formatting */

// Lazy formatting
// This allows to replace macro `format!` in order to not build the string if it won't actually be used
// (Example: no string will be allocated for `Debug` messages if the verbose level is lower)
// A crate `LazyFormat` exists, but it uses a `Fn `instead of a `FnOnce`, causing all non-copy arguments
// to be moved.

/// Objects that are consumed when converted to string.
/// (Typical use: `FnOnce() -> String`)
pub trait ToStringOnce {
    fn to_string_once(self) -> String;
}

// Who can do more can do less.
impl<T: ToString> ToStringOnce for T {
    fn to_string_once(self) -> String {
        self.to_string()
    }
}

/// A wrapper around a closure that lazily produces a string value.
pub struct LazyFormat<Closure>(pub Closure)
where
    Closure: FnOnce() -> String;

impl<Closure: FnOnce() -> String> ToStringOnce for LazyFormat<Closure> {
    fn to_string_once(self) -> String {
        self.0()
    }
}

// Convenience macros to use lazy formatting more easily and to have a
// more concise syntax.

/// The same as `format!` with lazy evaluation.
/// The first argument should be a format string (it must be a string literal).
/// The values captures in the closure must stay valid until the closure is dropped.
#[macro_export]
macro_rules! lazy_format {
    ($($args: tt)*) => {
        $crate::api::logging::LazyFormat(|| format!($($args)*))
    }
}

/// Convenience macro that logs a warning from an object with a `logger` field.
#[macro_export]
macro_rules! log_warning {
    ($self: expr, $($args: tt)*) => {
        $self.logger.warning(lazy_format!($($args)*));
    }
}
/// Convenience macro that logs an anomaly from an object with a `logger` field.
#[macro_export]
macro_rules! log_anomaly {
    ($self: expr, $($args: tt)*) => {
        $self.logger.anomaly(lazy_format!($($args)*));
    }
}
/// Convenience macro that logs an important event from an object with a `logger` field.
#[macro_export]
macro_rules! log_important {
    ($self: expr, $($args: tt)*) => {
        $self.logger.important(lazy_format!($($args)*));
    }
}
/// Convenience macro that logs an informative event from an object with a `logger` field.
#[macro_export]
macro_rules! log_info {
    ($self: expr, $($args: tt)*) => {
        $self.logger.information(lazy_format!($($args)*));
    }
}
/// Convenience macro that logs a trace event from an object with a `logger` field.
#[macro_export]
macro_rules! log_trace {
    ($self: expr, $($args: tt)*) => {
        $self.logger.trace(lazy_format!($($args)*));
    }
}
/// Convenience macro that logs a debug event from an object with a `logger` field.
#[macro_export]
macro_rules! log_debug {
    ($self: expr, $($args: tt)*) => {
        $self.logger.debug(lazy_format!($($args)*));
    }
}

/* #endregion */
