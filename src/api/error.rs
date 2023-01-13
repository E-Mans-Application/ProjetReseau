//! This modules contains the errors used by the API.
//! The structures were removed from module `util`
//! because it was becoming too big.

extern crate derive_more;
use super::addresses::Addr;

use self::derive_more::{Display, From};
use std::error::Error;

/// Errors that may occur when a message is parsed.
#[derive(Display, Debug)]
pub(super) enum ParseError {
    #[display(fmt = "Cannot receive a datagram from UDP socket: {_0}")]
    ReceiveFailed(std::io::Error),
    #[display(fmt = "Received UDP datagram is not a MIRC service data unit")]
    NotAMircDatagram,
    #[display(fmt = "Received MIRC message uses an unsupported protocol version")]
    UnsupportedProtocolVersion(u8),
    #[display(fmt = "Invalid UTF-8 string: {_0}")]
    InvalidUtf8String(std::str::Utf8Error),
    // StringTooLarge is here for convenience reasons, but it may actually not
    // occur when parsing a message because of the maximum length of a TLV (255 bytes)
    StringTooLarge,
    #[display(fmt = "Protocol violation from {_0}")]
    ProtocolViolation(Addr),
    #[display(
        fmt = "Message received from uninvited third party: {_0} (Message ignored according to security rules.)"
    )]
    UnknownSender(Addr),
}

impl From<std::io::Error> for ParseError {
    fn from(value: std::io::Error) -> Self {
        Self::ReceiveFailed(value)
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReceiveFailed(err) => Some(err),
            _ => None,
        }
    }
}

// Actually, this error should never happen because:
// - The program should never try to send unsupported tags (tags Unrecognized or Illegal);
// - The program uses constant-size messages in warnings and go-away TLVs, and splits data sent
// from the user in several TLVs if needed.
/// Errors that may occur when serializing data to send into bytes
/// (It is the reverse of `ParseError`.)
#[derive(Display, Debug)]
pub(super) enum SerializationError {
    UnsupportedTag,
    StringTooLarge(String),
}

impl Error for SerializationError {}

/// Error that is returned by functions that give up
/// if the neighbour has been inactive for too long.
#[derive(From, Display, Debug)]
pub(super) struct NeighbourInactive;

impl Error for NeighbourInactive {}

/// Error that may occur when using the ready-to-use function
/// `crate::api::use_client`.
#[derive(From, Debug)]
pub enum UseClientError {
    PanicError(Box<dyn std::any::Any + Send + 'static>),
    IOError(std::io::Error),
    InvalidNeighbourAddress,
}

pub(super) type ParseResult<R> = std::result::Result<R, ParseError>;
pub(super) type SerializationResult<R> = std::result::Result<R, SerializationError>;
pub(super) type InactivityResult<R> = std::result::Result<R, NeighbourInactive>;
