extern crate derive_more;
use crate::addresses::Addr;

use self::derive_more::{Display, From};
use std::error::Error;

#[derive(From, Display, Debug)]
pub enum ParseError {
    #[display(fmt = "Cannot receive a datagram from UDP socket: {_0}")]
    ReceiveFailed(std::io::Error),
    #[display(fmt = "Received UDP datagram is not a MIRC service data unit")]
    NotAMircDatagram,
    #[display(fmt = "Received MIRC message uses an unsupported protocol version")]
    UnsupportedProtocolVersion(u8),
    #[display(fmt = "Invalid UTF-8 string: {_0}")]
    InvalidUtf8String(std::str::Utf8Error),
    StringTooLarge,
    #[display(fmt = "Protocol violation from {_0}")]
    ProtocolViolation(Addr),
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
#[derive(Display, Debug)]
pub enum SerializationError {
    UnsupportedTag,
    StringTooLarge(String),
}

impl Error for SerializationError {}

#[derive(From, Display, Debug)]
pub struct NeighbourInactive;

impl Error for NeighbourInactive {}

#[derive(From, Debug)]
pub enum UseClientError {
    PanicError(Box<dyn std::any::Any + Send + 'static>),
    IOError(std::io::Error),
    RustylineError(rustyline::error::ReadlineError),
}

pub type ParseResult<R> = std::result::Result<R, ParseError>;
pub type SerializationResult<R> = std::result::Result<R, SerializationError>;
pub type InactivityResult<R> = std::result::Result<R, NeighbourInactive>;
