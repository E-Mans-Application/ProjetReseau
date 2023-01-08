extern crate derive_more;

use self::derive_more::{Display, From};
use std::error::Error;

#[derive(From, Display, Debug)]
pub(crate) enum ParseError {
    #[display(fmt = "Cannot receive a datagram from UDP socket: {0}", _0)]
    ReceiveFailed(std::io::Error),
    #[display(fmt = "Received UDP datagram is not a MIRC service data unit")]
    NotAMircDatagram,
    #[display(fmt = "Received MIRC message uses an unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[display(fmt = "Invalid UTF-8 string")]
    InvalidUtf8String,
    #[display(fmt = "Protocol violation")] // should be more verbose
    ProtocolViolation,
    /// Sender not previously registered as a potential neighbour.
    UnknownSender,
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReceiveFailed(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Display, Debug)]
pub(crate) enum SerializationError {
    UnsupportedTag,
    MessageBodyTooLarge,
    StringTooLarge(String),
    Unspecified,
}

impl Error for SerializationError {}

#[derive(From, Display, Debug)]
pub(crate) enum MessageDeliveryError {
    SerializationFailed(SerializationError),
    DeliveryFailed(std::io::Error),
}

impl Error for MessageDeliveryError {}

pub(crate) type ParseResult<R> = std::result::Result<R, ParseError>;
pub(crate) type SerializationResult<R> = std::result::Result<R, SerializationError>;
pub(crate) type DeliveryResult<R> = std::result::Result<R, MessageDeliveryError>;
