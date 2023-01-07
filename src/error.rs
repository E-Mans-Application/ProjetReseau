extern crate derive_more;

use self::derive_more::{Display, From};
use crate::util::TagLengthValue;
use std::error::Error;

#[derive(From, Display, Debug)]
pub(crate) enum ParseError {
    #[display(fmt = "Cannot receive a datagram from UDP socket: {0}", _0)]
    ReceiveFailed(std::io::Error),
    #[display(fmt = "Received UDP datagram is not a MIRC service data unit")]
    NotAMircDatagram,
    #[display(fmt = "Received MIRC message uses an unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[display(fmt = "Protocol violation")] // should be more verbose
    ProtocolViolation,
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
pub(crate) enum SerializationError<'arena> {
    #[display(fmt = "Unsupported tag: {_0:?}")]
    UnsupportedTag(&'arena TagLengthValue),
    #[display(fmt = "Tag value too large: {_0:?}")]
    TagValueTooLarge(&'arena TagLengthValue),
    MessageBodyTooLarge,
    Unspecified,
}

impl<'arena> Error for SerializationError<'arena> {}

#[derive(From, Display, Debug)]
pub(crate) enum MessageDeliveryError<'arena> {
    SerializationFailed(SerializationError<'arena>),
    DeliveryFailed(std::io::Error),
}

impl<'arena> Error for MessageDeliveryError<'arena> {}

pub(crate) type ParseResult<R> = std::result::Result<R, ParseError>;
pub(crate) type SerializationResult<'arena, R> = std::result::Result<R, SerializationError<'arena>>;
pub(crate) type DeliveryResult<'arena, R> = std::result::Result<R, MessageDeliveryError<'arena>>;
