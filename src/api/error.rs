//! This modules contains the errors used by the API.
//! The structures were removed from module `util`
//! because it was becoming too big.

extern crate derive_more;
use super::addresses::Addr;

use self::derive_more::{Display, From};
use std::error::Error;

#[derive(Display, Debug)]
pub(super) enum LimitedStringError {
    StringTooLarge,
    InvalidUtf8String(std::str::Utf8Error),
}

impl Error for LimitedStringError {}

#[derive(Display, Debug)]
pub(super) enum ViolationKind {
    /// The datagram does not start by the [`super::util::PROTOCOL_MAGIC`] byte.
    NotAMircDatagram,
    /// The datagram specifies a protocol version different from
    /// [`super::util::PROTOCOL_VERSION`]
    UnsupportedProtocolVersion(u8),
    /// The datagram is less than 4-byte-long, or its body is shorter than
    /// the size specified in the header.
    InvalidLength,
    /// The body of the datagram is not a valid sequence of TLVs.
    /// ### Note:
    /// The whole datagram is discarded, even if this error occurs after some TLVs
    /// have been parsed successfully.
    InvalidSequenceOfTlv,
}

/// Errors that may occur when a message is parsed.
#[derive(Display, Debug)]
pub(super) enum ParseError {
    #[display(fmt = "Cannot receive a datagram from UDP socket: {_0}")]
    ReceiveFailed(std::io::Error),
    #[display(fmt = "Protocol violation from {_0}: {_1}")]
    ProtocolViolation(Addr, ViolationKind),
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

/// Error that occurs when trying to serialize an
/// unsupported tag (such as [`super::util::TagLengthValue::Unrecognized`],
/// or a "Warning" with an invalid UTF-8 message)
///
/// This error should never occur in practice.
#[derive(Display, Debug)]
pub(super) struct UnsupportedTag;

impl Error for UnsupportedTag {}

/// Error that is returned by functions that give up
/// if the neighbour has been inactive for too long.
#[derive(From, Display, Debug)]
pub(super) struct NeighbourInactive;

impl Error for NeighbourInactive {}

/// Error that may occur when using the ready-to-use function
/// [`crate::api::use_client`].
#[derive(From, Debug)]
pub enum UseClientError {
    PanicError(Box<dyn std::any::Any + Send + 'static>),
    IOError(std::io::Error),
    InvalidNeighbourAddress,
}

pub(super) type ParseResult<R> = std::result::Result<R, ParseError>;
pub(super) type InactivityResult<R> = std::result::Result<R, NeighbourInactive>;
