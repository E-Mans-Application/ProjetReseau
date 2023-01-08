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
    NeighbourInactive,
}

impl Error for MessageDeliveryError {}

#[derive(Display, Debug)]
pub(crate) enum AggregateError<E: Error> {
    #[display(fmt = "Errors aggregated during iterative operation:")]
    NoMoreError,
    #[display(fmt = "{_0}\n\n{_1}")]
    Aggregate(Box<AggregateError<E>>, E),
}

impl<E: Error> Error for AggregateError<E> {}

impl<E: Error> From<E> for AggregateError<E> {
    fn from(value: E) -> Self {
        AggregateError::Aggregate(Box::new(AggregateError::NoMoreError), value)
    }
}

impl<E: Error> AggregateError<E> {
    pub(crate) fn aggregate(self, other: E) -> AggregateError<E> {
        AggregateError::Aggregate(Box::new(self), other)
    }
    pub(crate) fn aggregate_result<_T>(self, other: Result<_T, E>) -> AggregateError<E> {
        match other {
            Ok(_) => self,
            Err(err) => self.aggregate(err),
        }
    }

    pub(crate) fn aggregate_flatten(self, other: AggregateError<E>) -> AggregateError<E> {
        match other {
            Self::NoMoreError => self,
            Self::Aggregate(head, tail) => {
                let new_head = self.aggregate_flatten(*head);
                Self::Aggregate(Box::new(new_head), tail)
            }
        }
    }

    pub(crate) fn aggregate_result_flatten(
        self,
        other: AggregateResult<(), E>,
    ) -> AggregateError<E> {
        match self {
            Self::NoMoreError => return other.err().unwrap_or(Self::NoMoreError),
            _ => (),
        }

        match other {
            Ok(()) | Err(Self::NoMoreError) => self,
            Err(err) => self.aggregate_flatten(err),
        }
    }
}

impl<E: Error> Into<AggregateResult<(), E>> for AggregateError<E> {
    fn into(self) -> AggregateResult<(), E> {
        match self {
            Self::NoMoreError => Ok(()),
            _ => Err(self),
        }
    }
}

pub(crate) type ParseResult<R> = std::result::Result<R, ParseError>;
pub(crate) type SerializationResult<R> = std::result::Result<R, SerializationError>;
pub(crate) type DeliveryResult<R> = std::result::Result<R, MessageDeliveryError>;
pub(crate) type AggregateResult<R, E: Error> = std::result::Result<R, AggregateError<E>>;
