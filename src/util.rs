extern crate derive_more;

use self::derive_more::{Display, From};
use crate::{addresses::Addr, protocol};
use std::{error::Error, str::pattern::ReverseSearcher};

pub(crate) type DateTime = i64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerID(u64);

impl PeerID {
    pub(crate) fn new() -> PeerID {
        PeerID(0) //TODO
    }

    pub(crate) fn from_bytes(recv: &[u8]) -> Option<PeerID> {
        if recv.len() != 8 {
            return None;
        }

        let mut val: u64 = 0;
        for i in 0..8 {
            val << 8;
            val |= recv[i] as u64;
        }
        Some(PeerID(val))
    }
}

pub(crate) type MessageId = (PeerID, [u8; 4]);

pub(crate) enum GoAwayReason {
    Unknown,
    EmitterLeaving,
    Inactivity,
    ProtocolViolation,
}

impl GoAwayReason {
    fn from_code(code: u8) -> GoAwayReason {
        match code {
            1 => GoAwayReason::EmitterLeaving,
            2 => GoAwayReason::Inactivity,
            3 => GoAwayReason::ProtocolViolation,
            _ => GoAwayReason::Unknown,
        }
    }
}

pub(crate) enum TagLengthValue {
    Pad1,
    PadN(usize),
    Hello(PeerID, Option<PeerID>),
    Neighbour(Addr),
    Data(MessageId, Vec<u8>),
    Ack(MessageId),
    GoAway(GoAwayReason, String),
    Warning(String),
    Unrecognized(Vec<u8>),
    Illegal,
}

impl TagLengthValue {
    pub(crate) fn try_parse(buffer: &mut protocol::Buffer) -> Option<TagLengthValue> {
        let tag = buffer.next()?;
        if tag == 0 {
            return Some(TagLengthValue::Pad1);
        }

        let length: usize = buffer.next()?.into();

        match tag {
            1 => Some(TagLengthValue::PadN(length)),
            2 => {
                if length != 8 && length != 16 {
                    return None;
                }

                let sender = buffer.try_take(8)?;
                let receiver = buffer.try_take(8);

                let sender_id = PeerID::from_bytes(sender)?;
                let receiver_id = PeerID::from_bytes(receiver.unwrap_or_else(|| &vec![]));

                Some(TagLengthValue::Hello(sender_id, receiver_id))
            }
            3 => {
                let content = buffer.try_take(length)?;
                let addr = Addr::from_bytes(content)?;
                Some(TagLengthValue::Neighbour(addr))
            }
            4 | 5 => {
                let sender = buffer.try_take(8)?;
                let sender = PeerID::from_bytes(sender)?;

                let msg_id_bytes = buffer.try_take(4)?;
                let msg_id: [u8; 4] = [0; 4];
                msg_id.clone_from_slice(msg_id_bytes);

                if tag == 4 {
                    let data = buffer.read_to_end().to_vec();

                    Some(TagLengthValue::Data((sender, msg_id), data))
                } else {
                    Some(TagLengthValue::Ack((sender, msg_id)))
                }
            }
            6 => {
                let code = buffer.next()?;
                let reason = GoAwayReason::from_code(code);

                let msg = buffer.read_to_end().to_utf8();
                Some(TagLengthValue::GoAway(reason, msg))
            }
            7 => {
                let msg = buffer.read_to_end().to_utf8();
                Some(TagLengthValue::Warning(msg))
            }
            _ => {
                let data = buffer.read_to_end();
                Some(TagLengthValue::Unrecognized(data.to_vec()))
            }
        }
    }
}

#[derive(From, Display, Debug)]
pub(crate) enum ParseError {
    #[display(fmt=("Cannot receive a datagram from UDP socket: {0}", _0.fmt))]
    ReceiveFailed(std::io::Error),
    #[display(fmt=("Received UDP datagram is not a MIRC service data unit"))]
    NotAMircDatagram,
    #[display(fmt=("Received MIRC message uses an unsupported protocol version"))]
    UnsupportedProtocolVersion,
    #[display(fmt=("Protocol violation"))] // should be more verbose
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

pub(crate) type Result<R> = std::result::Result<R, ParseError>;

pub(crate) trait BytesConcat<R> {
    fn concat(self) -> R;
}
impl BytesConcat<u16> for (u8, u8) {
    fn concat(self) -> u16 {
        ((self.0 as u16) << 8) | (self.1 as u16)
    }
}

trait BytesToUtf8 {
    fn to_utf8(self) -> String;
}

impl BytesToUtf8 for &[u8] {
    fn to_utf8(self) -> String {
        String::from_utf8(self.to_vec()).unwrap_or("".to_owned())
    }
}
