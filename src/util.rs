extern crate derive_more;

use crate::addresses::Addr;
use crate::error::{ParseError, SerializationError, SerializationResult};
use crate::parse::{self, BytesStreamReader};
use std::convert::TryFrom;
use std::fmt::Display;

pub(crate) const PROTOCOL_MAGIC: u8 = 95;
pub(crate) const PROTOCOL_VERSION: u8 = 0;

/* #region PeerID */

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub(crate) struct PeerID(u64);

impl PeerID {
    pub(crate) fn new() -> PeerID {
        PeerID(0) //TODO
    }

    fn from_bytes(recv: &[u8]) -> Option<PeerID> {
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

impl ToBytes for PeerID {
    fn to_bytes(&self) -> Vec<u8> {
        let bytes = vec![];
        for i in 0..8 {
            bytes.push(((self.0 >> (8 * i)) & 0xff) as u8); // cannot overflow
        }
        bytes.reverse();
        bytes
    }
}

/* #endregion */

/* #region MessageId */

pub(crate) type MessageId = (PeerID, [u8; 4]);

impl ToBytes for MessageId {
    fn to_bytes(&self) -> Vec<u8> {
        let bytes = vec![];
        bytes.extend(self.0.to_bytes());
        bytes.extend(self.1);
        bytes
    }
}

/* #endregion */

/* #region Data */

/// A wrapper for a vector of bytes that guarantees that
/// the bytes fits in a TLV.
#[derive(Debug)]
pub(crate) struct Data(Vec<u8>);
impl Data {
    const MAX_DATA_LENGTH: usize = 235; // 255 (max tlv value size) - 20 (message id size)

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        String::from_utf8(self.0).map_or_else(
            |_| f.write_fmt(format_args!("{:?}", self.0)),
            |str| str.fmt(f),
        )
    }
}

impl TryFrom<Vec<u8>> for Data {
    type Error = ParseError;

    /// Tries to wrap the vector of bytes in a new Data object.
    /// # Errors
    /// This method fails if the vector is too large to fit in a TLV.
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        if value.len() > Data::MAX_DATA_LENGTH {
            Err(ParseError::ProtocolViolation)
        } else {
            Ok(Data(value))
        }
    }
}

impl ToBytes for Data {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/* #endregion */

/* #region GoAwayReason */

#[derive(Debug)]
pub(crate) enum GoAwayReason {
    Unknown,
    EmitterLeaving,
    Inactivity,
    ProtocolViolation,
}

impl GoAwayReason {
    const CODE_EMITTER_LEAVING: u8 = 1;
    const CODE_INACTIVITY: u8 = 2;
    const CODE_PROTOCOL_VIOLATION: u8 = 3;

    fn from_code(code: u8) -> GoAwayReason {
        match code {
            GoAwayReason::CODE_EMITTER_LEAVING => GoAwayReason::EmitterLeaving,
            GoAwayReason::CODE_INACTIVITY => GoAwayReason::Inactivity,
            GoAwayReason::CODE_PROTOCOL_VIOLATION => GoAwayReason::ProtocolViolation,
            _ => GoAwayReason::Unknown,
        }
    }
    fn to_code(&self) -> u8 {
        match self {
            GoAwayReason::Unknown => 0,
            GoAwayReason::EmitterLeaving => GoAwayReason::CODE_EMITTER_LEAVING,
            GoAwayReason::Inactivity => GoAwayReason::CODE_INACTIVITY,
            GoAwayReason::ProtocolViolation => GoAwayReason::CODE_PROTOCOL_VIOLATION,
        }
    }
}

/* #endregion */

/* #region TagLengthValue */

#[derive(Debug)]
pub(crate) enum TagLengthValue {
    Pad1,
    PadN(usize),
    Hello(PeerID, Option<PeerID>),
    Neighbour(Addr),
    Data(MessageId, Data),
    Ack(MessageId),
    GoAway(GoAwayReason, String),
    Warning(String),
    Unrecognized(u8, Vec<u8>),
}

impl TagLengthValue {
    const TAG_ID_PAD1: u8 = 0;
    const TAG_ID_PADN: u8 = 1;
    const TAG_ID_HELLO: u8 = 2;
    const TAG_ID_NEIGHBOUR: u8 = 3;
    const TAG_ID_DATA: u8 = 4;
    const TAG_ID_ACK: u8 = 5;
    const TAG_ID_GO_AWAY: u8 = 6;
    const TAG_ID_WARNING: u8 = 7;

    pub(crate) fn try_parse(buffer: &mut parse::Buffer) -> Option<TagLengthValue> {
        let tag = buffer.next()?;
        if tag == TagLengthValue::TAG_ID_PAD1 {
            return Some(TagLengthValue::Pad1);
        }

        let length: usize = buffer.next()?.into();
        // Allows read_to_end to consume only the current TLV
        // Also allows to check that the specified TLV length is correct
        let buffer = buffer.extract(length)?;

        match tag {
            TagLengthValue::TAG_ID_PADN => {
                buffer.try_take(length)?; // Check the specified length is correct
                Some(TagLengthValue::PadN(length))
            }
            TagLengthValue::TAG_ID_HELLO => {
                if length != 8 && length != 16 {
                    return None;
                }

                let sender = buffer.try_take(8)?;
                let receiver = buffer.try_take(8);

                let sender_id = PeerID::from_bytes(sender)?;
                let receiver_id = PeerID::from_bytes(receiver.unwrap_or_else(|| &vec![]));

                Some(TagLengthValue::Hello(sender_id, receiver_id))
            }
            TagLengthValue::TAG_ID_NEIGHBOUR => {
                let content = buffer.try_take(length)?;
                let addr = Addr::from_bytes(content)?;
                Some(TagLengthValue::Neighbour(addr))
            }
            TagLengthValue::TAG_ID_DATA | TagLengthValue::TAG_ID_ACK => {
                let sender = buffer.try_take(8)?;
                let sender = PeerID::from_bytes(sender)?;

                let msg_id_bytes = buffer.try_take(4)?;
                let msg_id: [u8; 4] = [0; 4];
                msg_id.clone_from_slice(msg_id_bytes);

                if tag == TagLengthValue::TAG_ID_DATA {
                    let data = buffer.read_to_end().to_vec();
                    // Check
                    let data = Data::try_from(data).ok()?;

                    Some(TagLengthValue::Data((sender, msg_id), data))
                } else {
                    // ACK
                    Some(TagLengthValue::Ack((sender, msg_id)))
                }
            }
            TagLengthValue::TAG_ID_GO_AWAY => {
                let code = buffer.next()?;
                let reason = GoAwayReason::from_code(code);

                let msg = buffer.read_to_end().to_utf8();
                Some(TagLengthValue::GoAway(reason, msg))
            }
            TagLengthValue::TAG_ID_WARNING => {
                let msg = buffer.read_to_end().to_utf8();
                Some(TagLengthValue::Warning(msg))
            }
            id => {
                let data = buffer.read_to_end();
                Some(TagLengthValue::Unrecognized(id, data.to_vec()))
            }
        }
    }

    fn data_header(&self, tag: u8, msg_id: &MessageId, data_len: usize) -> Vec<u8> {
        let bytes = vec![tag];
        bytes.push((10 + data_len) as u8); // cannot overflow because data_len <= Data::MAX_DATA_LENGTH
        bytes.extend(msg_id.to_bytes());
        bytes
    }
}

impl<'arena> TryToBytes<'arena> for TagLengthValue {
    fn try_to_bytes(&'arena self) -> SerializationResult<'arena, Vec<u8>> {
        match self {
            TagLengthValue::Pad1 => Ok(vec![TagLengthValue::TAG_ID_PAD1]),
            TagLengthValue::PadN(size) => {
                let bytes = vec![TagLengthValue::TAG_ID_PADN, *size as u8]; // overflow ignored
                bytes.extend(std::iter::repeat(0).take(*size));
                Ok(bytes)
            }
            TagLengthValue::Hello(sender, receiver) => {
                let size: usize = if receiver.is_some() { 16 } else { 8 };
                let bytes = vec![TagLengthValue::TAG_ID_HELLO, size as u8]; // cannot overflow
                bytes.extend(sender.to_bytes());
                match receiver {
                    Some(id) => bytes.extend(id.to_bytes()),
                    _ => (),
                }
                Ok(bytes)
            }
            TagLengthValue::Neighbour(addr) => {
                let bytes = vec![
                    TagLengthValue::TAG_ID_NEIGHBOUR,
                    Addr::LENGTH_IN_BYTES as u8, // cannot overflow
                ];
                bytes.extend(addr.to_bytes());
                Ok(bytes)
            }
            TagLengthValue::Data(msg_id, data) => {
                let bytes = self.data_header(TagLengthValue::TAG_ID_DATA, msg_id, data.len());
                bytes.extend(data.to_bytes());
                Ok(bytes)
            }
            TagLengthValue::Ack(msg_id) => {
                Ok(self.data_header(TagLengthValue::TAG_ID_ACK, msg_id, 0))
            }
            TagLengthValue::GoAway(reason, msg) => {
                let msg_bytes = msg.as_bytes();
                if msg_bytes.len() > 254 {
                    // 255 (max TLV length) - 1 (code)
                    return Err(SerializationError::TagValueTooLarge(self));
                }

                let bytes = vec![
                    TagLengthValue::TAG_ID_GO_AWAY,
                    // cannot overflow
                    (msg_bytes.len() + 1) as u8,
                    reason.to_code(),
                ];
                bytes.extend(msg_bytes);
                Ok(bytes)
            }
            TagLengthValue::Warning(msg) => {
                let msg_bytes = msg.as_bytes();
                if msg_bytes.len() > 255 {
                    return Err(SerializationError::TagValueTooLarge(self));
                }

                let bytes = vec![
                    TagLengthValue::TAG_ID_WARNING,
                    // cannot overflow
                    msg_bytes.len() as u8,
                ];
                bytes.extend(msg_bytes);
                Ok(bytes)
            }
            _ => Err(SerializationError::UnsupportedTag(self)),
        }
    }
}

/* #endregion */

/* #region Message */

/// The type of a received message (the Addr element is the address of
/// the peer that sent the message), or of a message to be sent (the Addr element is
/// the address to the peer that should receive the message).
pub(crate) type Message = (Addr, Vec<TagLengthValue>);

impl<'arena> TryToBytes<'arena> for Message {
    fn try_to_bytes(&'arena self) -> SerializationResult<'arena, Vec<u8>> {
        let bytes = vec![PROTOCOL_MAGIC, PROTOCOL_VERSION];

        let body = vec![];
        for tlv in self.1 {
            body.extend(tlv.try_to_bytes()?);
        }
        if body.len() > 255 {
            return Err(SerializationError::MessageBodyTooLarge);
        }
        // cannot overflow
        bytes.push(body.len() as u8);
        bytes.extend(body);

        Ok(bytes)
    }
}

/* #endregion */

/* #region util trait implementations */

pub(crate) trait BytesConcat<R> {
    fn concat(self) -> R;
}
impl BytesConcat<u16> for (u8, u8) {
    fn concat(self) -> u16 {
        ((self.0 as u16) << 8) | (self.1 as u16)
    }
}

pub(crate) trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}
pub(crate) trait TryToBytes<'arena> {
    fn try_to_bytes(&'arena self) -> SerializationResult<'arena, Vec<u8>>;
}

impl ToBytes for u16 {
    fn to_bytes(&self) -> Vec<u8> {
        vec![(self >> 8) as u8, (self & 0xff) as u8] // cannot overflow
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

/* #endregion */
