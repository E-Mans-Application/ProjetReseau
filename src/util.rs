extern crate derive_more;

use self::derive_more::Display;
use crate::addresses::Addr;
use crate::error::{ParseError, ParseResult, SerializationError, SerializationResult};
use crate::parse::{self, BytesStreamReader};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::rc::Rc;

pub(crate) const PROTOCOL_MAGIC: u8 = 95;
pub(crate) const PROTOCOL_VERSION: u8 = 0;
pub(crate) const MAX_SDU_SIZE: usize = 1024;

pub(crate) static EMPTY_BYTE_VEC: Vec<u8> = vec![];

/* #region PeerID */

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub(crate) struct PeerID(u64);

impl PeerID {
    pub(crate) fn new() -> PeerID {
        PeerID(0) //TODO
    }

    fn from_bytes(recv: &[u8]) -> Option<PeerID> {
        if recv.len() != PeerID::LENGTH_IN_BYTES {
            return None;
        }

        let mut val: u64 = 0;
        for i in 0..8 {
            val <<= 8;
            val |= recv[i] as u64;
        }
        Some(PeerID(val))
    }
}

impl ConstantByteLength for PeerID {
    const LENGTH_IN_BYTES: usize = 8;
}

impl ToBytes for PeerID {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        for i in 0..8 {
            bytes.push(((self.0 >> (8 * i)) & 0xff) as u8); // cannot overflow
        }
        bytes.reverse();
        bytes
    }
}

/* #endregion */

/* #region MessageId */

pub(crate) type MessageId = (PeerID, u32);

impl ConstantByteLength for MessageId {
    const LENGTH_IN_BYTES: usize = PeerID::LENGTH_IN_BYTES + 4;
}

impl ToBytes for MessageId {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.0.to_bytes());
        bytes.extend(self.1.to_le_bytes());
        bytes
    }
}

/* #endregion */

/* #region LimitedString */

/// A wrapper for a String whose byte
/// representation must take at most S bytes.
/// If S is equal to 0, the type will not be constructible
/// because even the empty string needs at least one byte.
#[derive(Debug, Display, Clone)]
#[display(fmt = "{_0}")]
pub(crate) struct LimitedString<const S: usize>(String, Vec<u8>);

impl<const S: usize> TryFrom<String> for LimitedString<S> {
    type Error = SerializationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if bytes.len() > S {
            Err(SerializationError::StringTooLarge(value))
        } else {
            let bytes = bytes.to_vec();
            Ok(LimitedString(value, bytes))
        }
    }
}

impl<const S: usize> TryFrom<Vec<u8>> for LimitedString<S> {
    type Error = ParseError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > S {
            Err(ParseError::ProtocolViolation)
        } else {
            let str = std::str::from_utf8(&value).map_err(|_| ParseError::InvalidUtf8String)?;
            Ok(LimitedString(str.to_owned(), value))
        }
    }
}

impl<const S: usize> TryFrom<&[u8]> for LimitedString<S> {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.to_vec())
    }
}

impl<const S: usize> ToBytes for LimitedString<S> {
    fn to_bytes(&self) -> Vec<u8> {
        self.1.clone()
    }
}

impl<const S: usize> LimitedString<S> {
    /// Forces wrapping the String value in a LimitedString.
    ///
    /// Because this method may panic, its use is discouraged except
    /// with String literals whose size in bytes is known to be compatible.
    ///
    /// Instead, prefer to use try_from and use pattern matching on the result.
    /// # Panics
    /// Panics if the string does not fit in the LimitedString.
    pub(crate) fn force_from_string(value: String) -> LimitedString<S> {
        LimitedString::try_from(value).unwrap()
    }
}

impl<const S: usize> LimitedString<S> {
    pub(crate) fn len_in_bytes(&self) -> usize {
        self.1.len()
    }

    pub(crate) fn pack(value: &str) -> Vec<LimitedString<S>> {
        let mut vec = vec![];
        if value.is_empty() {
            return vec;
        }

        let mut i = std::cmp::min(value.len(), S / 4); // UTF-8 chars take at most 4 bytes
        let mut bytes = value[0..i].as_bytes().to_vec();
        assert!(bytes.len() <= S);

        while bytes.len() < S && i < value.len() {
            let b = value[i..(i + 1)].as_bytes().to_vec();
            if bytes.len() + b.len() <= S {
                bytes.extend(b);
                i += 1;
            } else {
                break;
            }
        }

        assert!(bytes.len() <= S);

        vec.push(LimitedString(value[0..i].to_owned(), bytes));
        if i < value.len() {
            vec.extend(LimitedString::pack(&value[i..]));
        }
        vec
    }
}

pub(crate) type Data = LimitedString<235>;

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

impl ConstantByteLength for GoAwayReason {
    const LENGTH_IN_BYTES: usize = 1;
}
impl ToBytes for GoAwayReason {
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.to_code()]
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
    Data(MessageId, Rc<Data>),
    Ack(MessageId),
    GoAway(GoAwayReason, Option<ParseResult<LimitedString<254>>>),
    Warning(LimitedString<255>),
    /// A special value for received TLVs that have not been recognized.
    /// Contains the raw tag id and the raw value of the TLV.
    /// This TLV cannot be sent.
    Unrecognized(u8, Vec<u8>),
    /// A special value for received TLVs that were recognized and
    /// well-formed, but
    Illegal(u8, ParseError),
}

impl TagLengthValue {
    const HEADER_SIZE: usize = 2;

    const TAG_ID_PAD1: u8 = 0;
    const TAG_ID_PADN: u8 = 1;
    const TAG_ID_HELLO: u8 = 2;
    const TAG_ID_NEIGHBOUR: u8 = 3;
    const TAG_ID_DATA: u8 = 4;
    const TAG_ID_ACK: u8 = 5;
    const TAG_ID_GO_AWAY: u8 = 6;
    const TAG_ID_WARNING: u8 = 7;

    /// Try to parse a TLV from the buffer, consuming all the bytes
    /// constituting the TLV.
    /// Only one byte is consumed if the first byte is PAD1.
    /// Otherwise, the second byte is consumed and assumed to be the length of the TLV;
    /// then 'length' more bytes are consumed in any case, even if the TLV is unrecognized
    /// or ill-formed.
    pub(crate) fn try_parse(buffer: &mut parse::Buffer) -> Option<TagLengthValue> {
        let tag = buffer.next()?;
        if tag == TagLengthValue::TAG_ID_PAD1 {
            return Some(TagLengthValue::Pad1);
        }

        let length: usize = buffer.next()?.into();
        // Allows read_to_end to consume only the current TLV
        // Also allows to check that the specified TLV length is correct
        let mut buffer = buffer.extract(length)?;

        match tag {
            TagLengthValue::TAG_ID_PADN => Some(TagLengthValue::PadN(length)),
            TagLengthValue::TAG_ID_HELLO => {
                if length != 8 && length != 16 {
                    return None;
                }

                let sender = buffer.try_take(8)?;
                let receiver = buffer.try_take(8);

                let sender_id = PeerID::from_bytes(sender)?;
                let receiver_id = PeerID::from_bytes(receiver.unwrap_or_else(|| &EMPTY_BYTE_VEC));

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
                let mut msg_id: [u8; 4] = [0; 4];
                msg_id.clone_from_slice(msg_id_bytes);

                if tag == TagLengthValue::TAG_ID_DATA {
                    let data = buffer.read_to_end().to_vec();
                    // Check
                    let data = Data::try_from(data).ok()?;

                    Some(TagLengthValue::Data(
                        (sender, msg_id.concat()),
                        Rc::new(data),
                    ))
                } else {
                    // ACK
                    Some(TagLengthValue::Ack((sender, msg_id.concat())))
                }
            }
            TagLengthValue::TAG_ID_GO_AWAY => {
                let code = buffer.next()?;
                let reason = GoAwayReason::from_code(code);

                let msg = if buffer.has_next() {
                    Some(LimitedString::try_from(buffer.read_to_end()))
                } else {
                    None
                };
                Some(TagLengthValue::GoAway(reason, msg))
            }
            TagLengthValue::TAG_ID_WARNING => {
                let msg = LimitedString::try_from(buffer.read_to_end());
                msg.map_or_else(
                    |err| Some(TagLengthValue::Illegal(tag, err)),
                    |str| Some(TagLengthValue::Warning(str)),
                )
            }
            id => {
                let data = buffer.read_to_end();
                Some(TagLengthValue::Unrecognized(id, data.to_vec()))
            }
        }
    }

    fn data_header(&self, tag: u8, msg_id: &MessageId, data_len: usize) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.push((10 + data_len) as u8); // cannot overflow because data_len <= Data::MAX_DATA_LENGTH
        bytes.extend(msg_id.to_bytes());
        bytes
    }

    /// Returns the total number of bytes required to serialize this TLV (including the header),
    /// without computing the actual serialization yet.
    fn byte_len(&self) -> usize {
        match self {
            TagLengthValue::Pad1 => 1,
            TagLengthValue::PadN(size) => TagLengthValue::HEADER_SIZE + size,
            TagLengthValue::Hello(_, Some(_)) => {
                TagLengthValue::HEADER_SIZE + 2 * PeerID::LENGTH_IN_BYTES
            }
            TagLengthValue::Hello(_, _) => TagLengthValue::HEADER_SIZE + PeerID::LENGTH_IN_BYTES,
            TagLengthValue::Neighbour(_) => TagLengthValue::HEADER_SIZE + Addr::LENGTH_IN_BYTES,
            TagLengthValue::Data(_, data) => {
                TagLengthValue::HEADER_SIZE + MessageId::LENGTH_IN_BYTES + data.len_in_bytes()
            }
            TagLengthValue::Ack(_) => TagLengthValue::HEADER_SIZE + MessageId::LENGTH_IN_BYTES,
            TagLengthValue::GoAway(_, Some(Ok(msg))) => {
                TagLengthValue::HEADER_SIZE + GoAwayReason::LENGTH_IN_BYTES + msg.len_in_bytes()
            }
            TagLengthValue::GoAway(_, _) => {
                TagLengthValue::HEADER_SIZE + GoAwayReason::LENGTH_IN_BYTES
            }
            TagLengthValue::Warning(msg) => TagLengthValue::HEADER_SIZE + msg.len_in_bytes(),
            _ => 0,
        }
    }
}

impl TryToBytes for TagLengthValue {
    fn try_to_bytes(&self) -> SerializationResult<Vec<u8>> {
        match self {
            TagLengthValue::Pad1 => Ok(vec![TagLengthValue::TAG_ID_PAD1]),
            TagLengthValue::PadN(size) => {
                let mut bytes = vec![TagLengthValue::TAG_ID_PADN, *size as u8]; // overflow ignored
                bytes.extend(std::iter::repeat(0).take(*size));
                Ok(bytes)
            }
            TagLengthValue::Hello(sender, receiver) => {
                let size: usize = if receiver.is_some() { 16 } else { 8 };
                let mut bytes = vec![TagLengthValue::TAG_ID_HELLO, size as u8]; // cannot overflow
                bytes.extend(sender.to_bytes());
                match receiver {
                    Some(id) => bytes.extend(id.to_bytes()),
                    _ => (),
                }
                Ok(bytes)
            }
            TagLengthValue::Neighbour(addr) => {
                let mut bytes = vec![
                    TagLengthValue::TAG_ID_NEIGHBOUR,
                    Addr::LENGTH_IN_BYTES as u8, // cannot overflow
                ];
                bytes.extend(addr.to_bytes());
                Ok(bytes)
            }
            TagLengthValue::Data(msg_id, data) => {
                let mut bytes =
                    self.data_header(TagLengthValue::TAG_ID_DATA, msg_id, data.len_in_bytes());
                bytes.extend(data.to_bytes());
                Ok(bytes)
            }
            TagLengthValue::Ack(msg_id) => {
                Ok(self.data_header(TagLengthValue::TAG_ID_ACK, msg_id, 0))
            }
            TagLengthValue::GoAway(reason, msg) => {
                let msg_bytes = match msg {
                    Some(msg) => msg.as_ref().map_or_else(|_| vec![], |msg| msg.to_bytes()),
                    None => vec![],
                };

                let mut bytes = vec![
                    TagLengthValue::TAG_ID_GO_AWAY,
                    // cannot overflow
                    (msg_bytes.len() + 1) as u8,
                    reason.to_code(),
                ];
                bytes.extend(msg_bytes);
                Ok(bytes)
            }
            TagLengthValue::Warning(msg) => {
                let msg_bytes = msg.to_bytes();

                let mut bytes = vec![
                    TagLengthValue::TAG_ID_WARNING,
                    // cannot overflow
                    msg_bytes.len() as u8,
                ];
                bytes.extend(msg_bytes);
                Ok(bytes)
            }
            _ => Err(SerializationError::UnsupportedTag),
        }
    }
}

/* #endregion */

/* #region ServiceDataUnit */

pub(crate) type ServiceDataUnit = Vec<TagLengthValue>;

impl TryToBytes for ServiceDataUnit {
    fn try_to_bytes(&self) -> SerializationResult<Vec<u8>> {
        let mut bytes = vec![PROTOCOL_MAGIC, PROTOCOL_VERSION];

        let mut body = vec![];
        for tlv in self.iter() {
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

/// A factory to split multiple TagLengthValues into multiple service data units.
pub(crate) struct ServiceDataUnitFactory(VecDeque<TagLengthValue>);

impl ServiceDataUnitFactory {
    /// Creates a new ServiceDataUnitFactory from the specified queue.
    pub(crate) fn new(queue: VecDeque<TagLengthValue>) -> ServiceDataUnitFactory {
        ServiceDataUnitFactory(queue)
    }

    /// Consumes as much TLVs as possible from the queue,
    /// until the queue is empty or the next TLVs no longer
    /// fit into a single datagram.
    /// The initial order of the TLVs is kept.
    /// Returns a list of TLVs that can be sent in a single datagram.
    /// If the queue is already empty, an empty vector is returned.
    pub(crate) fn next_message(&mut self) -> ServiceDataUnit {
        let mut size = 4;
        let mut sdus = vec![];

        loop {
            let tlv = self.0.pop_front();
            match tlv {
                None => break,
                Some(tlv) => {
                    let tlv_len = tlv.byte_len();
                    if size + tlv_len <= MAX_SDU_SIZE {
                        sdus.push(tlv);
                        size += tlv_len;
                    } else {
                        self.0.push_front(tlv);
                        break;
                    }
                }
            }
        }
        sdus
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
impl BytesConcat<u32> for [u8; 4] {
    fn concat(self) -> u32 {
        ((self[0] as u32) << 24)
            | ((self[1] as u32) << 16)
            | ((self[2] as u32) << 8)
            | (self[3] as u32)
    }
}

pub(crate) trait ConstantByteLength: ToBytes {
    const LENGTH_IN_BYTES: usize;
}

pub(crate) trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}
pub(crate) trait TryToBytes {
    fn try_to_bytes(&self) -> SerializationResult<Vec<u8>>;
}

impl TryToBytes for Vec<u8> {
    fn try_to_bytes(&self) -> SerializationResult<Vec<u8>> {
        Ok(self.clone())
    }
}

impl ConstantByteLength for u16 {
    const LENGTH_IN_BYTES: usize = 2;
}

impl ToBytes for u16 {
    fn to_bytes(&self) -> Vec<u8> {
        vec![(self >> 8) as u8, (self & 0xff) as u8] // cannot overflow
    }
}

/* #endregion */
