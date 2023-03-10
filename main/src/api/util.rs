//! This modules contains miscellaneous structures that
//! are used by the internal API.

extern crate derive_more;
extern crate rand;

use self::rand::RngCore;

use self::derive_more::Display;
use super::addresses::Addr;
use super::error::{LimitedStringError, UnsupportedTag};
use super::parse;
use std::collections::LinkedList;
use std::convert::TryFrom;
use std::rc::Rc;

pub(super) const PROTOCOL_MAGIC: u8 = 95;
pub(super) const PROTOCOL_VERSION: u8 = 0;
const MAX_SDU_SIZE: usize = 1024;

pub(super) static EMPTY_BYTE_VEC: Vec<u8> = vec![];

/* #region PeerID */

/// The ID of a client.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Display)]
#[display(fmt = "{_0}")]
pub struct PeerID(u64);

impl PeerID {
    /// Creates a new random ID using the given `RngCore`.
    pub fn new<T: RngCore>(rng: &mut T) -> Self {
        Self(rng.next_u64())
    }

    fn try_parse(buffer: &mut parse::Buffer) -> Option<Self> {
        let id = buffer.next_u64()?;
        Some(Self(id))
    }

    const LENGTH_IN_BYTES: usize = 8;
    const fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/* #endregion */

/* #region MessageId */

/// The ID of a message
#[derive(Debug, Display, PartialEq, Eq, Hash, Clone, Copy)]
#[display(fmt = "({_0}, {_1})")]
pub struct MessageId(PeerID, u32);

impl MessageId {
    const LENGTH_IN_BYTES: usize = PeerID::LENGTH_IN_BYTES + 4;
    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.0.to_bytes());
        bytes.extend(self.1.to_be_bytes());
        bytes
    }
    fn try_parse(buffer: &mut parse::Buffer) -> Option<Self> {
        let sender = PeerID::try_parse(buffer)?;
        let id = buffer.next_u32()?;
        Some(Self(sender, id))
    }
}

impl From<(PeerID, u32)> for MessageId {
    fn from(value: (PeerID, u32)) -> Self {
        Self(value.0, value.1)
    }
}

/* #endregion */

/* #region LimitedString */

/// A wrapper for a String whose byte
/// representation must take at most S bytes.
#[derive(Debug, Display, Clone)]
#[display(fmt = "{_0}")]
pub(super) struct LimitedString<const S: usize>(String);

impl<const S: usize> TryFrom<String> for LimitedString<S> {
    type Error = LimitedStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > S {
            Err(LimitedStringError::StringTooLarge)
        } else {
            Ok(Self(value))
        }
    }
}
impl<const S: usize> TryFrom<&[u8]> for LimitedString<S> {
    type Error = LimitedStringError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > S {
            Err(LimitedStringError::StringTooLarge)
        } else {
            let str = std::str::from_utf8(value).map_err(LimitedStringError::InvalidUtf8String)?;
            Ok(Self(str.to_owned()))
        }
    }
}

impl<const S: usize> LimitedString<S> {
    pub fn len_in_bytes(&self) -> usize {
        self.0.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Creates a `LimitedString` from the specified string, assuming it
    /// is less than `S`-byte long.
    /// ### Safety:
    /// The value given must be such that `value.len() <= S`.
    /// ### Note:
    /// This internal function avoids unnecessary wrapping and unwrapping if the size
    /// of the `value` has already been checked. It is not intended for general use.
    unsafe fn from_str_unchecked(value: &str) -> LimitedString<S> {
        Self(value.to_owned())
    }
}

/* #endregion */

/* #region Data */

const DATA_MAX_SIZE: usize = 243;

#[derive(Debug, Clone)]
pub(super) struct Data(Result<LimitedString<DATA_MAX_SIZE>, Vec<u8>>);

impl TryFrom<&[u8]> for Data {
    type Error = LimitedStringError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match LimitedString::try_from(value) {
            Ok(msg) => Ok(Data(Ok(msg))),
            Err(LimitedStringError::InvalidUtf8String(_)) => Ok(Data(Err(value.to_owned()))),
            Err(err) => Err(err),
        }
    }
}

impl Data {
    pub fn len_in_bytes(&self) -> usize {
        match &self.0 {
            Ok(msg) => msg.len_in_bytes(),
            Err(raw) => raw.len(),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Ok(msg) => msg.as_bytes(),
            Err(raw) => raw.as_slice(),
        }
    }
    pub fn to_string(&self) -> Option<&LimitedString<DATA_MAX_SIZE>> {
        match &self.0 {
            Ok(msg) => Some(msg),
            Err(_) => None,
        }
    }

    /// Divides a string value in multiple `Data`s,
    /// such as all `Data`s start with the specified `header`,
    /// contain a valid UTF-8 string,
    /// and the concatenation of the `Data`s without the `header` is the
    /// initial value.
    pub fn pack(header: Option<String>, value: &str) -> Vec<Self> {
        let header_size = header.as_ref().map_or(0, String::len);

        // Check that it is always possible to put (at least) the header +
        // one UTF-8 char in one Data object.
        debug_assert!(header_size + 4 <= DATA_MAX_SIZE);

        let initial_value = header.unwrap_or_default();

        if header_size + value.len() <= DATA_MAX_SIZE {
            let value = initial_value + value;
            // Safety: header_size + value.len() <= DATA_MAX_SIZE
            return vec![unsafe { Self(Ok(LimitedString::from_str_unchecked(&value))) }];
        }

        let mut vec = vec![];
        let mut str = initial_value.clone();

        for c in value.chars() {
            if str.len() + c.len_utf8() <= DATA_MAX_SIZE {
                str.push(c);
            } else {
                // Safety: str.len() <= DATA_MAX_SIZE is an invariant.
                vec.push(unsafe { Self(Ok(LimitedString::from_str_unchecked(&str))) });

                str = initial_value.clone();
                str.push(c);
            }
        }

        vec
    }
}

/* #endregion */

/* #region GoAwayReason */

/// Reason for a "GoAway" TLV.
#[derive(Debug)]
pub enum GoAwayReason {
    Unknown,
    EmitterLeaving,
    Inactivity,
    ProtocolViolation,
}

impl GoAwayReason {
    const CODE_EMITTER_LEAVING: u8 = 1;
    const CODE_INACTIVITY: u8 = 2;
    const CODE_PROTOCOL_VIOLATION: u8 = 3;

    const fn from_code(code: u8) -> Self {
        match code {
            Self::CODE_EMITTER_LEAVING => Self::EmitterLeaving,
            Self::CODE_INACTIVITY => Self::Inactivity,
            Self::CODE_PROTOCOL_VIOLATION => Self::ProtocolViolation,
            _ => Self::Unknown,
        }
    }
    const fn to_code(&self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::EmitterLeaving => Self::CODE_EMITTER_LEAVING,
            Self::Inactivity => Self::CODE_INACTIVITY,
            Self::ProtocolViolation => Self::CODE_PROTOCOL_VIOLATION,
        }
    }

    const LENGTH_IN_BYTES: usize = 1;
}

/* #endregion */

/* #region TagLengthValue */

/// Structure that represents a TLV.
#[derive(Debug)]
pub(super) enum TagLengthValue {
    Pad1,
    PadN(usize),
    Hello(PeerID, Option<PeerID>),
    Neighbour(Addr),
    // Note: currently, only UTF-8 data can be sent.
    // Non UTF-8 data can be received without triggering a protocol violation,
    // but they will be ignored.
    Data(MessageId, Data),
    Ack(MessageId),
    // None => no message specified
    // Some(Err(_)) => invalid UTF-8 message specified
    // Some(Ok(_)) => self-explanatory
    GoAway(
        GoAwayReason,
        Option<Result<LimitedString<254>, LimitedStringError>>,
    ),
    Warning(Result<LimitedString<255>, LimitedStringError>),
    /// A special value for TLVs that have not been recognized.
    /// Contains the raw tag id of the TLV. The content is discarded because it
    /// would not be used anyway.
    ///
    /// This TLV cannot be sent.
    Unrecognized(u8),
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
    /// If the parsing succeeds, the buffer is advanced by the size of the tag.
    /// If the parsing fails (i.e. this function returns None),
    /// the buffer is left in an unspecified state. The bytes read until the error
    /// is detected are lost.
    pub fn try_parse(buffer: &mut parse::Buffer) -> Option<Self> {
        let tag = buffer.next()?;
        if tag == Self::TAG_ID_PAD1 {
            return Some(Self::Pad1);
        }

        let length: usize = buffer.next()?.into();
        // Allows `read_to_end` to consume only the current TLV
        // Also allows to check that the specified TLV length is correct
        let mut buffer = buffer.extract(length)?;

        match tag {
            TagLengthValue::TAG_ID_PADN => Some(TagLengthValue::PadN(length)),

            TagLengthValue::TAG_ID_HELLO => {
                let sender_id = PeerID::try_parse(&mut buffer)?;
                let receiver_id = PeerID::try_parse(&mut buffer);
                buffer.ensure_empty()?;
                Some(TagLengthValue::Hello(sender_id, receiver_id))
            }

            TagLengthValue::TAG_ID_NEIGHBOUR => {
                let addr = Addr::try_parse(&mut buffer)?;
                buffer.ensure_empty()?;
                Some(TagLengthValue::Neighbour(addr))
            }

            TagLengthValue::TAG_ID_DATA | TagLengthValue::TAG_ID_ACK => {
                let msg_id = MessageId::try_parse(&mut buffer)?;

                if tag == TagLengthValue::TAG_ID_DATA {
                    match Data::try_from(buffer.read_to_end()) {
                        Ok(data) => Some(TagLengthValue::Data(msg_id, data)),
                        Err(_) => None, // unreachable
                    }
                } else {
                    // ACK
                    Some(TagLengthValue::Ack(msg_id))
                }
            }

            TagLengthValue::TAG_ID_GO_AWAY => {
                let code = buffer.next()?;
                let reason = GoAwayReason::from_code(code);

                let msg = buffer
                    .has_next()
                    .then(|| LimitedString::try_from(buffer.read_to_end()));
                Some(TagLengthValue::GoAway(reason, msg))
            }

            TagLengthValue::TAG_ID_WARNING => {
                let msg = LimitedString::try_from(buffer.read_to_end());
                Some(TagLengthValue::Warning(msg))
            }

            id => Some(TagLengthValue::Unrecognized(id)),
        }
    }

    /// Returns the first part of a Data or an Ack TLV
    /// The first part is defined as: [tag, length, message id...], that is, the TLV
    /// without the datum.
    /// For the Ack TLV, this is actually the whole TLV.
    fn data_header(tag: u8, msg_id: &MessageId, data_len: usize) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.push((12 + data_len) as u8); // cannot overflow because data_len <= 235
        bytes.extend(msg_id.to_bytes());
        bytes
    }

    /// Returns the total number of bytes required to serialize this TLV (including the header),
    /// without computing the actual serialization yet.
    /// This function MUST return the correct value, otherwise the
    /// functions that rely on it will have an unspecified behaviour.
    fn byte_len(&self) -> usize {
        match self {
            Self::Pad1 => 1,
            Self::PadN(size) => Self::HEADER_SIZE + size,
            Self::Hello(_, Some(_)) => Self::HEADER_SIZE + 2 * PeerID::LENGTH_IN_BYTES,
            Self::Hello(_, _) => Self::HEADER_SIZE + PeerID::LENGTH_IN_BYTES,
            Self::Neighbour(_) => Self::HEADER_SIZE + Addr::LENGTH_IN_BYTES,
            Self::Data(_, data) => {
                Self::HEADER_SIZE + MessageId::LENGTH_IN_BYTES + data.len_in_bytes()
            }
            Self::Ack(_) => Self::HEADER_SIZE + MessageId::LENGTH_IN_BYTES,
            Self::GoAway(_, Some(Ok(msg))) => {
                Self::HEADER_SIZE + GoAwayReason::LENGTH_IN_BYTES + msg.len_in_bytes()
            }
            Self::GoAway(_, _) => Self::HEADER_SIZE + GoAwayReason::LENGTH_IN_BYTES,
            Self::Warning(msg) => {
                Self::HEADER_SIZE
                    + msg
                        .as_ref()
                        .map(LimitedString::len_in_bytes)
                        .unwrap_or_default()
            }
            _ => 0,
        }
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>, UnsupportedTag> {
        match self {
            TagLengthValue::Pad1 => Ok(vec![TagLengthValue::TAG_ID_PAD1]),

            TagLengthValue::PadN(size) => {
                let mut bytes = vec![TagLengthValue::TAG_ID_PADN, *size as u8]; // overflow ignored
                bytes.extend(std::iter::repeat(0u8).take(*size));
                Ok(bytes)
            }

            TagLengthValue::Hello(sender, receiver) => {
                let size = if receiver.is_some() { 16u8 } else { 8u8 };
                let mut bytes = vec![TagLengthValue::TAG_ID_HELLO, size];
                bytes.extend(sender.to_bytes());
                if let Some(id) = receiver {
                    bytes.extend(id.to_bytes());
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
                    Self::data_header(TagLengthValue::TAG_ID_DATA, msg_id, data.len_in_bytes());
                bytes.extend(data.as_bytes());
                Ok(bytes)
            }

            TagLengthValue::Ack(msg_id) => {
                Ok(Self::data_header(TagLengthValue::TAG_ID_ACK, msg_id, 0))
            }

            TagLengthValue::GoAway(reason, msg) => {
                // Flatten &Option<Result<T, _>> into Option<&T>
                #[allow(clippy::shadow_unrelated)]
                let msg = msg.as_ref().and_then(|msg| msg.as_ref().ok());

                let mut bytes = vec![
                    TagLengthValue::TAG_ID_GO_AWAY,
                    // cannot overflow
                    (msg.as_ref().map_or(0, |m| m.len_in_bytes()) + 1) as u8,
                    reason.to_code(),
                ];
                bytes.extend(msg.map_or(&*EMPTY_BYTE_VEC, LimitedString::as_bytes));
                Ok(bytes)
            }

            TagLengthValue::Warning(msg) => {
                let msg_bytes = msg
                    .as_ref()
                    .map(LimitedString::as_bytes)
                    .map_err(|_err| UnsupportedTag)?;

                let mut bytes = vec![
                    TagLengthValue::TAG_ID_WARNING,
                    // cannot overflow
                    msg_bytes.len() as u8,
                ];
                bytes.extend(msg_bytes);
                Ok(bytes)
            }

            _ => Err(UnsupportedTag),
        }
    }
}

/* #endregion */

/* #region MessageFactory */

/// A private enum used by `MessageFactory` to allow
/// storage of pre-computed byte representation of TLVS.
#[derive(Debug)]
enum MessagePart {
    TLV(Rc<TagLengthValue>),
    Precomputed(Rc<[u8]>),
}

impl MessagePart {
    fn len_in_bytes(&self) -> usize {
        match self {
            MessagePart::TLV(tlv) => tlv.byte_len(),
            MessagePart::Precomputed(bytes) => bytes.len(),
        }
    }
    fn to_bytes(&self) -> Rc<[u8]> {
        match self {
            MessagePart::TLV(tlv) => Rc::from(tlv.try_to_bytes().unwrap_or_default()),
            MessagePart::Precomputed(bytes) => Rc::clone(bytes),
        }
    }
}

/// A buffered queue-like factory to construct service data units.
pub(super) struct MessageFactory {
    total_bytes: usize,
    buffer: LinkedList<MessagePart>,
}

impl MessageFactory {
    pub const fn new() -> MessageFactory {
        MessageFactory {
            total_bytes: 0,
            buffer: LinkedList::new(),
        }
    }

    /// Enqueues one TLV
    pub fn enqueue_tlv(&mut self, tlv: Rc<TagLengthValue>) {
        self.total_bytes += tlv.byte_len();
        self.buffer.push_back(MessagePart::TLV(tlv));
    }

    /// Enqueues multiple TLVs at once.
    pub fn enqueue_many_tlvs(&mut self, tlvs: &[Rc<TagLengthValue>]) {
        self.total_bytes += tlvs.iter().fold(0, |acc, elt| acc + elt.byte_len());
        self.buffer
            .extend(tlvs.iter().map(|t| MessagePart::TLV(Rc::clone(t))));
    }

    /// Enqueues a precomputed byte representation of a single TLV.
    /// The bytes must correspond to a single TLV.
    /// Enqueuing multiple TLVs using this function is not supported (because it is not
    /// useful in the program) and may lead to unexpected results.
    pub fn enqueue_precomputed(&mut self, bytes: Rc<[u8]>) {
        debug_assert!(bytes.len() < MAX_SDU_SIZE - 4);
        self.total_bytes += bytes.len();
        self.buffer.push_back(MessagePart::Precomputed(bytes));
    }

    /// Indicates whether the queue is full enough to build a complete
    /// datagram (leaving as few blanks as possible) and should be flushed.
    pub const fn should_flush(&self) -> bool {
        self.total_bytes >= MAX_SDU_SIZE - 4
    }

    /// Builds a single SDU from the queue, by concatenating
    /// as many enqueued TLVs as possible without exceeding the
    /// maximum length of a SDU. Those TLVs are removed from the queue.
    /// This function uses a greedy algorithm. The TLVs that were enqueued
    /// first are given a higher priority.
    /// The returned value should be sent as-is.
    /// When this method returns, there may still be TLVs in the queue.
    pub fn build_next(&mut self) -> Option<Vec<u8>> {
        let mut vec = vec![PROTOCOL_MAGIC, PROTOCOL_VERSION, 0u8, 0u8];

        let mut cursor = self.buffer.cursor_front_mut();
        while let Some(part) = cursor.current() {
            if vec.len() + part.len_in_bytes() < MAX_SDU_SIZE {
                vec.extend(part.to_bytes().iter());
                debug_assert!(part.len_in_bytes() == part.to_bytes().len());

                self.total_bytes -= part.len_in_bytes();
                cursor.remove_current();
            } else {
                cursor.move_next();
            }
        }

        if vec.len() == 4 {
            return None;
        }

        let size = (vec.len() as u16 - 4).to_be_bytes();
        vec[2] = size[0];
        vec[3] = size[1];

        Some(vec)
    }
}

/* #endregion */
