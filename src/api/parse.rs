//! This modules contains some of the objects used to parse
//! UDP datagrams.
//! An important part of the work is done by `TagLengthValue` in `util`.

use crate::lazy_format;

use super::addresses::Addr;
use super::error::{ParseError, ParseResult};
use super::logging::EventLog;
use super::util::{self, TagLengthValue};
use std::convert::TryInto;
use std::net::UdpSocket;

macro_rules! from_be_bytes {
    // unwrap will not panic because the macro is called with the right number of
    // bytes for each data type
    ($a:expr, $t:ty) => {
        <$t>::from_be_bytes($a.try_into().unwrap())
    };
}

/// A queue-like wrapper to a contiguous byte buffer.
/// The implementation maintains a cursor into the underlying data,
/// the cursor is advanced after each read operation.
pub struct Buffer<'arena> {
    wrapped: &'arena [u8],
    pos: usize,
}

impl<'arena> Buffer<'arena> {
    /// Creates a new buffer from the given datagram.
    pub const fn new(wrapped: &'arena [u8]) -> Buffer<'arena> {
        Buffer { wrapped, pos: 0 }
    }

    /// Shrinks the buffer to a new size, discarding the bytes
    /// that no longer fit into it.
    /// When this method succeeds, [` self.remaining() `] shall
    /// return [` new_len `].
    /// ### Errors
    /// If [` new_len `] > [` self.remaining() `], this method has no
    /// effect and Err(()) is returned. The buffer remains in a valid state.
    pub fn shrink(&mut self, new_len: usize) -> Result<(), ()> {
        if self.remaining() < new_len {
            Err(())
        } else {
            self.wrapped = &self.wrapped[self.pos..(self.pos + new_len)];
            self.pos = 0;
            Ok(())
        }
    }

    /// Shortcut to the len of the wrapped array. Internal use only.
    const fn len(&self) -> usize {
        self.wrapped.len()
    }

    /// Returns the number of bytes that can still be read.
    pub const fn remaining(&self) -> usize {
        self.wrapped.len() - self.pos
    }

    /// Tells whether there is still bytes to consume, without consuming them.
    pub const fn has_next(&self) -> bool {
        self.pos < self.len()
    }
    /// Consumes the next byte from the stream (if any) and advances (by one) the
    /// position of the buffer.
    pub fn next(&mut self) -> Option<u8> {
        self.has_next().then(|| {
            self.pos += 1;
            self.wrapped[self.pos - 1]
        })
    }
    /// Reads the next big-endian u16 from the stream,
    /// consuming the next 2 bytes.
    /// Returns None if there are less than 2 bytes remaining.
    pub fn next_u16(&mut self) -> Option<u16> {
        let bytes = self.try_take(2)?;
        Some(from_be_bytes!(bytes, u16))
    }
    /// Reads the next big-endian u32 from the stream,
    /// consuming the next 4 bytes.
    /// Returns None if there are less than 4 bytes remaining.
    pub fn next_u32(&mut self) -> Option<u32> {
        let bytes = self.try_take(4)?;
        Some(from_be_bytes!(bytes, u32))
    }
    /// Reads the next big-endian u64 from the stream,
    /// consuming the next 8 bytes.
    /// Returns None if there are less than 8 bytes remaining.
    pub fn next_u64(&mut self) -> Option<u64> {
        let bytes = self.try_take(8)?;
        Some(from_be_bytes!(bytes, u64))
    }
    /// Reads the next big-endian u128 from the stream,
    /// consuming the next 16 bytes.
    /// Returns None if there are less than 16 bytes remaining.
    pub fn next_u128(&mut self) -> Option<u128> {
        let bytes = self.try_take(16)?;
        Some(from_be_bytes!(bytes, u128))
    }

    /// Consumes exactly 'count' bytes from the stream, if there are at less
    /// 'count' bytes remaining. If there are not enough bytes to be read, nothing is consumed
    /// and None is returned.
    /// ### Lifetime
    /// This method returns a reference to the corresponding slice of the stream. This reference
    /// cannot outlive this stream.
    pub fn try_take(&mut self, count: usize) -> Option<&'arena [u8]> {
        let slice = &self.wrapped[self.pos..];
        if count > slice.len() {
            return None;
        }
        let slice = &slice[0..count];
        self.pos += count;
        Some(slice)
    }
    /// Extracts the next 'count' bytes from this stream and fills them into
    /// a new sub-stream, without copying them.
    /// The position of this buffer is advanced by 'count'.
    /// If there are less than 'count' bytes remaining, nothing is consumed and
    /// None is returned.
    /// ### Lifetime
    /// The sub-stream cannot outlive this stream.
    pub fn extract(&mut self, count: usize) -> Option<Buffer> {
        let slice = self.try_take(count)?;
        Some(Buffer::new(slice))
    }
    /// Reads the stream to its end, consuming all the remaining bytes.
    /// If there is no byte left, an empty array is returned.
    /// ### Note
    /// If this is an extracted sub-stream, this will only read the bytes
    /// that were filled into the sub-stream, not all the bytes contained in its parent.
    /// ### Lifetime
    /// This method returns a reference to the corresponding slice of the stream. This reference
    /// cannot outlive this stream.
    pub fn read_to_end(&mut self) -> &'arena [u8] {
        self.try_take(self.len() - self.pos)
            .unwrap_or(&util::EMPTY_BYTE_VEC)
    }

    /// Convenience method that returns Some(()) if the buffer is empty
    /// (i.e. [`self.remaining()`] would return 0 and [`self.read_to_end`] would
    /// return an empty string), and returns None if there are still bytes to read.
    pub fn ensure_empty(&self) -> Option<()> {
        (self.remaining() == 0).then_some(())
    }
}

/// Allows to parse messages received from a socket.
/// This is an emtpy struct, with only static methods.
pub(super) struct MessageParser;

impl MessageParser {
    fn check_magic(buffer: &mut Buffer) -> ParseResult<()> {
        buffer
            .next()
            .filter(|m| *m == util::PROTOCOL_MAGIC)
            .map(|_| ())
            .ok_or_else(|| ParseError::NotAMircDatagram)
    }

    fn check_version(buffer: &mut Buffer) -> ParseResult<()> {
        buffer.next().map_or_else(
            || Err(ParseError::NotAMircDatagram),
            |v| {
                (v == util::PROTOCOL_VERSION)
                    .then_some(())
                    .ok_or(ParseError::UnsupportedProtocolVersion(v))
            },
        )
    }

    fn parse_body_length(buffer: &mut Buffer) -> Option<usize> {
        buffer.next_u16().map(|size| size as usize)
    }

    /// Tries to parse TLVs from a byte array corresponding to a MIRC
    /// datagram. `addr` is the address of the sender of the datagram.
    /// # Errors
    /// Returns an Err value if
    /// - the array does not correspond to a valid supported MIRC datagram,
    /// - the array contains no valid TLV.
    /// If the parsing fails after some TLVs have been found, the parsing
    /// is interrupted, those TLVs are returned and the event is logged.
    pub fn try_parse(
        addr: &Addr,
        buffer: &mut Buffer,
        logger: &EventLog,
    ) -> ParseResult<Vec<TagLengthValue>> {
        // Checking that the DGram starts with bytes 95 0.
        Self::check_magic(buffer)?;
        Self::check_version(buffer)?;

        let body_length = Self::parse_body_length(buffer)
            .ok_or_else(|| ParseError::ProtocolViolation(addr.clone()))?;

        // Discard bytes according to the specified body length
        buffer
            .shrink(body_length)
            .map_err(|()| ParseError::ProtocolViolation(addr.clone()))?;

        let mut tags = vec![];

        while buffer.has_next() {
            match TagLengthValue::try_parse(buffer) {
                Some(tlv) => tags.push(tlv),
                None if !tags.is_empty() => {
                    logger.warning(format!(
                        "While processing bytes received from {0}: Parsing interrupted before the end of the message \
                        due to a protocol violation. Keeping only the TLVs parsed so far.",
                    addr));
                    break;
                }
                None => return Err(ParseError::ProtocolViolation(addr.clone())),
            }
        }
        Ok(tags)
    }
}
