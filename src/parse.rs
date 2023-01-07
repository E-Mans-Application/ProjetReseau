use crate::addresses::Addr;
use crate::error::{ParseError, ParseResult};
use crate::util::{self, BytesConcat, Message, TagLengthValue};
use std::net::UdpSocket;

/// A generic buffered bytes stream reader used for parsing
pub(crate) trait BytesStreamReader<'arena> {
    type SubBuffer: BytesStreamReader<'arena>;
    /// Tells whether there is still bytes to consume, without consuming them.
    fn has_next(&self) -> bool;
    /// Consumes the next byte from the stream (if any) and advances (by one) the
    /// position of the buffer.
    fn next(&mut self) -> Option<u8>;
    /// Consumes exactly 'count' bytes from the stream, if there is at less
    /// 'count' bytes remaining. If there is not enough bytes to be read, nothing is consumed
    /// and None is returned.
    /// ### Lifetime
    /// This method returns a reference to the corresponding slice of the stream. This reference
    /// cannot outlive this stream.
    fn try_take(&mut self, count: usize) -> Option<&'arena [u8]>;
    /// Reads the stream to its end, consuming all the remaining bytes.
    /// If there is no byte left, an empty array is returned.
    /// ### Note
    /// If this is an extracted sub-stream, this will only read the bytes
    /// that were filled into the sub-stream, not all the bytes contained in its parent.
    /// ### Lifetime
    /// This method returns a reference to the corresponding slice of the stream. This reference
    /// cannot outlive this stream.
    fn read_to_end(&mut self) -> &'arena [u8];
    /// Extracts the next 'count' bytes from this stream and fills them into
    /// a new sub-stream, without copying them.
    /// If there is less than 'count' bytes remaining, nothing is consumed and
    /// None is returned.
    /// ### Lifetime
    /// The sub-stream cannot outlive this stream.
    fn extract(&mut self, count: usize) -> Option<Self::SubBuffer>;
}

impl<'arena> BytesStreamReader<'arena> for (&'arena [u8], usize) {
    type SubBuffer = BufferSlice<'arena>;

    fn has_next(&self) -> bool {
        self.1 < self.0.len()
    }

    fn next(&mut self) -> Option<u8> {
        if self.has_next() {
            self.1 += 1;
            Some(self.0[self.1 - 1])
        } else {
            None
        }
    }

    fn try_take(&mut self, count: usize) -> Option<&'arena [u8]> {
        let (_, slice) = self.0.split_at(self.1);
        if count > slice.len() {
            return None;
        }
        let (slice, _) = slice.split_at(count);
        self.1 += count;
        Some(slice)
    }

    fn read_to_end(&mut self) -> &'arena [u8] {
        self.try_take(self.0.len() - self.1).unwrap_or(&vec![])
    }

    fn extract(&mut self, count: usize) -> Option<Self::SubBuffer> {
        let slice = self.try_take(count)?;
        Some(BufferSlice { slice, pos: 0 })
    }
}

/// The base implementation of BytesStreamReader, initialized with
/// the full byte array.
pub(crate) struct Buffer {
    wrapped: [u8; 1024],
    len: usize,
    pos: usize,
}

impl<'arena> Buffer {
    /// Creates a new buffer from the given datagram.
    /// len must not be greater than 1024 (the maximum length of a datagram).
    /// ### Panics
    /// This method panics if len > 1024.
    pub(crate) fn new(wrapped: [u8; 1024], len: usize) -> Buffer {
        assert!(len <= 1024);
        Buffer {
            wrapped,
            len,
            pos: 0,
        }
    }

    /// Shrinks the buffer to a new size, discarding the bytes
    /// that no longer fits into it.
    /// This method cannot discard bytes that have already been consumed.
    /// ### Panics
    /// This method panics if the new_len is less than the number of bytes
    /// that have already been consumed.
    pub(crate) fn shrink(&mut self, new_len: usize) {
        assert!(new_len <= self.pos && new_len <= self.len);
        self.len = new_len;
    }

    fn as_tuple(&self) -> (&'arena [u8], usize) {
        (self.wrapped.split_at(self.len).0, self.pos)
    }
}

impl<'arena> BytesStreamReader<'arena> for Buffer {
    type SubBuffer = BufferSlice<'arena>;

    fn has_next(&self) -> bool {
        self.as_tuple().has_next()
    }

    fn next(&mut self) -> Option<u8> {
        self.as_tuple().next()
    }

    fn try_take(&mut self, count: usize) -> Option<&'arena [u8]> {
        self.as_tuple().try_take(count)
    }

    fn extract(&mut self, count: usize) -> Option<Self::SubBuffer> {
        self.as_tuple().extract(count)
    }

    fn read_to_end(&mut self) -> &'arena [u8] {
        self.as_tuple().read_to_end()
    }
}

struct BufferSlice<'arena> {
    slice: &'arena [u8],
    pos: usize,
}

impl<'arena> BufferSlice<'arena> {
    fn as_tuple(&self) -> (&'arena [u8], usize) {
        (self.slice, self.pos)
    }
}

impl<'arena> BytesStreamReader<'arena> for BufferSlice<'arena> {
    type SubBuffer = BufferSlice<'arena>;

    fn has_next(&self) -> bool {
        self.as_tuple().has_next()
    }

    fn next(&mut self) -> Option<u8> {
        self.as_tuple().next()
    }

    fn try_take(&mut self, count: usize) -> Option<&'arena [u8]> {
        self.as_tuple().try_take(count)
    }

    fn read_to_end(&mut self) -> &'arena [u8] {
        self.as_tuple().read_to_end()
    }

    fn extract(&mut self, count: usize) -> Option<Self::SubBuffer> {
        self.as_tuple().extract(count)
    }
}

pub(crate) struct MessageParser {}

impl MessageParser {
    pub fn new() -> MessageParser {
        MessageParser {}
    }

    fn check_magic(&self, buffer: &mut Buffer) -> ParseResult<()> {
        buffer
            .next()
            .filter(|m| *m == util::PROTOCOL_MAGIC)
            .map(|_| ())
            .ok_or_else(|| ParseError::NotAMircDatagram)
    }

    fn check_version(&self, buffer: &mut Buffer) -> ParseResult<()> {
        buffer
            .next()
            .filter(|v| *v == util::PROTOCOL_VERSION)
            .map(|_| ())
            .ok_or_else(|| ParseError::UnsupportedProtocolVersion)
    }

    fn parse_body_length(&self, buffer: &mut Buffer) -> Option<usize> {
        let part1 = buffer.next()?;
        let part2 = buffer.next()?;

        Some((part1, part2).concat().into())
    }

    pub(crate) fn try_parse(&self, socket: &UdpSocket) -> ParseResult<Message> {
        let mut buf = [0; 1024];
        let (size, addr) = socket.recv_from(&mut buf)?;
        let addr: Addr = addr.into();

        let buffer = Buffer::new(buf, size);

        self.check_magic(&mut buffer)?;
        self.check_version(&mut buffer)?;

        let body_length = self
            .parse_body_length(&mut buffer)
            .ok_or_else(|| ParseError::ProtocolViolation)?;

        buffer.shrink(body_length + 4);

        let tags = vec![];

        while buffer.has_next() {
            let tlv = TagLengthValue::try_parse(&mut buffer)
                .ok_or_else(|| ParseError::ProtocolViolation)?;
            tags.push(tlv);
        }
        Ok((addr, tags))
    }
}
