use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;

use crate::addresses::Addr;
use crate::util::{BytesConcat, DateTime, MessageId, ParseError, PeerID, Result, TagLengthValue};

pub(crate) struct LocalState {
    id: PeerID,
    tvp: HashSet<Addr>,
    tva: HashMap<Addr, (PeerID, DateTime, DateTime)>,
    data: HashMap<MessageId, (DateTime, Vec<(Addr, u8)>)>,
}

impl LocalState {
    pub fn new() -> LocalState {
        LocalState {
            id: PeerID::new(),
            tvp: HashSet::new(),
            tva: HashMap::new(),
            data: HashMap::new(),
        }
    }
}

pub(crate) struct Buffer {
    wrapped: [u8; 1024],
    len: usize,
    pos: usize,
}

impl Buffer {
    pub(crate) fn new(wrapped: [u8; 1024], len: usize) -> Buffer {
        assert!(len <= 1024);
        Buffer {
            wrapped,
            len,
            pos: 0,
        }
    }

    pub(crate) fn has_next(&self) -> bool {
        self.pos < self.len
    }

    pub(crate) fn next(&mut self) -> Option<u8> {
        if self.pos < self.len {
            self.pos += 1;
            Some(self.wrapped[self.pos - 1])
        } else {
            None
        }
    }

    pub(crate) fn try_take(&mut self, count: usize) -> Option<&[u8]> {
        let (_, slice) = self.wrapped.split_at(self.pos);
        if count > slice.len() {
            return None;
        }
        let (slice, _) = slice.split_at(count);
        self.pos += count;
        Some(slice)
    }

    pub(crate) fn read_to_end(&mut self) -> &[u8] {
        self.try_take(self.len - self.pos).unwrap()
    }

    pub(crate) fn shrink(&mut self, new_len: usize) {
        assert!(new_len <= self.pos && new_len <= self.len);
    }
}

pub(crate) type Message = Vec<TagLengthValue>;

pub(crate) struct MessageParser {}

impl MessageParser {
    const MAGIC: u8 = 95;
    const VERSION: u8 = 0;

    pub fn new() -> MessageParser {
        MessageParser {}
    }

    fn check_magic(&self, buffer: &mut Buffer) -> Result<()> {
        buffer
            .next()
            .filter(|m| *m == MessageParser::MAGIC)
            .map(|_| ())
            .ok_or_else(|| ParseError::NotAMircDatagram)
    }

    fn check_version(&self, buffer: &mut Buffer) -> Result<()> {
        buffer
            .next()
            .filter(|v| *v == MessageParser::VERSION)
            .map(|_| ())
            .ok_or_else(|| ParseError::UnsupportedProtocolVersion)
    }

    fn parse_body_length(&self, buffer: &mut Buffer) -> Option<usize> {
        let part1 = buffer.next()?;
        let part2 = buffer.next()?;

        Some((part1, part2).concat().into())
    }

    pub(crate) fn try_parse(&self, socket: &UdpSocket) -> Result<Message> {
        let mut buf = [0; 1024];
        let (size, addr) = socket.recv_from(&mut buf)?;
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
        Ok(tags)
    }
}
