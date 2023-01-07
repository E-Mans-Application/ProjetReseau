use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;

use crate::addresses::Addr;
use crate::datetime::{self, DateTime};
use crate::error::{DeliveryResult, ParseResult};
use crate::parse::MessageParser;
use crate::util::{Data, Message, MessageId, PeerID, TagLengthValue, TryToBytes};

struct ActiveNeighbour {
    pub id: PeerID,
    pub last_hello: DateTime,
    pub last_long_hello: DateTime,
}

struct DataToFlood {
    pub receive_time: DateTime,
    pub data: Data,
    pub neighbours_to_flood: HashMap<Addr, u8>,
}

impl From<(PeerID, DateTime, DateTime)> for ActiveNeighbour {
    fn from(value: (PeerID, DateTime, DateTime)) -> Self {
        ActiveNeighbour {
            id: value.0,
            last_hello: value.1,
            last_long_hello: value.2,
        }
    }
}

/// A wrapper struct representing the peer
/// using this local instance of the program
pub(crate) struct LocalPeerSocket {
    id: PeerID,
    socket: UdpSocket,
    parser: MessageParser,
    tvp: HashSet<Addr>,
    tva: HashMap<Addr, ActiveNeighbour>,
    data: HashMap<MessageId, DataToFlood>,
}

impl LocalPeerSocket {
    const ACTIVITY_TIMEOUT: u64 = 120;
    const SYMMETRY_TIMEOUT: u64 = 120;

    /// Creates a new LocalPeerSocket object and binds it to the
    /// specified port.
    /// # Errors
    /// This method fails if it cannot bind the socket.
    pub fn new(port: u16) -> std::io::Result<LocalPeerSocket> {
        let socket = UdpSocket::bind(("::1", port))?;
        Ok(LocalPeerSocket {
            id: PeerID::new(),
            socket,
            parser: MessageParser::new(),
            tvp: HashSet::new(),
            tva: HashMap::new(),
            data: HashMap::new(),
        })
    }

    fn is_symmetric(&self, key: &Addr) -> bool {
        let neighbour = self.tva.get(key);
        neighbour.map_or(false, |f| {
            datetime::secs_since(f.last_long_hello) < LocalPeerSocket::SYMMETRY_TIMEOUT
        })
    }

    /// Removes the sender of the Ack from the list of
    /// the neighbours to flood for the specified message.
    fn process_ack(&mut self, from: &Addr, msg_id: &MessageId) {
        self.data
            .get(msg_id)
            .map(|data| data.neighbours_to_flood.remove(from));
    }

    /// Sends a message to a peer.
    /// # Errors
    /// This method fails if the specified message is not a valid MIRC
    /// service data unit, or if the datagram cannot be sent.
    fn send_message(&self, msg: &Message) -> DeliveryResult<()> {
        let bytes = msg.try_to_bytes()?;
        self.socket.send_to(bytes.as_slice(), msg.0)?;
        Ok(())
    }

    /// Sends an Ack for the specified message to a peer.
    /// # Errors
    /// This methods fails if the datagram cannot be sent.
    fn send_ack(&self, to: &Addr, msg_id: &MessageId) -> DeliveryResult<()> {
        let tlv = TagLengthValue::Ack(*msg_id);
        self.send_message(&(*to, vec![tlv]))
    }

    /// Initializes a list of neighbours to flood for a message that has
    /// just been received, or that is to be sent.
    /// The list of the neighbours to flood is initialized to the
    /// list of the currently active neighbours.
    fn prepare_flooding(&self, data: Data) -> DataToFlood {
        let neighbours_to_flood = HashMap::new();
        for (addr, _) in self.tva.iter() {
            neighbours_to_flood.insert(*addr, 0_u8);
        }
        DataToFlood {
            receive_time: datetime::now(),
            data,
            neighbours_to_flood,
        }
    }

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&self, sender: &Addr, tlv: &TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                let neighbour = self
                    .tva
                    .entry(*sender)
                    .or_insert((*sender_id, datetime::never(), datetime::never()).into());

                neighbour.last_hello = datetime::now();
                neighbour.last_long_hello = receiver
                    .filter(|id| *id == self.id)
                    .map_or(neighbour.last_long_hello, |_| datetime::now());
            }
            TagLengthValue::Neighbour(addr) => {
                self.tvp.insert(*addr);
            }
            TagLengthValue::Data(msg_id, data) => {
                if self.is_symmetric(sender) {
                    self.data.entry(*msg_id).or_insert_with(|| {
                        //TODO show data
                        self.prepare_flooding(*data)
                    });
                    self.send_ack(sender, msg_id);
                    self.process_ack(sender, msg_id);
                }
            }
            TagLengthValue::Ack(msg_id) => {
                self.process_ack(sender, msg_id);
            }
            TagLengthValue::GoAway(reason, msg) => {
                // TODO verbose
                self.tva.remove(sender);
            }
            TagLengthValue::Warning(msg) => {
                // TODO verbose
            }
            _ => {}
        }
    }

    /// Tries to receive a single datagram from the socket.
    /// The received datagram (if any) is then processed.
    /// When this method completes, more datagrams may still be
    /// waiting for being processed.
    /// # Errors
    /// This method returns an Err value if
    /// - no datagram has been received,
    /// - the received datagram could not be parsed.
    pub fn receive_message(&self) -> ParseResult<()> {
        let (addr, msg) = self.parser.try_parse(&self.socket)?;
        for tlv in msg {
            self.process_tlv(&addr, &tlv);
        }
        Ok(())
    }
}
