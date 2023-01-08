extern crate rand;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::net::UdpSocket;
use std::sync::RwLock;

use self::rand::Rng;

use crate::addresses::Addr;
use crate::datetime::{self, DateTime};
use crate::error::{DeliveryResult, ParseError, ParseResult};
use crate::parse::MessageParser;
use crate::util::{
    Data, GoAwayReason, LimitedString, MessageId, PeerID, ServiceDataUnit, ServiceDataUnitFactory,
    TagLengthValue, TryToBytes,
};

struct ActiveNeighbour {
    id: PeerID,
    last_hello: DateTime,
    last_long_hello: DateTime,
}

struct FloodingState {
    flooding_times: u8,
    last_flooding: DateTime,
    next_flooding_delay: u128,
}

struct DataToFlood<'arena> {
    receive_time: DateTime,
    data: Data,
    neighbours_to_flood: HashMap<&'arena Addr, FloodingState>,
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
pub(crate) struct LocalPeerSocket<'arena> {
    id: PeerID,
    socket: UdpSocket,
    alloc: bumpalo::Bump,
    parser: MessageParser,
    last_hello: DateTime,
    last_neighbourhood: DateTime,
    tvp: HashSet<&'arena Addr>,
    tva: HashMap<&'arena Addr, ActiveNeighbour>,
    data: HashMap<MessageId, RefCell<DataToFlood<'arena>>>,
    rng: RefCell<rand::rngs::ThreadRng>,
    connected: RwLock<bool>,
}

impl<'arena> LocalPeerSocket<'arena> {
    const ACTIVITY_TIMEOUT: u128 = 120000;
    const SYMMETRY_TIMEOUT: u128 = 120000;

    const MAX_FLOODING_TIMES: u8 = 5;
    const min_NS: usize = 1;

    const HELLO_INTERVAL: u128 = 30000;
    const NEIGHBOURHOOD_BROADCAST_INTERVAL: u128 = 30000;

    /// Creates a new LocalPeerSocket object and binds it to the
    /// specified port.
    /// # Errors
    /// This method fails if it cannot bind the socket.
    pub fn new(port: u16) -> std::io::Result<LocalPeerSocket<'arena>> {
        let socket = UdpSocket::bind(("::1", port))?;
        socket.set_nonblocking(true)?;
        Ok(LocalPeerSocket {
            id: PeerID::new(),
            socket,
            alloc: bumpalo::Bump::new(),
            parser: MessageParser::new(),
            last_hello: datetime::never(),
            last_neighbourhood: datetime::now(),
            tvp: HashSet::new(),
            tva: HashMap::new(),
            data: HashMap::new(),
            rng: RefCell::new(rand::thread_rng()),
            connected: RwLock::new(false),
        })
    }

    fn hashcons(&mut self, addr: Addr) -> &'arena Addr {
        match self.tvp.get(&addr) {
            Some(addr) => addr,
            None => {
                let addr = self.alloc.alloc(addr);
                self.tvp.get(addr).unwrap()
            }
        }
    }

    fn retrieve_addr(&self, addr: Addr) -> Option<&'arena Addr> {
        match self.tvp.get(&addr) {
            Some(addr) => Some(*addr),
            None => None,
        }
    }

    fn is_symmetric(&self, key: &Addr) -> bool {
        let neighbour = self.tva.get(key);
        neighbour.map_or(false, |f| self.is_neighbour_symmetric(f))
    }

    fn is_neighbour_symmetric(&self, neighbour: &ActiveNeighbour) -> bool {
        datetime::millis_since(neighbour.last_long_hello) < LocalPeerSocket::SYMMETRY_TIMEOUT
    }

    /// Removes the sender of the Ack from the list of
    /// the neighbours to flood for the specified message.
    fn process_ack(&mut self, from: &Addr, msg_id: &MessageId) {
        self.data
            .get_mut(msg_id)
            .map(|data| data.borrow_mut().neighbours_to_flood.remove(from));

        if self
            .data
            .get(msg_id)
            .is_some_and(|data| data.borrow().neighbours_to_flood.is_empty())
        {
            self.data.remove(msg_id);
        }
    }

    /// Sends a message to a peer.
    /// # Errors
    /// This method fails if the specified message is not a valid MIRC
    /// service data unit, or if the datagram cannot be sent.
    fn send_message(&self, to: &Addr, msg: &ServiceDataUnit) -> DeliveryResult<()> {
        let bytes = msg.try_to_bytes()?;
        self.socket.send_to(bytes.as_slice(), to)?;
        Ok(())
    }

    fn send_single_tlv(&self, to: &Addr, tlv: TagLengthValue) -> DeliveryResult<()> {
        self.send_message(to, &vec![tlv])
    }

    /// Sends an Ack for the specified message to a peer.
    /// # Errors
    /// This methods fails if the datagram cannot be sent.
    fn send_ack(&self, to: &Addr, msg_id: &MessageId) -> DeliveryResult<()> {
        let tlv = TagLengthValue::Ack(*msg_id);
        self.send_single_tlv(to, tlv)
    }

    fn random_flooding_delay(&self, flooding_times: u8) -> u128 {
        if flooding_times == 0 {
            self.rng.borrow_mut().gen_range(500..1000)
        } else {
            self.rng
                .borrow_mut()
                .gen_range((1000 * (1 << (flooding_times - 1)))..(1000 * (1 << flooding_times)))
        }
    }

    /// Initializes a list of neighbours to flood for a message that has
    /// just been received, or that is to be sent.
    /// The list of the neighbours to flood is initialized to the
    /// list of the currently active neighbours.
    fn prepare_flooding(&mut self, data: Data) -> DataToFlood<'arena> {
        let mut neighbours_to_flood = HashMap::new();
        let receive_time = datetime::now();

        for (addr, _) in self.tva.iter() {
            neighbours_to_flood.insert(
                *addr,
                FloodingState {
                    flooding_times: 0,
                    last_flooding: receive_time,
                    next_flooding_delay: self.random_flooding_delay(0),
                },
            );
        }
        DataToFlood {
            receive_time: datetime::now(),
            data,
            neighbours_to_flood,
        }
    }

    fn send_warning(&self, to: &Addr, msg: String) -> DeliveryResult<()> {
        self.send_single_tlv(
            to,
            TagLengthValue::Warning(LimitedString::force_from_string(msg)),
        )
    }

    fn mark_inactive(&mut self, n: &'arena Addr, msg: Option<String>) -> DeliveryResult<()> {
        self.tva.remove(n);
        self.send_single_tlv(
            n,
            TagLengthValue::GoAway(
                GoAwayReason::Inactivity,
                msg.map(|str| {
                    // whatever, the error is (supposed to be) used when receiving the TLV,
                    // it is ignored when sending it.
                    LimitedString::try_from(str).map_err(|_| ParseError::ProtocolViolation)
                }),
            ),
        )
    }

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&mut self, sender: &'arena Addr, tlv: TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                let neighbour = self
                    .tva
                    .entry(sender)
                    .or_insert((sender_id, datetime::never(), datetime::never()).into());

                neighbour.last_hello = datetime::now();

                let self_id = self.id;
                neighbour.last_long_hello = receiver
                    .filter(|id| *id == self_id)
                    .map_or(neighbour.last_long_hello, |_| datetime::now());
            }
            TagLengthValue::Neighbour(addr) => {
                self.hashcons(addr);
            }
            TagLengthValue::Data(msg_id, data) => {
                if self.is_symmetric(sender) {
                    if !self.data.contains_key(&msg_id) {
                        //TODO show data
                        let flooding = self.prepare_flooding(data);
                        self.data.insert(msg_id, RefCell::new(flooding));
                    }

                    self.process_ack(sender, &msg_id);
                    self.send_ack(sender, &msg_id);
                }
            }
            TagLengthValue::Ack(msg_id) => {
                self.process_ack(sender, &msg_id);
            }
            TagLengthValue::GoAway(reason, msg) => {
                // TODO verbose
                self.tva.remove(sender);
            }
            TagLengthValue::Warning(msg) => {
                // TODO verbose
            }
            TagLengthValue::Unrecognized(tag, _) => {
                self.send_warning(sender, format!("Unrecognized tag {0} was ignored.", tag));
            }
            TagLengthValue::Illegal(tag, _) => {
                self.send_warning(
                    sender,
                    format!("Tag {0} had illegal content and was ignored.", tag),
                );
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
    fn receive_message(&mut self) -> ParseResult<()> {
        let (addr, msg) = self.parser.try_parse(&self.socket)?;
        let addr = self.retrieve_addr(addr).ok_or(ParseError::UnknownSender)?;
       
        for tlv in msg {
            self.process_tlv(addr, tlv);
        }
        Ok(())
    }

    fn send_hellos(&mut self) {
        let mut symmetrics = 0;
        let mut inactives = vec![];

        for (addr, neighbour) in self.tva.iter() {
            if datetime::millis_since(neighbour.last_hello) > LocalPeerSocket::ACTIVITY_TIMEOUT {
                inactives.push(*addr);
            } else {
                if self.is_neighbour_symmetric(neighbour) {
                    symmetrics += 1;
                }
                let hello = TagLengthValue::Hello(self.id, Some(neighbour.id));
                self.send_single_tlv(addr, hello);
            }
        }
        for inactive in inactives {
            self.mark_inactive(inactive, None);
        }
        if symmetrics < LocalPeerSocket::min_NS {
            for addr in self.tvp.iter() {
                if !self.tva.contains_key(addr) {
                    let hello = TagLengthValue::Hello(self.id, None);
                    self.send_single_tlv(addr, hello);
                }
            }
        }
    }

    fn brodcast_neighbourhood(&self) {
        let mut queue = VecDeque::new();
        for (addr, neighbour) in self.tva.iter() {
            if self.is_neighbour_symmetric(neighbour) {
                queue.push_back(TagLengthValue::Neighbour((*addr).clone()));
            }
        }

        let mut factory = ServiceDataUnitFactory::new(queue);
        loop {
            let msg = factory.next_message();
            if msg.is_empty() {
                break;
            }
            for (addr, _) in self.tva.iter() {
                self.send_message(addr, &msg);
            }
        }
    }

    fn flood_messages(&self, msg_id: &MessageId, data: &RefCell<DataToFlood<'arena>>) {
        let msg = vec![TagLengthValue::Data(*msg_id, data.borrow().data.clone())];

        for (addr, state) in data.borrow_mut().neighbours_to_flood.iter_mut() {
            if datetime::millis_since(state.last_flooding) > state.next_flooding_delay {
                match self.send_message(addr, &msg) {
                    Ok(()) => {
                        state.flooding_times += 1;
                        state.next_flooding_delay =
                            self.random_flooding_delay(state.flooding_times);
                    }
                    _ => { /* TODO */ }
                }
            }
        }
    }

    fn routine(&mut self) {
        if datetime::millis_since(self.last_hello) > LocalPeerSocket::HELLO_INTERVAL {
            self.send_hellos();
            self.last_hello = datetime::now();
        }
        if datetime::millis_since(self.last_neighbourhood)
            > LocalPeerSocket::NEIGHBOURHOOD_BROADCAST_INTERVAL
        {
            self.brodcast_neighbourhood();
            self.last_neighbourhood = datetime::now();
        }
        let mut inactives = HashSet::new();
        for (msg_id, data) in self.data.iter() {
            self.flood_messages(msg_id, data);

            data.borrow_mut()
                .neighbours_to_flood
                .drain_filter(|_, state| {
                    state.flooding_times >= LocalPeerSocket::MAX_FLOODING_TIMES
                })
                .for_each(|(addr, _)| {
                    inactives.insert(addr);
                });
        }
        for inactive in inactives {
            self.mark_inactive(inactive, Some("You didn't acknoledge a message in time.".to_owned()));
        }
    }

}
