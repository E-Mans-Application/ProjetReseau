extern crate rand;

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::io::Write;
use std::net::UdpSocket;
use std::rc::Rc;
use std::sync::{RwLock, RwLockWriteGuard};

use self::rand::rngs::ThreadRng;
use self::rand::Rng;
use crate::datetime::{self, DateTime};
use crate::error::{DeliveryResult, MessageDeliveryError, ParseError, ParseResult};
use crate::parse::MessageParser;
use crate::util::{
    Data, GoAwayReason, LimitedString, MessageId, PeerID, ServiceDataUnit, ServiceDataUnitFactory,
    TagLengthValue, ToBytes, TryToBytes,
};
use addresses::Addr;

/* #region ActiveNeighbour */

struct ActiveNeighbour<'arena> {
    id: PeerID,
    addr: &'arena Addr,
    last_hello: DateTime,
    last_long_hello: DateTime,
}

impl ActiveNeighbour<'_> {
    fn is_symmetric(&self) -> bool {
        datetime::millis_since(self.last_long_hello) < LocalUser::SYMMETRY_TIMEOUT
    }
}

/* #endregion */

/* #region ActiveNeighbourMap */

struct ActiveNeighbourMap<'arena>(RwLock<HashMap<&'arena Addr, ActiveNeighbour<'arena>>>);

impl<'arena> ActiveNeighbourMap<'arena> {
    fn new() -> ActiveNeighbourMap<'arena> {
        ActiveNeighbourMap(RwLock::new(HashMap::new()))
    }

    fn mark_inactive(
        &self,
        addr: &Addr,
        socket: &MircHost,
        msg: Option<String>,
    ) -> DeliveryResult<()> {
        self.0.write().unwrap().remove(addr);

        socket.send_single_tlv(
            addr,
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

    fn mark_all_inactives(&self, who: Vec<&Addr>, socket: &MircHost, msg: Option<String>) {
        for addr in who {
            self.mark_inactive(addr, socket, msg);
        }
    }

    fn is_symmetric(&self, addr: &Addr) -> bool {
        self.0
            .read()
            .unwrap()
            .get(addr)
            .is_some_and(|n| n.is_symmetric())
    }

    fn fold<T, F>(&self, init: T, f: F) -> T
    where
        F: Fn(&Addr, &ActiveNeighbour, T) -> T,
    {
        let mut result = init;
        for (addr, neighbour) in self.0.read().unwrap().iter() {
            result = f(addr, neighbour, result);
        }
        result
    }
}

/* #endregion */

/* #region FloodingState */

struct FloodingState {
    addr: Rc<Addr>,
    data: Rc<DataToFlood>,
    flooding_times: u8,
    last_flooding: DateTime,
    next_flooding_delay: u128,
}

impl FloodingState {
    fn new(time: DateTime, rng: &mut ThreadRng) -> FloodingState {
        let mut state = FloodingState {
            flooding_times: 0,
            last_flooding: time,
            next_flooding_delay: 0,
        };
        state.next_flooding_delay = state.random_flooding_delay(rng);
        state
    }

    fn should_flood(&self) -> bool {
        datetime::millis_since(self.last_flooding) > self.next_flooding_delay
    }

    fn flood(
        &mut self,
        to: &Addr,
        msg: &ServiceDataUnit,
        socket: &MircHost,
        rng: &mut ThreadRng,
    ) -> DeliveryResult<()> {
        if self.should_flood() {
            socket.send_sdu(to, msg)?;
            self.flooded(rng);

            if self.should_give_up_flooding() {
                return Err(MessageDeliveryError::NeighbourInactive);
            }
        }
        Ok(())
    }

    fn flooded(&mut self, rng: &mut ThreadRng) {
        self.flooding_times += 1;
        self.last_flooding = datetime::now();
        self.next_flooding_delay = self.random_flooding_delay(rng);
    }

    fn random_flooding_delay(&self, rng: &mut ThreadRng) -> u128 {
        if self.flooding_times == 0 {
            rng.gen_range(500..1000)
        } else {
            rng.gen_range(
                (1000 * (1 << (self.flooding_times - 1)))..(1000 * (1 << self.flooding_times)),
            )
        }
    }

    fn should_give_up_flooding(&self) -> bool {
        self.flooding_times >= LocalUser::MAX_FLOODING_TIMES
    }

    fn give_up_flooding(&mut self) {
        self.flooding_times = LocalUser::MAX_FLOODING_TIMES;
    }
}

/* #endregion */

/* #region DataToFlood */

struct DataToFlood {
    receive_time: DateTime,
    msg_id: Rc<MessageId>,
    data: Data,
    neighbours_to_flood: HashMap<&'arena Addr, FloodingState>,
}

impl<'arena> DataToFlood<'arena> {
    fn new(
        msg_id: &MessageId,
        data: Data,
        neighbours: ActiveNeighbourMap<'arena>,
        rng: &mut ThreadRng,
    ) -> DataToFlood<'arena> {

        let date = datetime::now();

        let mut neighbours_to_flood = neighbours.fold(HashMap::new(), |addr, n, v| {
            if n.is_symmetric() {
                v.insert(addr, FloodingState::new(date, rng));
            }
            v
        });

        DataToFlood {
            receive_time: date,
            msg_id,
            data,
            neighbours_to_flood,
        }
    }

    fn process_ack(&mut self, from: &Addr) {
        self.neighbours_to_flood.remove(from);
    }
    fn flooding_complete(&self) -> bool {
        self.neighbours_to_flood.is_empty()
    }

    fn flood(
        &mut self,
        socket: &MircHost,
        rng: &mut ThreadRng,
        tva: &ActiveNeighbourMap,
    ) -> DeliveryResult<()> {
        let msg = vec![TagLengthValue::Data(self.msg_id, self.data.clone())];
        let mut inactives = vec![];

        for (addr, state) in self.neighbours_to_flood.iter_mut() {
            if tva.is_symmetric(addr) {
                match state.flood(addr, &msg, socket, rng) {
                    Ok(()) => (),
                    Err(MessageDeliveryError::NeighbourInactive) => inactives.push(*addr),
                    Err(_) => { /* TODO */ }
                }
            } else {
                state.give_up_flooding();
            }
        }

        self.neighbours_to_flood
            .retain(|_, state| !state.should_give_up_flooding());
        tva.mark_all_inactives(
            inactives,
            socket,
            Some("You did not acknoledge a message on time".to_owned()),
        );

        Ok(())
    }
}

/* #endregion */

/* #region MircHost */

struct MircHost {
    socket: UdpSocket,
    parser: MessageParser,
}

impl MircHost {
    fn new(port: u16) -> std::io::Result<MircHost> {
        let socket = UdpSocket::bind(("::1", port))?;
        socket.set_nonblocking(true)?;

        Ok(MircHost {
            socket,
            parser: MessageParser::new(),
        })
    }

    /// Sends a message to a peer.
    /// # Errors
    /// This method fails if the specified message is not a valid MIRC
    /// service data unit, or if the datagram cannot be sent.
    fn send_sdu(&self, to: &Addr, msg: &ServiceDataUnit) -> DeliveryResult<()> {
        let bytes = msg.try_to_bytes()?;
        self.socket.send_to(bytes.as_slice(), to)?;
        Ok(())
    }

    fn send_single_tlv(&self, to: &Addr, tlv: TagLengthValue) -> DeliveryResult<()> {
        self.send_sdu(to, &vec![tlv])
    }

    fn send_many_tlvs(&self, to: &[&Addr], tlvs: VecDeque<TagLengthValue>) -> DeliveryResult<()> {
        let mut factory = ServiceDataUnitFactory::new(tlvs);
        loop {
            let msg = factory.next_message();
            if msg.is_empty() {
                break;
            }
            for addr in to {
                self.send_sdu(addr, &msg)?;
            }
        }
        Ok(())
    }

    fn receive_message(&mut self) -> ParseResult<(Addr, ServiceDataUnit)> {
        self.parser.try_parse(&self.socket)
    }
}

/* #endregion */

/* #region LocalUser */

/// A wrapper struct representing the peer
/// using this local instance of the program
pub(crate) struct LocalUser<'arena> {
    id: PeerID,
    socket: MircHost,
    alloc: &'arena bumpalo::Bump,
    last_hello: DateTime,
    last_neighbourhood: DateTime,
    tvp: HashSet<&'arena Addr>,
    tva: ActiveNeighbourMap<'arena>,
    next_msg_id: RwLock<u32>,
    data: RwLock<HashMap<MessageId, RwLock<DataToFlood<'arena>>>>,
    rng: RwLock<rand::rngs::ThreadRng>,
}

impl<'arena> LocalUser<'arena> {
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
    pub fn new(
        alloc: &'arena bumpalo::Bump,
        port: u16,
        first_neighbour: String,
    ) -> std::io::Result<LocalUser<'arena>> {
        let first_neighbour = Addr::try_from(first_neighbour)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
        let socket = MircHost::new(port)?;

        let id = PeerID::new();
        let mut socket = LocalUser {
            id,
            socket,
            alloc,
            last_hello: datetime::never(),
            last_neighbourhood: datetime::now(),
            tvp: HashSet::new(),
            tva: ActiveNeighbourMap::new(),
            next_msg_id: RwLock::new(0),
            data: RwLock::new(HashMap::new()),
            rng: RwLock::new(rand::thread_rng()),
        };
        socket.hashcons(first_neighbour);
        Ok(socket)
    }

    fn hashcons(&mut self, addr: Addr) -> &'arena Addr {
        match self.tvp.get(&addr) {
            Some(addr) => addr,
            None => {
                let addr = self.alloc.alloc(addr);
                self.tvp.insert(addr);
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

    /// Sends an Ack for the specified message to a peer.
    /// # Errors
    /// This methods fails if the datagram cannot be sent.
    fn send_ack(&self, to: &Addr, msg_id: &MessageId) -> DeliveryResult<()> {
        let tlv = TagLengthValue::Ack(*msg_id);
        self.socket.send_single_tlv(to, tlv)
    }

    fn send_warning(&self, to: &Addr, msg: String) -> DeliveryResult<()> {
        self.socket.send_single_tlv(
            to,
            TagLengthValue::Warning(LimitedString::force_from_string(msg)),
        )
    }

    fn process_ack(&self, from: &Addr, msg_id: &MessageId) {
        self.data
            .read()
            .unwrap()
            .get(msg_id)
            .map(|data| data.write().unwrap().process_ack(from));

        if self
            .data
            .read()
            .unwrap()
            .get(&msg_id)
            .is_some_and(|f| f.read().unwrap().flooding_complete())
        {
            self.data.write().unwrap().remove(&msg_id);
        }
    }

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&mut self, sender: &'arena Addr, tlv: TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                let mut tva = self.tva.write().unwrap();
                let neighbour = tva
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
                if self
                    .tva
                    .read()
                    .unwrap()
                    .get(sender)
                    .is_some_and(|n| n.is_symmetric())
                {
                    if !self.data.read().unwrap().contains_key(&msg_id) {
                        //TODO show data

                        std::io::stdout().lock().write(data.to_bytes().as_slice());

                        DataToFlood::new(msg_id, data, self.tva, self.rng.write().unwrap());

                        let flooding = self.prepare_flooding(datetime::now(), data);
                        self.data
                            .write()
                            .unwrap()
                            .insert(msg_id, RwLock::new(flooding));
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
                self.tva.write().unwrap().remove(sender);
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

    fn send_hellos(&mut self) {
        let mut symmetrics = 0;
        let mut inactives = vec![];

        for (addr, neighbour) in self.tva.read().unwrap().iter() {
            if datetime::millis_since(neighbour.last_hello) > LocalUser::ACTIVITY_TIMEOUT {
                inactives.push(*addr);
            } else {
                if neighbour.is_symmetric() {
                    symmetrics += 1;
                }
                let hello = TagLengthValue::Hello(self.id, Some(neighbour.id));
                self.send_single_tlv(addr, hello);
            }
        }
        for inactive in inactives {
            self.mark_inactive(inactive, None);
        }
        if symmetrics < LocalUser::min_NS {
            for addr in self.tvp.iter() {
                if !self.tva.read().unwrap().contains_key(addr) {
                    let hello = TagLengthValue::Hello(self.id, None);
                    self.send_single_tlv(addr, hello);
                }
            }
        }
    }

    fn brodcast_neighbourhood(&self) {
        let mut queue = VecDeque::new();
        for (addr, neighbour) in self.tva.read().unwrap().iter() {
            if neighbour.is_symmetric() {
                queue.push_back(TagLengthValue::Neighbour((*addr).clone()));
            }
        }
    }

    fn flood_message(&self, msg_id: &MessageId, data: &mut DataToFlood<'arena>) {
        let msg = vec![TagLengthValue::Data(*msg_id, data.data.clone())];

        for (addr, state) in data.neighbours_to_flood.iter_mut() {
            if datetime::millis_since(state.last_flooding) > state.next_flooding_delay {
                match self.send_sdu(addr, &msg) {
                    Ok(()) => state.flooded(datetime::now(), self.rng.write().unwrap()),
                    _ => { /* TODO */ }
                }
            }
        }
    }

    fn flood_all_messages(&self, inactives: &mut HashSet<&'arena Addr>) {
        for (msg_id, data) in self.data.read().unwrap().iter() {
            let data = &mut *data.write().unwrap();
            self.flood_message(msg_id, data);

            data.neighbours_to_flood
                .drain_filter(|_, state| state.flooding_times >= LocalUser::MAX_FLOODING_TIMES)
                .for_each(|(addr, _)| {
                    inactives.insert(addr);
                });
            break;
        }
    }

    pub(crate) fn routine(&mut self) {
        if datetime::millis_since(self.last_hello) > LocalUser::HELLO_INTERVAL {
            self.send_hellos();
            self.last_hello = datetime::now();
        }

        if datetime::millis_since(self.last_neighbourhood)
            > LocalUser::NEIGHBOURHOOD_BROADCAST_INTERVAL
        {
            self.brodcast_neighbourhood();
            self.last_neighbourhood = datetime::now();
        }

        let mut inactives = HashSet::new();
        self.flood_all_messages(&mut inactives);

        for inactive in inactives {
            self.tva.mark_inactive(
                inactive,
                &self.socket,
                Some("You didn't acknoledge a message in time.".to_owned()),
            );
        }
        self.receive_message();
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
        let (addr, msg) = self.socket.receive_message()?;
        let addr = self.hashcons(addr);

        for tlv in msg {
            self.process_tlv(addr, tlv);
        }
        Ok(())
    }

    pub(crate) fn send_data(&self, data: String) {
        let data_vec = Data::pack(&data);

        for data in data_vec {
            let receive_time = datetime::now();
            let data = self.prepare_flooding(receive_time, data);

            let next_id = &mut *self.next_msg_id.write().unwrap();
            *next_id += 1;

            self.data
                .write()
                .unwrap()
                .insert((self.id, *next_id), RwLock::new(data));
        }
    }
}

// Warning:
// Sync and Send implementations forced because
// only fields rng, next_msg_id, data and tva are synchronized.
//
// LocalUser is thread-safe only under the assumption it
// is used appropriately: 'routine' should be used only on the thread
// that owns the object, and only 'send_data' can be called concurrently
// by other threads.
unsafe impl Sync for LocalUser<'_> {}
unsafe impl Send for LocalUser<'_> {}

/* #endregion LocalUser */
