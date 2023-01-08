extern crate rand;

use std::collections::hash_map::Iter;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::io::Write;
use std::net::UdpSocket;
use std::ops::{Deref, DerefMut};
use std::rc::{Rc, Weak};
use std::sync::{RwLock, RwLockWriteGuard};

use self::rand::rngs::ThreadRng;
use self::rand::Rng;
use crate::datetime::{self, DateTime};
use crate::error::{
    AggregateError, AggregateResult, DeliveryResult, MessageDeliveryError, ParseError, ParseResult,
};
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

impl<'arena> ActiveNeighbour<'arena> {
    fn new(id: PeerID, addr: &'arena Addr, symmetric: bool) -> ActiveNeighbour<'arena> {
        let last_hello = datetime::now();
        let last_long_hello = if symmetric {
            last_hello
        } else {
            datetime::never()
        };
        ActiveNeighbour {
            id,
            addr,
            last_hello,
            last_long_hello,
        }
    }

    fn mark_symmetric(&mut self) {
        self.last_long_hello = datetime::now();
    }

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

    fn remove(&self, addr: &'arena Addr) {
        self.0.write().unwrap().remove(addr);
    }

    fn mark_active(&self, addr: &'arena Addr, id: PeerID, symmetric: bool) {
        self.0
            .write()
            .unwrap()
            .insert(addr, ActiveNeighbour::new(id, addr, symmetric));
    }

    fn mark_inactive(
        &self,
        addr: &'arena Addr,
        socket: &MircHost,
        msg: Option<String>,
    ) -> DeliveryResult<()> {
        self.remove(addr);

        socket.send_single_tlv(
            addr,
            TagLengthValue::GoAway(
                GoAwayReason::Inactivity,
                msg.map(|str| {
                    // the error is (supposed to be) used when receiving the TLV,
                    // it is ignored when sending it.
                    LimitedString::try_from(str).map_err(|_| ParseError::ProtocolViolation)
                }),
            ),
        )
    }

    fn mark_all_inactive(
        &self,
        who: Vec<&'arena Addr>,
        socket: &MircHost,
        msg: Option<String>,
    ) -> AggregateResult<(), MessageDeliveryError> {
        let mut err = AggregateError::NoMoreError;

        for addr in who {
            err = err.aggregate_result(self.mark_inactive(addr, socket, msg.clone()));
        }

        err.into()
    }

    fn is_symmetric(&self, addr: &Addr) -> bool {
        self.0
            .read()
            .unwrap()
            .get(addr)
            .is_some_and(|n| n.is_symmetric())
    }

    fn count_symmetrics(&self) -> usize {
        self.fold(0, |_, n, c| if n.is_symmetric() { c + 1 } else { c })
    }

    fn fold<T, F>(&self, init: T, mut f: F) -> T
    where
        F: FnMut(&'arena Addr, &ActiveNeighbour, T) -> T,
    {
        let mut result = init;
        for (addr, neighbour) in self.0.read().unwrap().iter() {
            result = f(addr, neighbour, result);
        }
        result
    }

    fn broadcast_neighbourhood(
        &self,
        socket: &MircHost,
    ) -> AggregateResult<(), MessageDeliveryError> {
        let mut keys = vec![];
        let mut queue = VecDeque::new();

        for (addr, neighbour) in self.0.read().unwrap().iter() {
            if neighbour.is_symmetric() {
                queue.push_back(TagLengthValue::Neighbour((*addr).clone()));
            }
            keys.push(*addr);
        }
        socket.send_many_tlvs(&keys, queue)
    }

    fn say_hello(
        &self,
        id: PeerID,
        socket: &MircHost,
    ) -> AggregateResult<(), MessageDeliveryError> {
        let mut inactives = vec![];

        let mut err = AggregateError::NoMoreError;

        for (addr, neighbour) in self.0.read().unwrap().iter() {
            if datetime::millis_since(neighbour.last_hello) > LocalUser::ACTIVITY_TIMEOUT {
                inactives.push(*addr);
            } else {
                let hello = TagLengthValue::Hello(id, Some(neighbour.id));
                err = err.aggregate_result(socket.send_single_tlv(addr, hello));
            }
        }
        err = err.aggregate_result_flatten(self.mark_all_inactive(
            inactives,
            socket,
            Some("You have been idle for too long.".to_owned()),
        ));

        err.into()
    }
}

/* #endregion */

/* #region FloodingState */

struct FloodingState<'arena> {
    addr: &'arena Addr,
    flooding_times: u8,
    last_flooding: DateTime,
    next_flooding_delay: u128,
}

impl<'arena> FloodingState<'arena> {
    fn new(time: DateTime, addr: &'arena Addr, rng: &mut ThreadRng) -> FloodingState<'arena> {
        let mut state = FloodingState {
            addr,
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
        msg: &ServiceDataUnit,
        socket: &MircHost,
        rng: &mut ThreadRng,
    ) -> DeliveryResult<()> {
        if self.should_flood() {
            socket.send_sdu(self.addr, msg)?;
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

struct DataToFlood<'arena> {
    receive_time: DateTime,
    msg_id: MessageId,
    data: Rc<Data>,
    neighbours_to_flood: HashMap<&'arena Addr, FloodingState<'arena>>,
}

impl<'arena> DataToFlood<'arena> {
    fn new(
        msg_id: MessageId,
        data: Rc<Data>,
        neighbours: &ActiveNeighbourMap<'arena>,
        rng: &mut ThreadRng,
    ) -> DataToFlood<'arena> {
        let date = datetime::now();

        let neighbours_to_flood = neighbours.fold(HashMap::new(), |addr, n, mut v| {
            if n.is_symmetric() {
                v.insert(addr, FloodingState::new(date, addr, rng));
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
        tva: &ActiveNeighbourMap<'arena>,
    ) -> AggregateResult<(), MessageDeliveryError> {
        let mut err = AggregateError::NoMoreError;

        let msg = vec![TagLengthValue::Data(self.msg_id, self.data.clone())];
        let mut inactives = vec![];

        for (addr, state) in self.neighbours_to_flood.iter_mut() {
            if tva.is_symmetric(addr) {
                match state.flood(&msg, socket, rng) {
                    Ok(()) => (),
                    Err(MessageDeliveryError::NeighbourInactive) => inactives.push(*addr),
                    Err(e) => err = err.aggregate(e),
                }
            } else {
                state.give_up_flooding();
            }
        }

        self.neighbours_to_flood
            .retain(|_, state| !state.should_give_up_flooding());

        err = err.aggregate_result_flatten(tva.mark_all_inactive(
            inactives,
            socket,
            Some("You did not acknoledge a message on time".to_owned()),
        ));

        err.into()
    }
}

/* #endregion */

struct DataToFloodCollection<'arena>(RwLock<HashMap<MessageId, RwLock<DataToFlood<'arena>>>>);

impl<'arena> DataToFloodCollection<'arena> {
    fn new() -> DataToFloodCollection<'arena> {
        DataToFloodCollection(RwLock::new(HashMap::new()))
    }

    fn insert_data(
        &self,
        msg_id: MessageId,
        data: Rc<Data>,
        neighbours: &ActiveNeighbourMap<'arena>,
        mut rng: RwLockWriteGuard<ThreadRng>,
    ) -> bool {
        let data = DataToFlood::new(msg_id, data, neighbours, &mut *rng);
        self.0
            .write()
            .unwrap()
            .try_insert(msg_id, RwLock::new(data))
            .is_ok()
    }

    fn flood_all(
        &self,
        socket: &MircHost,
        rng: &mut ThreadRng,
        neighbours: &ActiveNeighbourMap<'arena>,
    ) -> AggregateResult<(), MessageDeliveryError> {
        let mut err = AggregateError::NoMoreError;

        for (_, data) in self.0.read().unwrap().iter() {
            err =
                err.aggregate_result_flatten(data.write().unwrap().flood(socket, rng, neighbours));
        }
        self.0
            .write()
            .unwrap()
            .retain(|_, data| !data.read().unwrap().flooding_complete());

        err.into()
    }

    fn process_ack(&self, from: &Addr, msg_id: &MessageId) {
        self.0
            .read()
            .unwrap()
            .get(msg_id)
            .inspect(|data| data.write().unwrap().process_ack(from));
    }
}

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

    fn send_many_tlvs(
        &self,
        to: &[&Addr],
        tlvs: VecDeque<TagLengthValue>,
    ) -> AggregateResult<(), MessageDeliveryError> {
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
    data: DataToFloodCollection<'arena>,
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
            data: DataToFloodCollection::new(),
            rng: RwLock::new(rand::thread_rng()),
        };
        socket.hashcons(first_neighbour);
        Ok(socket)
    }

    fn get_rng(&self) -> RwLockWriteGuard<ThreadRng> {
        self.rng.write().unwrap()
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

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&mut self, sender: &'arena Addr, tlv: TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                self.tva
                    .mark_active(sender, sender_id, receiver.contains(&self.id));
            }

            TagLengthValue::Neighbour(addr) => {
                self.hashcons(addr);
            }

            TagLengthValue::Data(msg_id, data) => {
                if self.tva.is_symmetric(sender) {
                    if self
                        .data
                        .insert_data(msg_id, data.clone(), &self.tva, self.get_rng())
                    {
                        //TODO show data
                        std::io::stdout().lock().write(data.to_bytes().as_slice());
                    }
                }

                self.data.process_ack(sender, &msg_id);
                self.send_ack(sender, &msg_id);
            }

            TagLengthValue::Ack(msg_id) => {
                self.data.process_ack(sender, &msg_id);
            }

            TagLengthValue::GoAway(reason, msg) => {
                // TODO verbose
                self.tva.remove(sender)
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

    pub(crate) fn routine(&mut self) {
        if datetime::millis_since(self.last_hello) > LocalUser::HELLO_INTERVAL {
            self.tva.say_hello(self.id, &self.socket);
            self.last_hello = datetime::now();
        }

        if datetime::millis_since(self.last_neighbourhood)
            > LocalUser::NEIGHBOURHOOD_BROADCAST_INTERVAL
        {
            self.tva.broadcast_neighbourhood(&self.socket);
            self.last_neighbourhood = datetime::now();
        }

        self.data
            .flood_all(&self.socket, &mut *self.get_rng(), &self.tva);

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
            let next_id = &mut *self.next_msg_id.write().unwrap();
            *next_id += 1;

            let msg_id = (self.id, *next_id);
            self.data
                .insert_data(msg_id, Rc::new(data), &self.tva, self.get_rng());
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
