extern crate rand;

use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io::Write;
use std::net::UdpSocket;
use std::rc::Rc;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockResult, Mutex};

use crate::datetime::{self, DateTime};
use crate::error::{InactivityResult, NeighbourInactive, ParseError, ParseResult};
use crate::parse::MessageParser;
use crate::util::{
    Data, EventLog, GoAwayReason, LimitedString, MessageFactory, MessageId, PeerID, TagLengthValue,
    VerboseLevel,
};
use crate::{lazy_format, log_anomaly, log_debug, log_important, log_info, log_trace, log_warning};
use addresses::Addr;
use rand::rngs::StdRng;
use self::rand::SeedableRng;

/* #region PARAMETERS */

const min_NS: usize = 1;

const ACTIVITY_TIMEOUT: u128 = 120_000;
const SYMMETRY_TIMEOUT: u128 = 120_000;

const MAX_FLOODING_TIMES: u8 = 5;

const HELLO_INTERVAL: u128 = 30_000;
const NEIGHBOURHOOD_BROADCAST_INTERVAL: u128 = 30_000;

/* #endregion */

/* #region ActiveNeighbour */

struct ActiveNeighbour<'arena> {
    id: PeerID,
    addr: &'arena Addr,
    last_hello: DateTime,
    last_long_hello: DateTime,
}

impl<'arena> ActiveNeighbour<'arena> {
    const fn new(id: PeerID, addr: &'arena Addr) -> ActiveNeighbour<'arena> {
        let last_hello = datetime::never();
        let last_long_hello = last_hello;
        ActiveNeighbour {
            id,
            addr,
            last_hello,
            last_long_hello,
        }
    }

    fn is_symmetric(&self) -> bool {
        datetime::millis_since(self.last_long_hello) < SYMMETRY_TIMEOUT
    }

    fn say_hello(&self, self_id: PeerID, socket: &MircHost<'arena>) -> InactivityResult<()> {
        if datetime::millis_since(self.last_hello) > ACTIVITY_TIMEOUT {
            Err(NeighbourInactive)
        } else {
            let hello = TagLengthValue::Hello(self_id, Some(self.id));
            socket.send_single_tlv(self.addr, Rc::new(hello));
            Ok(())
        }
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

    fn mark_active(&self, addr: &'arena Addr, id: PeerID, symmetric: bool) -> bool {
        let mut lock = self.0.write().unwrap();

        let mut neighbour = lock
            .entry(addr)
            .or_insert_with(|| ActiveNeighbour::new(id, addr));

        let new = neighbour.last_hello == datetime::never();

        neighbour.last_hello = datetime::now();
        if symmetric {
            neighbour.last_long_hello = neighbour.last_hello;
        }

        new
    }

    /// Get the TLV used to report inactivity.
    fn get_inactivity_go_away(msg: Option<String>) -> TagLengthValue {
        TagLengthValue::GoAway(
            GoAwayReason::Inactivity,
            msg.and_then(|str| {
                // the error is used when receiving the TLV,
                // it is ignored when sending it.
                LimitedString::try_from(str).ok().map(Ok)
            }),
        )
    }

    fn mark_all_inactive(
        &self,
        who: &[&'arena Addr],
        socket: &MircHost<'arena>,
        msg: Option<String>,
    ) {
        let msg = Rc::new(Self::get_inactivity_go_away(msg));

        for addr in who {
            log_info!(socket, "Neighbour {0} is now inactive.", addr);
            self.remove(addr);
            socket.send_single_tlv(addr, Rc::clone(&msg));
        }
    }

    fn is_symmetric(&self, addr: &Addr) -> bool {
        self.0
            .read()
            .unwrap()
            .get(addr)
            .is_some_and(ActiveNeighbour::is_symmetric)
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

    fn broadcast_neighbourhood(&self, socket: &MircHost<'arena>) {
        let mut neighbours = vec![];
        let mut msg = vec![];

        for (addr, neighbour) in self.0.read().unwrap().iter() {
            if neighbour.is_symmetric() {
                msg.push(Rc::new(TagLengthValue::Neighbour((*addr).clone())));
            }
            neighbours.push(*addr);
        }
        socket.send_many_tlvs(&neighbours, &msg);
    }

    fn say_hello(&self, id: PeerID, socket: &MircHost<'arena>) {
        let mut inactives = vec![];

        for (addr, neighbour) in self.0.read().unwrap().iter() {
            match neighbour.say_hello(id, socket) {
                Ok(_) => (),
                Err(_) => inactives.push(*addr),
            }
        }
        self.mark_all_inactive(
            &inactives,
            socket,
            Some("You have been idle for too long.".to_owned()),
        );
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
    fn new(time: DateTime, addr: &'arena Addr, rng: &mut StdRng) -> FloodingState<'arena> {
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
        msg: Rc<[u8]>,
        socket: &MircHost<'arena>,
        rng: &mut StdRng,
    ) -> InactivityResult<()> {
        if self.should_flood() {
            if self.should_give_up_flooding() {
                return Err(NeighbourInactive);
            }
            socket.send_precomputed_tlv(self.addr, msg);
            self.flooded(rng);
        }
        Ok(())
    }

    fn flooded(&mut self, rng: &mut StdRng) {
        self.flooding_times += 1;
        self.last_flooding = datetime::now();
        self.next_flooding_delay = self.random_flooding_delay(rng);
    }

    fn random_flooding_delay(&self, rng: &mut StdRng) -> u128 {
        if self.flooding_times == 0 {
            rng.gen_range(500..1000)
        } else {
            rng.gen_range(
                (1000 * (1 << (self.flooding_times - 1)))..(1000 * (1 << self.flooding_times)),
            )
        }
    }

    const fn should_give_up_flooding(&self) -> bool {
        self.flooding_times > MAX_FLOODING_TIMES
    }

    fn give_up_flooding(&mut self) {
        self.flooding_times = MAX_FLOODING_TIMES + 1;
    }
}

/* #endregion */

/* #region DataToFlood */

struct DataToFlood<'arena> {
    msg_id: MessageId,
    receive_time: DateTime, //TODO
    precomputed: Rc<[u8]>,
    neighbours_to_flood: HashMap<&'arena Addr, FloodingState<'arena>>,
}

impl<'arena> DataToFlood<'arena> {
    fn new(
        msg_id: MessageId,
        data: Data,
        neighbours: &ActiveNeighbourMap<'arena>,
        rng: &mut StdRng,
    ) -> DataToFlood<'arena> {
        let date_now = datetime::now();

        let neighbours_to_flood = neighbours.fold(HashMap::new(), |addr, n, mut v| {
            if n.is_symmetric() {
                v.insert(addr, FloodingState::new(date_now, addr, rng));
            }
            v
        });

        let precomputed = Rc::from(
            TagLengthValue::Data(msg_id, data)
                .try_to_bytes()
                .unwrap_or_default(),
        );

        DataToFlood {
            msg_id,
            receive_time: date_now,
            precomputed,
            neighbours_to_flood,
        }
    }

    fn process_ack(&mut self, socket: &MircHost, from: &Addr) {
        if self.neighbours_to_flood.remove(from).is_some() {
            log_info!(
                socket,
                "Data {0} has been received by {1}",
                self.msg_id,
                from
            );
            if self.flooding_complete() {
                log_info!(socket, "Message {0} delivery complete.", self.msg_id);
            }
        }
    }
    fn flooding_complete(&self) -> bool {
        self.neighbours_to_flood.is_empty()
    }

    fn flood(
        &mut self,
        socket: &MircHost<'arena>,
        rng: &mut StdRng,
        tva: &ActiveNeighbourMap<'arena>,
    ) {
        let mut inactives = vec![];

        for (addr, state) in &mut self.neighbours_to_flood {
            if tva.is_symmetric(addr) {
                match state.flood(Rc::clone(&self.precomputed), socket, rng) {
                    Ok(()) => (),
                    Err(_ /*MessageDeliveryError::NeighbourInactive*/) => inactives.push(*addr),
                }
            } else {
                state.give_up_flooding();
            }
        }

        self.neighbours_to_flood
            .retain(|_, state| !state.should_give_up_flooding());

        tva.mark_all_inactive(
            &inactives,
            socket,
            Some("You did not acknoledge a message on time".to_owned()),
        );
    }
}

/* #endregion */

/* #region DataToFloodCollection */
struct DataToFloodCollection<'arena>(RwLock<HashMap<MessageId, RwLock<DataToFlood<'arena>>>>);

impl<'arena> DataToFloodCollection<'arena> {
    fn new() -> DataToFloodCollection<'arena> {
        DataToFloodCollection(RwLock::new(HashMap::new()))
    }

    fn insert_data(
        &self,
        msg_id: MessageId,
        data: Data,
        neighbours: &ActiveNeighbourMap<'arena>,
        mut rng: RwLockWriteGuard<StdRng>,
    ) -> bool {
        let data = DataToFlood::new(msg_id, data, neighbours, &mut rng);
        self.0
            .write()
            .unwrap()
            .try_insert(msg_id, RwLock::new(data))
            .is_ok()
    }

    fn flood_all(
        &self,
        socket: &MircHost<'arena>,
        rng: &mut StdRng,
        neighbours: &ActiveNeighbourMap<'arena>,
    ) {
        for (_, data) in self.0.read().unwrap().iter() {
            data.write().unwrap().flood(socket, rng, neighbours);
        }
        self.0
            .write()
            .unwrap()
            .retain(|_, data| !data.read().unwrap().flooding_complete());
    }

    fn process_ack(&self, socket: &MircHost, from: &Addr, msg_id: &MessageId) {
        if let Some(data) = self.0.read().unwrap().get(msg_id) {
            data.write().unwrap().process_ack(socket, from);
        }
    }
}

/* #endregion */

fn _is_remote_fault(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
    )
}

macro_rules! report_on_fail {
    ($logger: expr, $e: expr) => {
        match $e {
            Ok(_) => (),
            Err(err) if _is_remote_fault(&err) => $logger.debug(err),
            Err(err) => $logger.error(err),
        }
    };
}

/* #region MircHost */

/// A wrapped for a `UdpSocket` with buffering.
struct MircHost<'arena> {
    socket: UdpSocket,
    local_addr: Addr,
    buffer: RefCell<HashMap<&'arena Addr, MessageFactory>>,
    logger: EventLog,
    /// Tells whether the buffer should be automatically
    /// flushed when it reaches a certain size.
    /// Always true in the current implementation.
    auto_flush: bool,
}

impl<'arena> MircHost<'arena> {
    fn new(port: u16, verbose_level: VerboseLevel) -> std::io::Result<MircHost<'arena>> {
        let logger = EventLog::new(verbose_level);

        let addr = Addr::try_from(("::", port))
            .map_err(|_err| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        let local_addr: Addr = socket.local_addr()?.into();

        Ok(MircHost {
            socket,
            local_addr,
            buffer: RefCell::new(HashMap::new()),
            logger,
            auto_flush: true,
        })
    }

    const fn get_logger(&self) -> &EventLog {
        &self.logger
    }

    fn get_queue<'a>(
        map: &'a mut RefMut<HashMap<&'arena Addr, MessageFactory>>,
        to: &'arena Addr,
    ) -> &'a mut MessageFactory {
        map.entry(to).or_insert_with(MessageFactory::new)
    }

    fn flush_if_appropriate(&self, to: &'arena Addr, queue: &mut MessageFactory) {
        if self.auto_flush && queue.should_flush() {
            self.flush(to, queue);
        }
    }

    fn flush(&self, to: &'arena Addr, queue: &mut MessageFactory) {
        loop {
            let msg = queue.build_next();
            if msg.len() <= 4 {
                // no TLV
                return;
            }
            log_debug!(self, "Sending bytes to {to}: {msg:?}");
            report_on_fail!(self.get_logger(), self.socket.send_to(&msg, to));
        }
    }

    /// Forces to flush the buffer, causing all the messages to be immediately sent to
    /// the neighbours.
    /// This method should be called regularly, even if auto-flush is enabled, because
    /// the buffer may not reach the minimum size for auto-flush in a reasonable delay.
    fn flush_all(&self) {
        for (addr, queue) in self.buffer.borrow_mut().iter_mut() {
            self.flush(addr, queue);
        }
    }

    /// Send a single precomputed TVL to a neighbour.
    /// The message may not be sent immediately due to buffering.
    /// The TLV may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_precomputed_tlv(&self, to: &'arena Addr, tlv: Rc<[u8]>) {
        let mut buffer = self.buffer.borrow_mut();
        let queue = Self::get_queue(&mut buffer, to);

        queue.enqueue_precomputed(tlv);
        self.flush_if_appropriate(to, queue);
    }

    /// Send a single TVL to a neighbour.
    /// The message may not be sent immediately due to buffering.
    /// The TLV may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_single_tlv(&self, to: &'arena Addr, tlv: Rc<TagLengthValue>) {
        let mut buffer = self.buffer.borrow_mut();
        let queue = Self::get_queue(&mut buffer, to);

        queue.enqueue_tlv(tlv);
        self.flush_if_appropriate(to, queue);
    }

    /// Send multiple TVLs to multiple neighbours.
    /// The messages may not be sent immediately due to buffering.
    /// The TLVs may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_many_tlvs(&self, to: &[&'arena Addr], tlvs: &[Rc<TagLengthValue>]) {
        for addr in to {
            let mut buffer = self.buffer.borrow_mut();
            let queue = Self::get_queue(&mut buffer, addr);

            queue.enqueue_many_tlvs(tlvs);
            self.flush_if_appropriate(addr, queue);
        }
    }

    /// Receives a message sent by a neighbour (if any), or
    /// returns the parse error.
    fn receive_message(&self) -> ParseResult<(Addr, Vec<TagLengthValue>)> {
        MessageParser::try_parse(&self.socket, &self.logger)
    }
}

/* #endregion */

/* #region LocalUser */

/// A struct representing the peer
/// using this local instance of the program
pub struct LocalUser<'arena> {
    id: PeerID,
    socket: MircHost<'arena>,
    alloc: &'arena bumpalo::Bump,
    last_hello: DateTime,
    last_neighbourhood: DateTime,
    tvp: HashSet<&'arena Addr>,
    tva: ActiveNeighbourMap<'arena>,
    next_msg_id: AtomicU32,
    data: DataToFloodCollection<'arena>,
    rng: Mutex<rand::rngs::StdRng>,
}

impl<'arena> LocalUser<'arena> {
    /// Creates a new `LocalPeerSocket` object and binds it to the
    /// specified port.
    /// # Errors
    /// This method fails if it cannot bind the socket.
    pub fn new(
        alloc: &'arena bumpalo::Bump,
        port: u16,
        first_neighbour: &str,
        verbose_level: VerboseLevel,
    ) -> std::io::Result<LocalUser<'arena>> {
        let first_neighbour = Addr::try_from(first_neighbour)
            .map_err(|_err| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
        let socket = MircHost::new(port, verbose_level)?;

        let mut rng = rand::rngs::StdRng::from_entropy();
        let id = PeerID::new(&mut rng);
        let mut socket = LocalUser {
            id,
            socket,
            alloc,
            last_hello: datetime::never(),
            last_neighbourhood: datetime::now(),
            tvp: HashSet::new(),
            tva: ActiveNeighbourMap::new(),
            next_msg_id: Mutex::new(0),
            data: DataToFloodCollection::new(),
            rng: Mutex::new(rng),
        };
        log_important!(socket, "Local client ID: {id}");
        socket.hashcons(first_neighbour);
        Ok(socket)
    }

    fn get_rng(&self) -> RwLockWriteGuard<StdRng> {
        self.rng.write().unwrap()
    }

    fn hashcons(&mut self, addr: Addr) -> &'arena Addr {
        if let Some(addr) = self.tvp.get(&addr) {
            addr
        } else {
            let addr = self.alloc.alloc(addr);
            self.tvp.insert(addr);
            self.tvp.get(addr).unwrap()
        }
    }

    pub const fn get_logger(&self) -> &EventLog {
        &self.socket.logger
    }

    /// Sends an Ack for the specified message to a peer.
    fn send_ack(&self, to: &'arena Addr, msg_id: &MessageId) {
        let tlv = TagLengthValue::Ack(*msg_id);
        self.socket.send_single_tlv(to, Rc::new(tlv));
    }

    fn send_warning(&self, to: &'arena Addr, msg: String) {
        let tlv = TagLengthValue::Warning(LimitedString::try_from(msg).unwrap());
        self.socket.send_single_tlv(to, Rc::new(tlv));
    }

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&mut self, sender: &'arena Addr, tlv: TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                if self
                    .tva
                    .mark_active(sender, sender_id, receiver.contains(&self.id))
                {
                    self.tva
                        .0
                        .read()
                        .unwrap()
                        .get(sender)
                        .unwrap()
                        .say_hello(self.id, &self.socket)
                        .unwrap();

                    log_info!(self, "New active neighbour: {sender} (id: {sender_id})");
                }
            }

            TagLengthValue::Neighbour(addr) => {
                if addr != self.socket.local_addr {
                    self.hashcons(addr);
                }
            }

            TagLengthValue::Data(msg_id, data) => {
                if self.tva.is_symmetric(sender)
                    && self
                        .data
                        .insert_data(msg_id, data.clone(), &self.tva, self.get_rng())
                {
                    log_info!(
                        self,
                        "Received new data (id: {0}) from {1}: {2}",
                        &msg_id,
                        sender,
                        &data
                    );
                    report_on_fail!(
                        self.get_logger(),
                        std::io::stdout().lock().write(data.as_bytes())
                    );
                    report_on_fail!(self.get_logger(), std::io::stdout().lock().write(b"\n"));
                }

                self.data.process_ack(&self.socket, sender, &msg_id);
                self.send_ack(sender, &msg_id);
            }

            TagLengthValue::Ack(msg_id) => {
                self.data.process_ack(&self.socket, sender, &msg_id);
            }

            TagLengthValue::GoAway(_reason, msg) => {
                self.tva.remove(sender);

                if let Some(Err(err)) = msg {
                    log_anomaly!(
                        self,
                        "Failed to parse 'GoAway' user-friendly message:\n{err}"
                    );
                }
            }

            TagLengthValue::Warning(msg) => {
                log_warning!(self, "Warning sent from: {sender}:\n{msg}");
            }

            TagLengthValue::Unrecognized(tag, _) => {
                self.send_warning(sender, format!("Unrecognized tag {tag} was ignored."));
                log_anomaly!(self, "Unrecognized tag {tag} received from {sender}");
            }

            TagLengthValue::Illegal(tag, err) => {
                self.send_warning(
                    sender,
                    format!("Tag {tag} had illegal content and was ignored."),
                );
                log_warning!(
                    self,
                    "Tag {0} was received from {1} with illegal content:\n{2}",
                    tag,
                    sender,
                    err
                );
            }
            _ => {}
        }
    }

    fn look_for_friends(&self) {
        for addr in &self.tvp {
            if !self.tva.is_symmetric(addr) {
                let tlv = TagLengthValue::Hello(self.id, None);
                self.socket.send_single_tlv(addr, Rc::new(tlv));
            }
        }
    }

    pub fn routine(&mut self) {
        if datetime::millis_since(self.last_hello) > HELLO_INTERVAL {
            self.tva.say_hello(self.id, &self.socket);
            self.last_hello = datetime::now();
        }

        if self.tva.count_symmetrics() < min_NS {
            self.look_for_friends();
        }

        if datetime::millis_since(self.last_neighbourhood) > NEIGHBOURHOOD_BROADCAST_INTERVAL {
            self.tva.broadcast_neighbourhood(&self.socket);
            self.last_neighbourhood = datetime::now();
        }

        self.data
            .flood_all(&self.socket, &mut self.get_rng(), &self.tva);

        self.socket.flush_all();

        match self.receive_message() {
            Ok(()) => (),
            Err(ParseError::ReceiveFailed(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
            }
            Err(ParseError::ReceiveFailed(err)) if _is_remote_fault(&err) => {
                self.get_logger().debug(err);
            }
            Err(ParseError::ReceiveFailed(err)) => self.get_logger().information(err),
            Err(err) => self.get_logger().warning(err),
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
        let (addr, msg) = self.socket.receive_message()?;
        let addr = self.hashcons(addr);

        for tlv in msg {
            log_trace!(self, "Received TLV from {0}: {1:?}", addr, &tlv);
            self.process_tlv(addr, tlv);
        }
        Ok(())
    }

    /// Sends a message to all the symmetric neighbours.
    /// If the message is too large to be sent in a single TLV, it is
    /// automatically split into multiple TLVs.
    ///
    /// This function does not immediately sends the data, it only
    /// enqueues it as a data to flood.
    pub fn send_data(&self, data_str: &str) {
        let data_vec = Data::pack(data_str.trim());

        for data in data_vec {
            log_trace!(self, "Preparing data to flood: {0:?}", &data.as_bytes());

            let next_id = &mut *self.next_msg_id.write().unwrap();
            *next_id += 1;

            let msg_id = MessageId::from((self.id, *next_id));
            self.data
                .insert_data(msg_id, data, &self.tva, self.get_rng());
        }
    }

    // Self does not need to be mut, but this allows to prevent
    // this function from being called from the wrong thread (see main::use_client).
    pub fn shutdown(&mut self) {
        log_important!(self, "Shutting down...");
        let tlv = Rc::new(TagLengthValue::GoAway(GoAwayReason::EmitterLeaving, None));
        self.tva.fold((), |addr, _, ()| {
            self.socket.send_single_tlv(addr, Rc::clone(&tlv));
        });
    }
}


/* #endregion LocalUser */

/// A wrapper of a `RwLock` that only exposes the `read` and `try_read` functions.
pub struct ReadOnlyRwLock<T>(Arc<RwLock<T>>);

impl<T> From<Arc<RwLock<T>>> for ReadOnlyRwLock<T> {
    fn from(value: Arc<RwLock<T>>) -> Self {
        ReadOnlyRwLock(value)
    }
}

impl<T> ReadOnlyRwLock<T> {
    pub fn read(&self) -> Result<RwLockReadGuard<T>, PoisonError<RwLockReadGuard<T>>> {
        self.0.read()
    }

    // Function kept for consistency
    #[allow(unused)]
    pub fn try_read(&self) -> TryLockResult<RwLockReadGuard<T>> {
        self.0.try_read()
    }
}
