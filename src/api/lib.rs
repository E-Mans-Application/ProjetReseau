use crossbeam::channel::Receiver;
use rand::{rngs::StdRng, Rng, SeedableRng};

use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryFrom,
    io::Write,
    iter::FromIterator,
    net::UdpSocket,
    rc::{Rc, Weak},
};

use super::{
    addresses::Addr,
    datetime::{self, DateTime},
    error::{InactivityResult, NeighbourInactive, ParseError, ParseResult},
    logging::EventLog,
    parse::MessageParser,
    util::{Data, GoAwayReason, LimitedString, MessageFactory, MessageId, PeerID, TagLengthValue},
};
use crate::{lazy_format, log_anomaly, log_debug, log_important, log_info, log_trace, log_warning};

/* #region PARAMETERS */

const ALLOW_SELF_INVITATION: bool = false;

const min_NS: usize = 1;

const ACTIVITY_TIMEOUT: u128 = 120_000;
const SYMMETRY_TIMEOUT: u128 = 120_000;

const MAX_FLOODING_TIMES: u8 = 5;

const HELLO_INTERVAL: u128 = 30_000;
const NEIGHBOURHOOD_BROADCAST_INTERVAL: u128 = 1_000;
const MIN_PING_INTERVAL: u128 = 1_000;

/* #endregion */

trait EntryExtension {
    fn is_vacant(&self) -> bool;
}

impl<K, V> EntryExtension for Entry<'_, K, V> {
    fn is_vacant(&self) -> bool {
        matches!(self, Entry::Vacant(_))
    }
}

/* #region ActiveNeighbour */

struct ActiveNeighbour<'arena> {
    id: PeerID,
    addr: &'arena Addr,
    last_hello: DateTime,
    last_long_hello: DateTime,
}

impl<'arena> ActiveNeighbour<'arena> {
    const fn new(id: PeerID, addr: &'arena Addr) -> Self {
        let never = datetime::never();
        Self {
            id,
            addr,
            last_hello: never,
            last_long_hello: never,
        }
    }

    fn is_symmetric(&self) -> bool {
        datetime::millis_since(self.last_long_hello) < SYMMETRY_TIMEOUT
    }

    fn say_hello(&self, local_id: PeerID, socket: &MircHost<'arena>) -> InactivityResult<()> {
        if datetime::millis_since(self.last_hello) > ACTIVITY_TIMEOUT {
            Err(NeighbourInactive)
        } else {
            let hello = TagLengthValue::Hello(local_id, Some(self.id));
            socket.send_single_tlv(self.addr, Rc::new(hello));
            Ok(())
        }
    }
}

/* #endregion */

struct NeighbourHood<'arena> {
    alloc: &'arena bumpalo::Bump,
    socket: &'arena MircHost<'arena>,
    tvp: HashSet<&'arena Addr>,
    tva: HashMap<&'arena Addr, Rc<RefCell<ActiveNeighbour<'arena>>>>,
    last_broadcast: DateTime,
    last_greetings: DateTime,
    last_ping: DateTime,
}

impl<'arena> NeighbourHood<'arena> {
    fn new(alloc: &'arena bumpalo::Bump, socket: &'arena MircHost<'arena>) -> Self {
        Self {
            alloc,
            socket,
            tvp: HashSet::new(),
            tva: HashMap::new(),
            last_broadcast: datetime::now(),
            last_greetings: datetime::never(),
            last_ping: datetime::never(),
        }
    }

    fn welcome(&mut self, addr: Addr, authorized: bool) -> Option<&'arena Addr> {
        if let Some(registered) = self.tvp.get(&addr) {
            Some(*registered)
        } else if ALLOW_SELF_INVITATION || authorized {
            let addr = self.alloc.alloc(addr);
            self.tvp.insert(addr);
            Some(addr)
        } else {
            None
        }
    }

    fn mark_active(
        &mut self,
        addr: &'arena Addr,
        id: PeerID,
    ) -> (bool, &Rc<RefCell<ActiveNeighbour<'arena>>>) {
        let neighbour = self.tva.entry(addr);
        let new = neighbour.is_vacant();

        let neighbour =
            neighbour.or_insert_with(|| Rc::new(RefCell::new(ActiveNeighbour::new(id, addr))));
        neighbour.borrow_mut().last_hello = datetime::now();
        (new, neighbour)
    }

    fn count_symmetrics(&self) -> usize {
        self.fold(
            0,
            |_, n, c| if n.borrow().is_symmetric() { c + 1 } else { c },
        )
    }

    fn is_symmetric(&self, addr: &Addr) -> bool {
        self.tva
            .get(addr)
            .is_some_and(|n| n.borrow().is_symmetric())
    }

    fn dismiss(&mut self, who: &[&'arena Addr], reason: GoAwayReason, msg: Option<String>) {
        let msg = Rc::new(TagLengthValue::GoAway(
            reason,
            msg.map(|m| LimitedString::try_from(m).map_err(|_err| ParseError::StringTooLarge)),
        ));

        for addr in who {
            log_info!(self.socket, "Neighbour {0} is now inactive.", addr);
            self.tva.remove(addr);
            self.socket.send_single_tlv(addr, Rc::clone(&msg));
        }
    }

    fn should_greet(&self) -> bool {
        datetime::millis_since(self.last_greetings) > HELLO_INTERVAL
    }

    fn greet_all(&mut self, id: PeerID) {
        let mut inactives = vec![];

        for (addr, neighbour) in &self.tva {
            if neighbour.borrow().say_hello(id, self.socket).is_err() {
                inactives.push(*addr);
            }
        }
        self.last_greetings = datetime::now();

        self.dismiss(
            &inactives,
            GoAwayReason::Inactivity,
            Some("You have been idle for too long.".to_owned()),
        );
    }

    fn should_broadcast(&self) -> bool {
        datetime::millis_since(self.last_broadcast) > NEIGHBOURHOOD_BROADCAST_INTERVAL
    }

    fn broadcast(&mut self) {
        let mut neighbours = vec![];
        let mut msg = vec![];

        for (addr, neighbour) in &self.tva {
            if neighbour.borrow().is_symmetric() {
                msg.push(Rc::new(TagLengthValue::Neighbour((*addr).clone())));
            }
            neighbours.push(*addr);
        }
        self.socket.send_many_tlvs(&neighbours, &msg);
        self.last_broadcast = datetime::now();
    }

    fn should_ping(&self) -> bool {
        self.count_symmetrics() < min_NS
            && datetime::millis_since(self.last_ping) > MIN_PING_INTERVAL
    }

    fn ping(&mut self, local_id: PeerID) {
        let tlv = Rc::new(TagLengthValue::Hello(local_id, None));

        for addr in &self.tvp {
            if !self.is_symmetric(addr) {
                self.socket.send_single_tlv(addr, Rc::clone(&tlv));
            }
        }
        self.last_ping = datetime::now();
    }

    fn acknoledge(&self, msg_id: MessageId) {
        let tlv = Rc::new(TagLengthValue::Ack(msg_id));
        self.for_each(|addr, _| {
            self.socket.send_single_tlv(addr, Rc::clone(&tlv));
        });
    }

    fn routine(&mut self, local_id: PeerID) {
        if self.should_greet() {
            self.greet_all(local_id);
        }

        if self.should_ping() {
            self.ping(local_id);
        }

        if self.should_broadcast() {
            self.broadcast();
        }
    }

    fn fold<T, F>(&self, init: T, mut f: F) -> T
    where
        F: FnMut(&'arena Addr, &Rc<RefCell<ActiveNeighbour<'arena>>>, T) -> T,
    {
        let mut result = init;
        for (addr, neighbour) in &self.tva {
            result = f(addr, neighbour, result);
        }
        result
    }

    fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&'arena Addr, &Rc<RefCell<ActiveNeighbour<'arena>>>),
    {
        self.fold((), |addr, neighbour, ()| f(addr, neighbour));
    }
}

/* #region FloodingState */

struct FloodingState<'arena> {
    neighbour: Weak<RefCell<ActiveNeighbour<'arena>>>,
    flooding_times: u8,
    last_flooding: DateTime,
    next_flooding_delay: u128,
}

impl<'arena> FloodingState<'arena> {
    fn new(
        time: DateTime,
        neighbour: &Rc<RefCell<ActiveNeighbour<'arena>>>,
        rng: &mut StdRng,
    ) -> Self {
        let mut state = Self {
            neighbour: Rc::downgrade(neighbour),
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
        rng: &mut StdRng,
        socket: &MircHost<'arena>,
    ) -> InactivityResult<()> {
        if !self.should_give_up_flooding() {
            if let Some(addr) = self.get_neighbour_addr() {
                socket.send_precomputed_tlv(addr, msg);
                self.flooded(rng);
                return Ok(());
            }
        }
        Err(NeighbourInactive)
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

    fn should_give_up_flooding(&self) -> bool {
        self.flooding_times > MAX_FLOODING_TIMES || self.neighbour.upgrade().is_none()
    }

    fn get_neighbour_addr(&self) -> Option<&'arena Addr> {
        self.neighbour.upgrade().map(|n| n.borrow().addr)
    }
}

/* #endregion */

/* #region DataToFlood */

struct RecentData<'arena> {
    msg_id: MessageId,
    receive_time: DateTime, //TODO
    precomputed: Rc<[u8]>,
    neighbours_to_flood: HashMap<&'arena Addr, FloodingState<'arena>>,
    socket: &'arena MircHost<'arena>,
}

impl<'arena> RecentData<'arena> {
    fn new(
        msg_id: MessageId,
        data: Data,
        neighbours: &NeighbourHood<'arena>,
        rng: &mut StdRng,
        socket: &'arena MircHost<'arena>,
    ) -> Self {
        let date_now = datetime::now();

        let mut neighbours_to_flood = HashMap::new();
        neighbours.for_each(|addr, neighbour| {
            if neighbour.borrow().is_symmetric() {
                neighbours_to_flood.insert(addr, FloodingState::new(date_now, neighbour, rng));
            }
        });

        let precomputed = Rc::from(
            TagLengthValue::Data(msg_id, data)
                .try_to_bytes()
                .unwrap_or_default(),
        );
        
        Self {
            msg_id,
            receive_time: date_now,
            precomputed,
            neighbours_to_flood,
            socket,
        }
    }

    fn process_ack(&mut self, from: &Addr) {
        if self.neighbours_to_flood.remove(from).is_some() {
            log_info!(
                self.socket,
                "Data {0} has been received by {1}",
                self.msg_id,
                from
            );
            if self.flooding_complete() {
                log_info!(self.socket, "Message {0} delivery complete.", self.msg_id);
            }
        }
    }

    fn flooding_complete(&self) -> bool {
        self.neighbours_to_flood.is_empty()
    }

    fn flood(&mut self, rng: &mut StdRng) -> HashSet<&'arena Addr> {
        let mut inactives = HashSet::new();

        for (addr, state) in &mut self.neighbours_to_flood {
            if state.should_flood() {
                match state.flood(Rc::clone(&self.precomputed), rng, self.socket) {
                    Ok(()) => (),
                    Err(NeighbourInactive) => {
                        inactives.insert(*addr);
                    }
                }
            }
        }

        self.neighbours_to_flood
            .retain(|_, state| !state.should_give_up_flooding());

        inactives
    }
}

/* #endregion */

/* #region DataToFloodCollection */
struct RecentDataMap<'arena> {
    neighbourhood: Rc<RefCell<NeighbourHood<'arena>>>,
    next_msg_id: u32,
    stream: Receiver<String>,
    recent_data: HashMap<MessageId, RecentData<'arena>>,
    socket: &'arena MircHost<'arena>,
}

impl<'arena> RecentDataMap<'arena> {
    fn new(
        neighbourhood: Rc<RefCell<NeighbourHood<'arena>>>,
        stream: Receiver<String>,
        socket: &'arena MircHost<'arena>,
    ) -> Self {
        Self {
            neighbourhood,
            next_msg_id: 0,
            stream,
            recent_data: HashMap::new(),
            socket,
        }
    }

    fn insert_data(&mut self, msg_id: MessageId, data: Data, rng: &mut StdRng) -> bool {
        let data = RecentData::new(msg_id, data, &self.neighbourhood.borrow(), rng, self.socket);
        if data.neighbours_to_flood.is_empty() {
            log_important!(self.socket, "There is nobody to send your message to...");
        }
        self.recent_data.try_insert(msg_id, data).is_ok()
    }

    /// Sends a message to all the symmetric neighbours.
    /// If the message is too large to be sent in a single TLV, it is
    /// automatically split into multiple TLVs.
    ///
    /// This function does not immediately sends the data, it only
    /// enqueues it as a data to flood.
    fn read_stream(&mut self, local_id: PeerID, rng: &mut StdRng) {
        if let Ok(data_str) = self.stream.try_recv() {
            let data_vec = Data::pack(data_str.trim());

            for data in data_vec {
                log_trace!(
                    self.socket,
                    "Preparing data to flood: {0:?}",
                    data.as_bytes()
                );

                let next_id = self.next_msg_id;
                self.next_msg_id += 1;

                let msg_id = MessageId::from((local_id, next_id));
                self.insert_data(msg_id, data, rng);
            }
        }
    }

    fn flood_all(&mut self, rng: &mut StdRng) {
        let mut inactives = HashSet::new();
        for data in self.recent_data.values_mut() {
            inactives.extend(data.flood(rng));
        }
        self.recent_data.retain(|_, data| !data.flooding_complete());

        self.neighbourhood.borrow_mut().dismiss(
            Vec::from_iter(inactives).as_slice(),
            GoAwayReason::Inactivity,
            Some("You did not acknoledge a message on time.".to_owned()),
        );
    }

    fn process_ack(&mut self, from: &Addr, msg_id: &MessageId) {
        if let Some(data) = self.recent_data.get_mut(msg_id) {
            data.process_ack(from);
        }
    }
}

/* #endregion */

trait RemoteError {
    fn is_remote_fault(&self) -> bool {
        false
    }
}
impl RemoteError for std::io::Error {
    fn is_remote_fault(&self) -> bool {
        matches!(
            self.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
        )
    }
}
impl RemoteError for NeighbourInactive {
    fn is_remote_fault(&self) -> bool {
        false
    }
}

macro_rules! report_on_fail {
    ($logger: expr, $e: expr) => {
        match $e {
            Ok(_) => (),
            Err(err) if err.is_remote_fault() => $logger.debug(err),
            Err(err) => $logger.error(err),
        }
    };
}

/* #region MircHost */

/// A wrapper for a `UdpSocket` with buffering.
pub(super) struct MircHost<'arena> {
    socket: UdpSocket,
    local_addr: Addr,
    buffer: RefCell<HashMap<&'arena Addr, MessageFactory>>,
    /// Tells whether the buffer should be automatically
    /// flushed when it reaches a certain size.
    /// Always true in the current implementation.
    auto_flush: bool,
    logger: &'arena EventLog,
}

impl<'arena> MircHost<'arena> {
    pub fn new(port: u16, logger: &'arena EventLog) -> std::io::Result<Self> {
        let addr = Addr::try_from(("::", port))
            .map_err(|_err| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        let local_addr: Addr = socket.local_addr()?.into();

        Ok(Self {
            socket,
            local_addr,
            buffer: RefCell::new(HashMap::new()),
            auto_flush: true,
            logger,
        })
    }

    fn flush_if_appropriate(&self, to: &Addr, queue: &mut MessageFactory) {
        if self.auto_flush && queue.should_flush() {
            self.flush(to, queue);
        }
    }

    fn flush(&self, to: &Addr, queue: &mut MessageFactory) {
        while let Some(msg) = queue.build_next() {
            log_debug!(self, "Sending bytes to {to}: {msg:?}");
            report_on_fail!(self.logger, self.socket.send_to(&msg, to));
        }
    }

    /// Forces to flush the buffer, causing all the messages to be immediately sent to
    /// the neighbours.
    /// This method should be called regularly, even if auto-flush is enabled, because
    /// the buffer may not reach the minimum size for auto-flush in a reasonable delay.
    fn flush_all(&self) {
        for (addr, queue) in &mut *self.buffer.borrow_mut() {
            self.flush(addr, queue);
        }
    }

    fn with_queue<F>(&self, to: &'arena Addr, f: F)
    where
        F: FnOnce(&mut MessageFactory),
    {
        let mut lock = self.buffer.borrow_mut();
        let queue = lock.entry(to).or_insert_with(MessageFactory::new);
        f(queue);
        self.flush_if_appropriate(to, queue);
    }

    /// Send a single precomputed TVL to a neighbour.
    /// The message may not be sent immediately due to buffering.
    /// The TLV may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_precomputed_tlv(&self, to: &'arena Addr, tlv: Rc<[u8]>) {
        self.with_queue(to, |queue| {
            queue.enqueue_precomputed(tlv);
        });
    }

    /// Send a single TVL to a neighbour.
    /// The message may not be sent immediately due to buffering.
    /// The TLV may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_single_tlv(&self, to: &'arena Addr, tlv: Rc<TagLengthValue>) {
        self.with_queue(to, |queue| {
            queue.enqueue_tlv(tlv);
        });
    }

    /// Send multiple TVLs to multiple neighbours.
    /// The messages may not be sent immediately due to buffering.
    /// The TLVs may be sent in the same datagram as other buffered TLVs when
    /// the buffer is flushed.
    fn send_many_tlvs(&self, to: &[&'arena Addr], tlvs: &[Rc<TagLengthValue>]) {
        for addr in to {
            self.with_queue(addr, |queue| {
                queue.enqueue_many_tlvs(tlvs);
            });
        }
    }

    /// Receives a message sent by a neighbour (if any), or
    /// returns the parse error.
    fn receive_message(&self) -> ParseResult<(Addr, Vec<TagLengthValue>)> {
        MessageParser::try_parse(&self.socket, self.logger)
    }
}

/* #endregion */

/* #region LocalUser */

/// A struct representing the peer
/// using this local instance of the program
pub(super) struct LocalUser<'arena> {
    id: PeerID,
    socket: &'arena MircHost<'arena>,
    neighbours: Rc<RefCell<NeighbourHood<'arena>>>,
    data: RecentDataMap<'arena>,
    rng: rand::rngs::StdRng,
    logger: &'arena EventLog,
}

impl<'arena> LocalUser<'arena> {
    pub fn new(
        first_neighbour: Addr,
        alloc: &'arena bumpalo::Bump,
        socket: &'arena MircHost<'arena>,
        receiver: Receiver<String>,
    ) -> Self {
        let mut rng = rand::rngs::StdRng::from_entropy();

        let id = PeerID::new(&mut rng);
        log_important!(socket, "Local client ID: {id}");

        let mut neighbours = NeighbourHood::new(alloc, socket);
        neighbours.welcome(first_neighbour, true);
        let neighbours = Rc::new(RefCell::new(neighbours));

        let data = RecentDataMap::new(Rc::clone(&neighbours), receiver, socket);

        Self {
            id,
            socket,
            neighbours,
            data,
            rng,
            logger: socket.logger,
        }
    }

    fn warn(&self, addr: &'arena Addr, msg: String) {
        let msg = LimitedString::try_from(msg);
        match msg {
            Err(err) => self.logger.error(lazy_format!(
                "Invalid message used in a 'warning' TLV: {err}"
            )),
            Ok(msg) => {
                let tlv = Rc::new(TagLengthValue::Warning(msg));
                self.socket.send_single_tlv(addr, Rc::clone(&tlv));
            }
        }
    }

    /// Process a single TLV from a received datagram.
    /// 'sender' is the address of the peer that sent the datagram.
    fn process_tlv(&mut self, sender: &'arena Addr, tlv: TagLengthValue) {
        match tlv {
            TagLengthValue::Hello(sender_id, receiver) => {
                let mut lock = self.neighbours.borrow_mut();
                let (new, neighbour) = lock.mark_active(sender, sender_id);
                if new {
                    // This should not fail because neighbour.last_hello has just been
                    // updated.
                    report_on_fail!(
                        self.logger,
                        neighbour.borrow_mut().say_hello(self.id, self.socket)
                    );
                    log_info!(self, "New active neighbour: {sender} (id: {sender_id})");
                }
                if receiver.contains(&self.id) {
                    let mut neighbour = neighbour.borrow_mut();
                    neighbour.last_long_hello = neighbour.last_hello;
                }
            }

            TagLengthValue::Neighbour(addr) => {
                if addr != self.socket.local_addr {
                    self.neighbours.borrow_mut().welcome(addr, false);
                }
            }

            TagLengthValue::Data(msg_id, data) => {
                if self.neighbours.borrow().is_symmetric(sender) {
                    if self.data.insert_data(msg_id, data.clone(), &mut self.rng) {
                        log_info!(
                            self,
                            "Received new data (id: {0}) from {1}: {2}",
                            &msg_id,
                            sender,
                            &data
                        );
                        report_on_fail!(
                            self.logger,
                            std::io::stdout().lock().write(data.as_bytes())
                        );
                        report_on_fail!(self.logger, std::io::stdout().lock().write(b"\n"));
                    }

                    self.data.process_ack(sender, &msg_id);
                    self.neighbours.borrow().acknoledge(msg_id);
                } else {
                    self.warn(
                        sender,
                        "Protocol violation: Please say hello before \
                            flooding data. Your message has been ignored. \
                            This could be more severely punished in a future version."
                            .to_owned(),
                    );
                    log_anomaly!(
                        self,
                        "Data flooded by non symmetric neighbour {sender} have been discarded."
                    );
                }
            }

            TagLengthValue::Ack(msg_id) => {
                self.data.process_ack(sender, &msg_id);
            }

            TagLengthValue::GoAway(_reason, msg) => {
                self.neighbours
                    .borrow_mut()
                    .dismiss(&[sender], GoAwayReason::Reciprocation, None);

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
                self.warn(sender, format!("Unrecognized tag {tag} was ignored."));
                log_anomaly!(self, "Unrecognized tag {tag} received from {sender}");
            }

            TagLengthValue::Illegal(tag, err) => {
                self.warn(
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

    pub fn routine(&mut self) {
        self.neighbours.borrow_mut().routine(self.id);

        self.data.read_stream(self.id, &mut self.rng);
        self.data.flood_all(&mut self.rng);

        self.socket.flush_all();

        match self.receive_message() {
            Ok(()) => (),
            Err(ParseError::ReceiveFailed(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
            }
            Err(ParseError::ReceiveFailed(err)) if err.is_remote_fault() => {
                self.logger.debug(err);
            }
            Err(ParseError::ReceiveFailed(err)) => self.logger.information(err),
            Err(ParseError::ProtocolViolation(from)) => {
                if let Some(addr) = self.neighbours.borrow_mut().welcome(from, false) {
                    self.warn(
                        addr,
                        "Protocol violation (no further information). Please abide by the rules. \
                    This could be more severely punished in a future version."
                            .to_owned(),
                    );
                }
            }
            Err(ParseError::UnknownSender(addr)) => self.logger.anomaly(ParseError::UnknownSender(addr)),
            Err(err) => self.logger.warning(err),
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
        let addr = self
            .neighbours
            .borrow_mut()
            .welcome(addr.clone(), false)
            .ok_or(ParseError::UnknownSender(addr))?;

        for tlv in msg {
            log_trace!(self, "Received TLV from {0}: {1:?}", addr, &tlv);
            self.process_tlv(addr, tlv);
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        log_important!(self, "Shutting down...");
        let tlv = Rc::new(TagLengthValue::GoAway(GoAwayReason::EmitterLeaving, None));
        self.neighbours.borrow_mut().for_each(|addr, _| {
            self.socket.send_single_tlv(addr, Rc::clone(&tlv));
        });
        self.socket.flush_all();
    }
}

/* #endregion LocalUser */
