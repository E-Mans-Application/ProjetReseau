//! This is the main module of the internal, private API.
//! It organizes the different API objects to make them work together.

use crossbeam::channel::Receiver;
use rand::{rngs::StdRng, Rng, SeedableRng};

use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryFrom,
    iter::FromIterator,
    net::{SocketAddr, UdpSocket},
    rc::{Rc, Weak},
};

use super::{
    addresses::Addr,
    datetime::{DateTime, Duration, MillisType},
    error::{InactivityResult, NeighbourInactive, ParseError, ParseResult},
    logging::EventLog,
    parse::{Buffer, MessageParser},
    util::{Data, GoAwayReason, LimitedString, MessageFactory, MessageId, PeerID, TagLengthValue},
};
use crate::{lazy_format, log_anomaly, log_debug, log_important, log_info, log_trace, log_warning, priority_map::QueuedMap};

/* #region PARAMETERS */

/// Indicates whether the socket should use dual-stack to support
/// IPv4 clients. This may not be supported, or not desired, on some
/// systems. Failure to apply this setting will be reported but is not
/// a hard error.
///
///  If [`IPV6_ONLY`] is `true`, the user will not be
/// able to send and receive messages to/from IPv4-mapped addresses.
/// In this case, the address of the first neighbour must be a genuine
/// IPv6 address.
///
/// ### Note on invitations:
/// If [`ALLOW_SELF_INVITATION`] is `false`, then the IP version used to invite
/// a neighbour *matters*. If a neighbour is invited with its IPv6,
/// it will not be able to send messages from its IPv4 because they will be
/// rejected (and vice versa).
const IPV6_ONLY: bool = false;

/// Indicates whether uninvited neighbours are allowed
/// to send messages to this client.
/// A neighbour is said to be "invited" if it is either
/// given as the "first neighbour" argument when the program
/// starts, or it is invited through a "Neighbour" TLV by an
/// invited neighbour.
///
/// If [`ALLOW_SELF_INVITATION`] is true, any uninvited remote
/// that sends a message to this client will be automatically
/// invited (i.e. added to the potential neighbour map).
/// Otherwise, messages from uninvited clients won't be processed.
const ALLOW_SELF_INVITATION: bool = false;

/// Minimum desired number of symmetric neighbours.
/// If the number of symmetric neighbours is lower,
/// an "Hello" TLV will be sent to all the non-symmetric
/// neighbours.
///
/// Note: named "min_NS" in the subject.
const MIN_DESIRED_SYMMETRIC: usize = 1; //TODO

/// Delay (in milliseconds) after which a neighbour is marked as inactive
/// if it does not say hello. (Set by the subject)
const ACTIVITY_TIMEOUT: MillisType = 120_000;

/// Delay (in milliseconds) after which a neighbour is marked as non-symmetric
/// if it does not send a long hello. (Set by the subject)
const SYMMETRY_TIMEOUT: MillisType = 120_000;

/// Number of times a "Data" TLV should be sent to a neighbour
/// before the neighbour is considered as inactive (unless it
/// sends acknoledgment). (Set by the subject)
const MAX_FLOODING_TIMES: u8 = 5;

/// Maximum number of recent data to keep. When this number is exceeded,
/// the oldest message will have its flooding given up, even if not all
/// the symmetric neighbours have acknoledged receipt of it.
/// Set to 0 to disable the limit.
const MAX_RECENT_DATA_COUNT: usize = 100;

/// Maximum age of a recent datum (in milliseconds).
/// Data older than this age will have their flooding given up,
/// even if not all the symmetric neighbours have acknoledged receipt of them.
/// Set to 0 to disable the limit.
const MAX_RECENT_DATA_AGE: MillisType = 1_800_000;

/// Interval (in milliseconds) at which to say hello to the active neighbours.
/// (Set by the subject)
const HELLO_INTERVAL: MillisType = 30_000;

/// Interval (in milliseconds) at which to send the list of symmetric neighbours
/// to all the active neighbours.
const NEIGHBOURHOOD_BROADCAST_INTERVAL: MillisType = 30_000;

/// The minimum interval (in milliseconds) between two "pings" to the potential neighbours.
/// (A ping is the operation performed when [`MIN_DESIRED_SYMMETRIC`] is not respected.)
const MIN_PING_INTERVAL: MillisType = 30_000;

/// The max length of the nickname of the user (used as a header for all `Data` messages
/// written by the user).
/// 
/// MUST be less than ``` DATA_MAX_SIZE - 6 ```
/// because ``` NICKNAME_LENGTH + 1 (space) + 1 (colon) + 4 (max size of a UTF-8 char) <= DATA_MAX_SIZE ```
/// must hold to guarantee that the `Data` TLVs can contain at least one char of the actual message.
pub(super) const MAX_NICKNAME_LENGTH: usize = 20;

pub(super) type NickName = LimitedString<MAX_NICKNAME_LENGTH>;

/* #endregion */

/// Adds a convenience method to `HashMap`'s entries.
trait EntryExtension {
    fn is_vacant(&self) -> bool;
}

impl<K, V> EntryExtension for Entry<'_, K, V> {
    fn is_vacant(&self) -> bool {
        matches!(self, Entry::Vacant(_))
    }
}

/* #region Neighbours */

/// A structure that represents an active neighbour.
struct ActiveNeighbour<'arena> {
    id: PeerID,
    addr: &'arena Addr,
    last_hello: DateTime,
    last_long_hello: DateTime,
}

impl<'arena> ActiveNeighbour<'arena> {
    /// Creates a new `ActiveNeighbour` for the neighbour with the specified `id`
    /// and address.
    const fn new(id: PeerID, addr: &'arena Addr) -> Self {
        let never = DateTime::never();
        Self {
            id,
            addr,
            last_hello: never,
            last_long_hello: never,
        }
    }

    fn is_symmetric(&self) -> bool {
        DateTime::now().millis_since(self.last_long_hello) < SYMMETRY_TIMEOUT
    }

    /// Sends a Hello TLV to the neighbour.
    /// `local_id` is the ID of the local user (`ActiveNeighbour` has no copy of it),
    /// `socket` is the socket used to send the message.
    /// # Errors
    /// If the neighbour has not said hello for more than [`ACTIVITY_TIMEOUT`] milliseconds,
    /// the operation is aborted and this function returns `Err(NeighbourInactive)`.
    fn say_hello(&self, local_id: PeerID, socket: &MircHost<'arena>) -> InactivityResult<()> {
        if DateTime::now().millis_since(self.last_hello) > ACTIVITY_TIMEOUT {
            Err(NeighbourInactive)
        } else {
            let hello = TagLengthValue::Hello(local_id, Some(self.id));
            socket.send_single_tlv(self.addr, Rc::new(hello));
            Ok(())
        }
    }
}

/// A structure that stores all the neighbours (potential or active).
struct NeighbourHood<'arena> {
    alloc: &'arena bumpalo::Bump,
    socket: &'arena MircHost<'arena>,
    tvp: HashSet<&'arena Addr>,
    tva: HashMap<&'arena Addr, Rc<RefCell<ActiveNeighbour<'arena>>>>,
    blocked: HashMap<&'arena Addr, (u32, DateTime)>,
    last_broadcast: DateTime,
    last_greetings: DateTime,
    last_ping: DateTime,
}

impl<'arena> NeighbourHood<'arena> {
    /// Creates a new neighbourhood.
    /// `alloc` is the [`bumpalo::Bump`] used for "hash consing".
    /// `socket` is the socket used to send the messages to the neighbours. It will be
    /// borrowed for all the life of the `NeighbourHood`.
    /// # Note:
    /// Using `&'arena Addr` prevents from storing copies of `Addr` (it is
    /// immutable and value-based, but it takes 18 bytes), but it also allows
    /// to distinguish between an invited or an uninvited neighbour.
    fn new(alloc: &'arena bumpalo::Bump, socket: &'arena MircHost<'arena>) -> Self {
        Self {
            alloc,
            socket,
            tvp: HashSet::new(),
            tva: HashMap::new(),
            blocked: HashMap::new(),
            last_broadcast: DateTime::now(),
            last_greetings: DateTime::never(),
            last_ping: DateTime::never(),
        }
    }

    /// Welcomes a new neighbour, and adds it to the potential neighbours map.
    /// `addr` is the address of the neighbour.
    /// `authorized` indicates whether the neighbour has been explictly invited (either
    ///  by the user who started the program, or by an invited neighbour).
    /// Returns a `Some` value containing a long-lasting reference to the address of the
    /// neighbour if it is authorized to join the neighbourhood, and `None` otherwise.
    /// # Note:
    /// If [`ALLOW_SELF_INVITATION`] is true, the argument `authorized` is ignored and
    /// this function only returns `None` if the neighbour has been explicitly blocked.
    fn welcome(&mut self, addr: Addr, authorized: bool) -> Option<&'arena Addr> {
        if let Some((_, until)) = self.blocked.get(&addr) {
            if DateTime::now().millis_since(*until) <= 0 {
                return None;
            }
        }

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

    /// Adds a neighbour to the active neighbours map and updates the date of its
    /// last activity (i.e. its last short hello).
    /// An `ActiveNeighbour` object is created if the neighbour was not previously active.
    /// # Returns
    /// A tuple with two items. The boolean is `true` if the neighbour was not active until now.
    /// The second element is a reference to the `ActiveNeighbour` object associated to the neighbour.
    fn mark_active(
        &mut self,
        addr: &'arena Addr,
        id: PeerID,
    ) -> (bool, &Rc<RefCell<ActiveNeighbour<'arena>>>) {
        let neighbour = self.tva.entry(addr);
        let new = neighbour.is_vacant();

        let neighbour =
            neighbour.or_insert_with(|| Rc::new(RefCell::new(ActiveNeighbour::new(id, addr))));
        neighbour.borrow_mut().last_hello = DateTime::now();
        (new, neighbour)
    }

    /// Returns the number of symmetric neighbours in the neighbourhood.
    fn count_symmetrics(&self) -> usize {
        self.fold(
            0,
            |_, n, c| if n.borrow().is_symmetric() { c + 1 } else { c },
        )
    }

    /// Indicates whether a neighbour is currently symmetric.
    fn is_symmetric(&self, addr: &Addr) -> bool {
        self.tva
            .get(addr)
            .is_some_and(|n| n.borrow().is_symmetric())
    }

    /// Convenience method to create a "GoAway" TLV with the specified `reason` and `msg`.
    fn create_go_away_tlv(reason: GoAwayReason, msg: Option<String>) -> TagLengthValue {
        TagLengthValue::GoAway(reason, msg.map(LimitedString::try_from))
    }

    /// Dismisses all the neighbours contained in the array `who`.
    /// The neighbours are removed from the active neighbour map, but are kept from
    /// the potential neighbour map.
    /// A "GoAway" TLV with the given `reason` and `msg` is sent to all the dismissed
    /// neighbours.
    fn dismiss(&mut self, who: &[&'arena Addr], reason: GoAwayReason, msg: Option<String>) {
        let msg = Rc::new(NeighbourHood::create_go_away_tlv(reason, msg));

        for addr in who {
            log_info!(self.socket, "Neighbour {0} is now inactive.", addr);
            self.tva.remove(addr);
            self.socket.send_single_tlv(addr, Rc::clone(&msg));
        }
    }

    /// Blocks the neighbour for the specified duration, preventing it from sending
    /// messages. This neighbour will no longer receive "pings" while it is blocked.
    /// A "GoAway" TLV with code "ProtocolViolation" and the specified message is also
    /// sent to the neighbour.
    ///
    /// If the neighbour has already been blocked recently, the duration is increased
    /// in order to punish spamming more severely.
    /// The function used to increase the duration is unspecified (see the implementation).
    fn block(&mut self, who: &'arena Addr, mut duration: Duration, msg: Option<String>) {
        let mut count = 1; // Number of unpardoned blockings

        if let Some((mut c, unblocked)) = self.blocked.get(who) {
            let unblocked_for = DateTime::now().millis_since(*unblocked);
            if unblocked_for > 0 {
                // Pardon 1 blocking per 20 seconds once the neighbour is unblocked (arbitrary)
                let pardon_count = unblocked_for / 20_000;
                if pardon_count <= c.into() {
                    c -= pardon_count as u32; // cannot overflow
                }
            }
            count = c + 1;
            // Exponential function
            duration = duration.checked_mul(Duration::from_millis(1i64 << std::cmp::min(62, c)));
        }

        let new_unblock = DateTime::now().checked_add(duration);

        self.blocked.insert(who, (count, new_unblock));
        self.dismiss(&[who], GoAwayReason::ProtocolViolation, msg);

        log_important!(
            self.socket,
            "Neighbour {} blocked until {} because of protocol violations.",
            who,
            new_unblock.formatted()
        );
    }

    /// Indicates whether it is timely to greet (i.e. say hello) to the
    /// active neighbours.
    fn should_greet(&self) -> bool {
        DateTime::now().millis_since(self.last_greetings) > HELLO_INTERVAL
    }

    /// Says hello to all the active neighbours.
    /// ### Side effect:
    /// This functions dismisses the neighbours that have not said hello for a long time,
    /// and sends them a "GoAway" TLV with code "Inactivity".
    fn greet_all(&mut self, id: PeerID) {
        let mut inactives = vec![];

        for (addr, neighbour) in &self.tva {
            if neighbour.borrow().say_hello(id, self.socket).is_err() {
                inactives.push(*addr);
            }
        }
        self.last_greetings = DateTime::now();

        self.dismiss(
            &inactives,
            GoAwayReason::Inactivity,
            Some("You have been idle for too long.".to_owned()),
        );
    }

    /// Indicates whether it is timely to broadcast the list of the symmetric neighbours
    /// to all the active neighbours.
    fn should_broadcast(&self) -> bool {
        DateTime::now().millis_since(self.last_broadcast) > NEIGHBOURHOOD_BROADCAST_INTERVAL
    }

    /// Broadcasts the list of the symmetric neighbours
    /// to all the active neighbours.
    /// This function does not check for inactivity.
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
        self.last_broadcast = DateTime::now();
    }

    /// Indicates whether it is timely and relevant to look for new friends by pinging
    /// all the potential (and non-symmetric) neighbours.
    fn should_ping(&self) -> bool {
        self.count_symmetrics() < MIN_DESIRED_SYMMETRIC
            && DateTime::now().millis_since(self.last_ping) > MIN_PING_INTERVAL
    }

    /// Looks for new friends by sending a Hello TLV to all the potential
    /// (and non-symmetric) neighbours.
    fn ping(&mut self, local_id: PeerID) {
        let tlv = Rc::new(TagLengthValue::Hello(local_id, None));

        for addr in &self.tvp {
            if !self.is_symmetric(addr) && !self.blocked.contains_key(addr) {
                self.socket.send_single_tlv(addr, Rc::clone(&tlv));
            }
        }
        self.last_ping = DateTime::now();
    }

    /// Acknoledges receipt of a message. An "Ack" TLV is sent to all the symmetric
    /// neighbours.
    fn acknoledge(&self, msg_id: MessageId) {
        let tlv = Rc::new(TagLengthValue::Ack(msg_id));
        self.for_each(|addr, neighbour| {
            if neighbour.borrow().is_symmetric() {
                self.socket.send_single_tlv(addr, Rc::clone(&tlv));
            }
        });
    }

    /// Groups greetings, pinging and neighbourhood broadcast as a
    /// single "routine" task.
    /// This method should be called very often.
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

    /// Folds every active neighbour into an accumulator by applying an
    /// operation. This function returns the final result.
    /// The closure should take as arguments the reference to the address of the neighbour,
    /// a reference to the `ActiveNeighbour` object associated to the neighbour, and an
    /// "accumulator". The order in which the active neighbours are yielded is unspecified.
    /// This function returns the last value returned by the closure.
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

    /// Calls a closure on all the active neighbours, in an unspecified order.
    /// The closure should take as arguments the reference to the address of the neighbour
    /// and a reference to the `ActiveNeighbour` object associated to the neighbour.
    fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&'arena Addr, &Rc<RefCell<ActiveNeighbour<'arena>>>),
    {
        self.fold((), |addr, neighbour, ()| f(addr, neighbour));
    }
}

/* #endregion */

/* #region DeliveryStatus */

/// This structure stores information about the status of the
/// delivery of a determined datum to a neighbour.
/// This structure does not store information about the datum in question,
/// but one `DeliveryStatus` should be used with one and only one datum.
struct DeliveryStatus<'arena> {
    /// Weak reference to the `ActiveNeighbour` object associated with this neighbour.
    /// If the neighbour is marked as inactive and removed from the active neighbours
    /// map before it has acknoledged receipt of the datum,
    /// the weak reference is expected to become invalid, allowing to stop the delivery
    /// without querying the map.
    neighbour: Weak<RefCell<ActiveNeighbour<'arena>>>,
    flooding_times: u8,
    last_flooding: DateTime,
    next_flooding_delay: MillisType,
}

impl<'arena> DeliveryStatus<'arena> {
    /// Creates a new `DeliveryStatus` object.
    /// `time` is the time the datum was received.
    /// Giving it as a parameter reduces the number of calls
    /// to [`datetime::now`].
    /// `neighbour` is the neighbour that will be associated with this
    /// delivery status.
    /// `rng` is a reference to a random number generator.
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

    /// Indicates whether it is timely to undertake a new delivery attempt to this neighbour.
    fn should_flood(&self) -> bool {
        DateTime::now().millis_since(self.last_flooding) > self.next_flooding_delay
    }

    /// Sends the datum to this neighbour and updates the delivery status.
    /// `msg` is the precomputed byte representation of the "Data" TLV (not only
    /// the UTF-8 message from the user).
    /// The same datum should be given at each call.
    /// This methods also needs a random number generator and a reference to the socket
    /// used to send the messages (the object stores no reference of it).
    /// # Errors
    /// If the associated neighbour is inactive, or has not acknoledged receipt of the message
    /// after [`MAX_FLOODING_TIMES`] attempts, this function sends nothing and returns
    /// `Err(NeighbourInactive)`.
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

    /// Updates this delivery status by incrementing the number of attempts
    /// and choosing the time of the next attempt.
    /// Internal use only (should be called only by `flood`).
    fn flooded(&mut self, rng: &mut StdRng) {
        self.flooding_times += 1;
        self.last_flooding = DateTime::now();
        self.next_flooding_delay = self.random_flooding_delay(rng);
    }

    /// Chooses a random delay for the next delivery attempt.
    /// Internal use only.
    fn random_flooding_delay(&self, rng: &mut StdRng) -> MillisType {
        if self.flooding_times == 0 {
            rng.gen_range(500..1000)
        } else {
            rng.gen_range(
                (1000 * (1 << (self.flooding_times - 1)))..(1000 * (1 << self.flooding_times)),
            )
        }
    }

    /// Indicates whether the delivery of the datum to this neighbour should be given up
    /// due to inactivity.
    fn should_give_up_flooding(&self) -> bool {
        self.flooding_times > MAX_FLOODING_TIMES || self.neighbour.upgrade().is_none()
    }

    /// Get a reference to the address of the neighbour, if it is still active.
    /// Returns `None` if the neighbour has been removed from the active neighbours map.
    fn get_neighbour_addr(&self) -> Option<&'arena Addr> {
        self.neighbour.upgrade().map(|n| n.borrow().addr)
    }
}

/* #endregion */

/* #region RecentDatum */

/// This structure stores informations about a recent datum.
struct RecentDatum<'arena> {
    msg_id: MessageId,
    precomputed: Rc<[u8]>,
    receive_time: DateTime,
    neighbours_to_flood: HashMap<&'arena Addr, DeliveryStatus<'arena>>,
    socket: &'arena MircHost<'arena>,
}

impl<'arena> RecentDatum<'arena> {
    /// Creates a new `RecentData` object for the `data` with ID `msg_id`.
    /// The neighbours to flood are initialized with the list of the symmetric
    /// neighbours from the `neighbours` argument.
    fn new(
        msg_id: MessageId,
        data: Data,
        neighbours: &NeighbourHood<'arena>,
        rng: &mut StdRng,
        socket: &'arena MircHost<'arena>,
    ) -> Self {
        let date_now = DateTime::now();

        let mut neighbours_to_flood = HashMap::new();
        neighbours.for_each(|addr, neighbour| {
            if neighbour.borrow().is_symmetric() {
                neighbours_to_flood.insert(addr, DeliveryStatus::new(date_now, neighbour, rng));
            }
        });

        let precomputed = Rc::from(
            TagLengthValue::Data(msg_id, data)
                .try_to_bytes()
                .unwrap_or_default(),
        );

        Self {
            msg_id,
            precomputed,
            neighbours_to_flood,
            receive_time: date_now,
            socket,
        }
    }

    /// Processes an acknoledgment of this message from the specified neighbour.
    /// The neighbour is removed from the list of the neighbours to flood.
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

    /// Indicates whether the message has been delivered to all the expected
    /// neighbours (expected those who became inactive).
    fn flooding_complete(&self) -> bool {
        self.neighbours_to_flood.is_empty()
    }

    /// Sends the message to all the neighbours that have not acknoledged receipt yet.
    /// The neighbours who became inactive are automatically removed.
    /// This function returns the list of the neighbours who have been removed from the queue
    /// for inactivity.
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

/* #region RecentDataMap */

/// This structure contains all the recent data.
/// It is also responsible for processing the messages that the local
/// user wants to send.
struct RecentDataMap<'arena> {
    nickname: Option<NickName>,
    neighbourhood: Rc<RefCell<NeighbourHood<'arena>>>,
    next_msg_id: u32,
    stream: Receiver<String>,
    recent_data: QueuedMap<MessageId, RecentDatum<'arena>>,
    socket: &'arena MircHost<'arena>,
}

impl<'arena> RecentDataMap<'arena> {
    /// Creates a new `RecentDataMap` for the given `neighbourhood`.
    ///
    /// If `nickname` is not `None`, the string `nickname: ` will be added
    /// at the beginning of all `Data` messages written by the user.
    /// `stream` is the receiver-side of a thread-safe channel.
    /// The messages should only be written to the sender-side of the same
    /// channel.
    /// This system is used instead of exposing functions like `read_stream` or
    /// `insert_data`, because most of the objects of the API are not
    /// thread-safe, and wrapping all of them inside thread-safe lockers would
    /// cause unnecessary overhead.
    fn new(
        nickname: Option<NickName>,
        neighbourhood: Rc<RefCell<NeighbourHood<'arena>>>,
        stream: Receiver<String>,
        socket: &'arena MircHost<'arena>,
    ) -> Self {
        Self {
            nickname,
            neighbourhood,
            next_msg_id: 0,
            stream,
            recent_data: QueuedMap::new(),
            socket,
        }
    }

    /// Insert a recent datum in the map.
    /// The neighbours to flood are initialized with the symmetric neighours from
    /// the (store) neighbourhood.
    /// This function returns `true` if the message was NOT previously in the map.
    ///
    /// Note that nothing is actually sent through the socket until the `flood_all`
    /// function is called.
    fn insert_data(&mut self, msg_id: MessageId, data: Data, rng: &mut StdRng) -> bool {
        let data = RecentDatum::new(msg_id, data, &self.neighbourhood.borrow(), rng, self.socket);
        if data.neighbours_to_flood.is_empty() {
            log_important!(self.socket, "There is nobody to send your message to...");
        }
        self.recent_data.try_insert(msg_id, data)
    }

    /// Reads the stream and prepares the delivery of the transmitted messages.
    /// If a message is too large to fit in a single TLV, it is automaticaly
    /// split into multiple TLVs.
    ///
    /// Note that nothing is actually sent through the socket until the `flood_all`
    /// function is called.
    fn read_stream(&mut self, local_id: PeerID, rng: &mut StdRng) {
        if let Ok(data_str) = self.stream.try_recv() {
            let header = self.nickname.as_ref().map(|str| str.to_string() + ": ");
            let data_vec = Data::pack(header, data_str.trim());

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

    /// Sends all the messages to the neighbours who have not acknoledged receipt of them yet.
    /// Data whose delivery is complete are automatically removed from the map.
    /// The neighbours who have not acknoledged receipt of a message after [`MAX_FLOODING_TIMES`]
    /// delivery attempts are automatically dismissed. A "GoAway" TLV with code Inactivity is sent to
    /// them.
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

    /// Processes an acknoledgment of this message from the specified neighbour.
    /// The neighbour is removed from the list of the neighbours to flood for the
    /// specified message.
    /// This method essentially calls `process_ack` function of `RecentData`
    /// and exists only for convenience and syntactic conciseness.
    ///
    /// Note: if the specified datum is not a recent datum, or the message is not
    /// expecting an acknoledgment from the specified neighbour, this function has
    /// no effect.
    fn process_ack(&mut self, from: &Addr, msg_id: &MessageId) {
        if let Some(data) = self.recent_data.get_mut(msg_id) {
            data.process_ack(from);
        }
    }

    /// Cleans the map such that, when this function returns,
    /// it has at most [`MAX_RECENT_DATA_COUNT`] (\*) items and
    /// contains only data younger than [`MAX_RECENT_DATA_AGE`] (\*).
    /// The data removed have their flooding given up.
    ///
    /// (*) only if those parameters are non-null.
    fn clean(&mut self) {
        while MAX_RECENT_DATA_COUNT > 0 && self.recent_data.len() > MAX_RECENT_DATA_COUNT {
            self.recent_data.pop_oldest();
        }

        if MAX_RECENT_DATA_AGE > 0 {
            let socket = self.socket; // Local binding to avoid using self in closure
            self.recent_data.retain(|msg_id, d| {
                if DateTime::now().millis_since(d.receive_time) <= MAX_RECENT_DATA_AGE {
                    true
                } else {
                    log_warning!(
                        socket,
                        "Given up flooding message {msg_id} because it was received too long ago."
                    );
                    false
                }
            });
        }
    }
}

/* #endregion */

/// Adds a convenience method to some errors.
trait RemoteError {
    /// This is true if the error should not be considered
    /// as an actual anomaly.
    /// This is used only to choose the appropriate verbose level
    /// when logging errors.
    fn is_remote_fault(&self) -> bool;
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

/// Executes the fallible operation given as the second
/// argument, and logs the error using the logger given as
/// the first argument if the operation returns an `Err` result.
/// The error type should implement `RemoteError`.
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
    /// Tries to create a new `MircHost` by binding a new `UdpSocket` to
    /// the specified port.
    /// This function also needs a logger, borrowed for all the life
    /// of the new object.
    /// # Errors
    /// This functions returns an `Ok` result containing the new object if
    /// the binding succeeds. Otherwise it returns an `Err` result containing the
    /// [`std::io::Error`] that has occurred when trying to bind the socket.
    pub fn new(port: u16, logger: &'arena EventLog) -> std::io::Result<Self> {
        let addr = Addr::try_from(("::", port))
            .map_err(|_err| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))?;

        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        // Failure to set IPV6_ONLY should not be a fatal error.
        report_on_fail!(logger, socket.set_only_v6(IPV6_ONLY));
        socket.bind(&SocketAddr::from(addr).into())?;
        socket.set_nonblocking(true)?;

        let socket: UdpSocket = socket.into();
        let local_addr: Addr = socket.local_addr()?.into();

        Ok(Self {
            socket,
            local_addr,
            buffer: RefCell::new(HashMap::new()),
            auto_flush: true,
            logger,
        })
    }

    /// Flushes the message queue for the specified neighbour, provided auto flushing is
    /// enabled and the queue is full enough. "Full enough" means full enough to fill
    /// a whole UDP datagram without leaving blanks.
    /// Internal use only. See `flood_all` instead.
    fn flush_if_appropriate(&self, to: &Addr, queue: &mut MessageFactory) {
        if self.auto_flush && queue.should_flush() {
            self.flush(to, queue);
        }
    }

    /// Forces to flush the message queue for the specified neighbour, causing
    /// all the queued messages to be immediately sent through the UDP socket.
    /// I/O errors that may occur during the process are logged by the logger.
    /// Internal use only. See `flood_all` instead.
    fn flush(&self, to: &Addr, queue: &mut MessageFactory) {
        while let Some(msg) = queue.build_next() {
            log_debug!(self, "Sending bytes to {to}: {msg:?}");
            report_on_fail!(self.logger, self.socket.send_to(&msg, to));
        }
    }

    /// Forces to flush the buffer for all the neighbours, causing all the messages
    /// to be immediately sent to the neighbours.
    /// This method should be called regularly, even if auto-flushing is enabled, because
    /// the buffer may not reach the minimum size for auto-flushing in a reasonable delay.
    fn flush_all(&self) {
        for (addr, queue) in &mut *self.buffer.borrow_mut() {
            self.flush(addr, queue);
        }
    }

    /// Calls the closure on the message queue associated with the specified neighbour.
    /// Internal use only. Wrong usage may cause dead locks because this function mutably
    /// borrows the buffer, and the buffer is still mutably borrowed when the closure is called.
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

    /// Receives a message sent by an invited neighbour (if any), or
    /// returns the parse error.
    /// `neighbours` will be used to check whether the sender is invited.
    fn receive_message(
        &self,
        neighbours: &Rc<RefCell<NeighbourHood<'arena>>>,
    ) -> ParseResult<(&'arena Addr, Vec<TagLengthValue>)> {
        let mut buf = [0; 1024];
        let (size, addr) = self.socket.recv_from(&mut buf)?;

        let addr: Addr = addr.into();
        let addr = neighbours
            .borrow_mut()
            .welcome(addr.clone(), false)
            .ok_or(ParseError::UnknownSender(addr))?;

        log_debug!(self, "Received bytes from {addr}: {0:?}", &buf[0..size]);

        let mut buffer = Buffer::new(&buf[0..size]);
        Ok((
            addr,
            MessageParser::try_parse(&mut buffer)
                .map_err(|kind| ParseError::ProtocolViolation(addr.clone(), kind))?,
        ))
    }
}

/* #endregion */

/* #region LocalUser */

/// This structure represents the local user of this local
/// instance of the program
pub(super) struct LocalUser<'arena> {
    id: PeerID,
    socket: &'arena MircHost<'arena>,
    neighbours: Rc<RefCell<NeighbourHood<'arena>>>,
    data: RecentDataMap<'arena>,
    rng: rand::rngs::StdRng,
    logger: &'arena EventLog,
}

impl<'arena> LocalUser<'arena> {
    /// Creates a new `LocalUser` object.
    /// - `nickname` (optional) will be added before all the `Data` messages
    /// written by the user. A long nickname may increase the need for splitting
    /// messages.
    /// - `first_neighbour` is the address of the first neighbour to contact
    /// - `alloc` is the allocator that will be used for hash consing
    /// - `receiver` is the receiver-side of a thread-safe channel.
    /// The messages that the local user wants to send should be passed to
    /// the sender-side of the same channel.
    pub fn new(
        nickname: Option<NickName>,
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

        let data = RecentDataMap::new(nickname, Rc::clone(&neighbours), receiver, socket);

        Self {
            id,
            socket,
            neighbours,
            data,
            rng,
            logger: socket.logger,
        }
    }

    /// Sends a warning to the neighbour, with the specified message.
    /// The byte size of the message must not exceed 255, otherwise an
    /// error is logged by the logger.
    fn warn(&self, addr: &'arena Addr, msg: String) {
        let msg = LimitedString::try_from(msg);
        let tlv = Rc::new(TagLengthValue::Warning(msg));
        self.socket.send_single_tlv(addr, Rc::clone(&tlv));
    }

    /// Shows a new datum to the user. This function behaves differently depending
    /// on whether or not the datum is a UTF-8 byte sequence.
    fn report_new_data(&self, sender: &'arena Addr, msg_id: MessageId, data: &Data) {
        if let Some(str) = data.to_string() {
            log_info!(
                self,
                "Received new data (id: {0}) from {1}: {2}",
                &msg_id,
                sender,
                str
            );
            self.logger.print(format!("\x1b[1;36m{str}\x1b[0m\n"));
        } else {
            log_info!(
                self,
                "Received non-UTF-8 data (id: {0} from {1}: {2:?}",
                &msg_id,
                sender,
                data.as_bytes(),
            );
        }
    }

    /// Processes a single TLV from a received datagram.
    /// `sender` is the address of the peer that sent the datagram.
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
                    //symmetric
                    let mut neighbour = neighbour.borrow_mut();
                    neighbour.last_long_hello = neighbour.last_hello;
                }
            }

            TagLengthValue::Neighbour(addr) => {
                if addr != self.socket.local_addr {
                    self.neighbours.borrow_mut().welcome(addr, true);
                }
            }

            TagLengthValue::Data(msg_id, data) => {
                // Only data sent from symmetric neighbours are accepted
                if self.neighbours.borrow().is_symmetric(sender) {
                    if self.data.insert_data(msg_id, data.clone(), &mut self.rng) {
                        // `insert_data` returns true if it is a new datum
                        self.report_new_data(sender, msg_id, &data);
                    }
                    self.data.process_ack(sender, &msg_id);
                    self.neighbours.borrow().acknoledge(msg_id);
                } else {
                    self.neighbours.borrow_mut().block(
                        sender,
                        Duration::from_millis(500),
                        Some(
                            "Please say hello before \
                            flooding data. Your message has been ignored"
                                .to_owned(),
                        ),
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
                self.neighbours.borrow_mut().tva.remove(sender);

                if let Some(Err(err)) = msg {
                    log_anomaly!(
                        self,
                        "Failed to parse 'GoAway' user-friendly message:\n{err}"
                    );
                }
            }

            TagLengthValue::Warning(msg) => {
                if let Ok(msg) = msg {
                    log_warning!(self, "Warning sent from {sender}: {msg}");
                } else {
                    self.warn(
                        sender,
                        "Warnings should contain a UTF-8 message.".to_owned(),
                    );
                    log_warning!(
                        self,
                        "Warning sent from {sender} with an invalid UTF-8 message."
                    );
                }
            }

            TagLengthValue::Unrecognized(tag) => {
                self.warn(sender, format!("Unrecognized tag {tag} was ignored."));
                log_anomaly!(self, "Unrecognized tag {tag} received from {sender}");
            }

            _ => {}
        }
    }

    /// Groups all the steps of the protocol in a single routine task.
    /// The steps are:
    /// - updating the state of the neighbours, saying hello etc.
    /// - looking for messages from the local user and preparing their flooding
    /// - flooding all data to flood (and flush the socket's buffer)
    /// - looking for messages from remote neighbours
    pub fn routine(&mut self) {
        self.neighbours.borrow_mut().routine(self.id);

        self.data.read_stream(self.id, &mut self.rng);
        self.data.flood_all(&mut self.rng);
        self.data.clean();

        self.socket.flush_all();

        // If there are too many messages to receive, the rest will wait.
        // The other routine steps should not stay blocked for too long.
        for _ in 0u8..10u8 {
            match self.receive_message() {
                Ok(()) => (),
                Err(ParseError::ReceiveFailed(err))
                    if err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    break
                }
                Err(ParseError::ReceiveFailed(err)) if err.is_remote_fault() => {
                    self.logger.debug(err);
                }
                Err(ParseError::ReceiveFailed(err)) => self.logger.information(err),
                Err(ParseError::ProtocolViolation(from, kind)) => {
                    self.logger
                        .anomaly(ParseError::ProtocolViolation(from.clone(), kind));
                    let mut neighbours = self.neighbours.borrow_mut();
                    if let Some(addr) = neighbours.welcome(from, false) {
                        neighbours.block(
                            addr,
                            Duration::from_millis(500),
                            Some("I can break rules, too.".to_owned()),
                        );
                    }
                }
                Err(ParseError::UnknownSender(addr)) => {
                    self.logger.anomaly(ParseError::UnknownSender(addr));
                }
            }
        }
    }

    /// Tries to receive a single datagram from the socket.
    /// The received datagram (if any) is then processed.
    /// When this method returns, more datagrams may still be
    /// waiting for being processed.
    /// # Errors
    /// This method returns an Err value if
    /// - no datagram has been received,
    /// - the received datagram could not be parsed.
    fn receive_message(&mut self) -> ParseResult<()> {
        let (addr, msg) = self.socket.receive_message(&self.neighbours)?;

        for tlv in msg {
            log_trace!(self, "Received TLV from {0}: {1:?}", addr, &tlv);
            self.process_tlv(addr, tlv);
        }
        Ok(())
    }

    /// Notifies all the active neighbours that this user is leaving.
    /// (Sends a "GoAway" TLV with code "EmitterLeaving", and flushes the socket's buffer).
    ///
    /// Note: this function does nothing else. This object may still be used until
    /// it is dropped.
    pub fn shutdown(&self) {
        log_important!(self, "Shutting down...");
        let tlv = Rc::new(NeighbourHood::create_go_away_tlv(
            GoAwayReason::EmitterLeaving,
            Some("Good bye!".to_owned()),
        ));
        self.neighbours.borrow_mut().for_each(|addr, _| {
            self.socket.send_single_tlv(addr, Rc::clone(&tlv));
        });
        self.socket.flush_all();
    }
}

/* #endregion LocalUser */
