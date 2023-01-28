//! This module (and its submodules) contain all the structures and functions that
//! make the MIRC client work.

use std::{convert::TryFrom, sync::Arc, time::Duration};

use crossbeam::channel::{self, Sender};

use self::{
    addresses::Addr,
    error::UseClientError,
    lib::{LocalUser, MircHost},
    logging::{EventLog, Printer, VerboseLevel}, util::LimitedString,
};

mod addresses;
mod datetime;
pub mod error;
mod lib;
pub mod logging;
mod parse;
mod util;


/// Internal use (see below).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum UseClientStatus {
    #[default]
    /// Constructing fallible structures
    Initializing,
    /// MIRC client ready for routine stuff
    Ready,
}

/// This is the main method to call in order to use the MIRC client.
/// Most of the other structures and methods are non-public intentionally.
///
/// This function takes as arguments the local UDP binding port of the client, the
/// address of the first neighbour to contact, the optional nickname of the local user,
/// a thread-safe printer that will be used to print events and messages,
/// a verbose level indicating which events should be printed, and a closure.
///
/// The closure should block the current thread until the client should be disconnected.
///
/// The MIRC client will run in the background. The closure has no direct access to it.
/// Instead, it can transmit it messages to send (by flooding) to the neighbours, using the
/// Sender object given as argument. The second argument is a reference to the logger (the same
/// as that of the MIRC client).
///
/// # Errors
/// On success, this function returns an `Ok` value containing the result of the closure.
/// It returns an error:
/// - if the socket cannot be bound to the specified UDP port,
/// - if the address of the first neighbour is invalid,
/// - if the closure panics,
/// - if the MIRC client panics (unlikely)
pub fn use_client<F, R>(    
    port: u16,
    first_neighbour: &str,
    nickname: Option<String>,
    printer: impl Printer + Send + 'static,
    verbose: VerboseLevel,
    f: F,
) -> Result<R, UseClientError>
where
    F: FnOnce(Sender<String>, Arc<EventLog>) -> R,
{
    crossbeam::scope(|s| {
        let logger = Arc::new(EventLog::new(printer, verbose));
        let logger_th = Arc::clone(&logger);

        let (sender, receiver) = channel::unbounded();

        let handle = crate::sync::spawn_control(s, move |this| {
            let neighbour = Addr::try_from(first_neighbour)
                .map_err(|_err| UseClientError::InvalidNeighbourAddress)?;

            let alloc = bumpalo::Bump::new();
            let socket = MircHost::new(port, &logger_th)?;

            let nickname = if let Some(n) = nickname {
                Some(LimitedString::try_from(n).map_err(|_err| UseClientError::NicknameTooLong)?)
            } else {
                None
            };

            let mut client = LocalUser::new(nickname, neighbour, &alloc, &socket, receiver);

            // The parent thread should wait until this thread reaches this line to
            // call the closure. (Previous statements may fail.)
            this.set_user_status(UseClientStatus::Ready).unwrap();

            while this.should_run() {
                client.routine();
                std::thread::sleep(Duration::from_millis(50));
            }
            client.shutdown(); // Tells the neighbours to go away.
            Ok(())
        });

        while handle.is_running() && handle.get_user_status() == UseClientStatus::Initializing {
            std::thread::sleep(Duration::from_millis(50));
        }
        if !handle.is_running() || handle.get_user_status() != UseClientStatus::Ready {
            handle.interrupt();
            // If unwrap panics, this means that the child thread has panicked as well.
            // The panick will be catched by crossbeam's scope and will be retrieved later

            // `unwrap_err` may not panic, because the only way for the thread not to
            // return an `Err` result at this point is to panic (and if the first `unwrap`
            // succeeds, the thread cannot have panicked).
            return Err(handle.join().unwrap().unwrap_err());
        }

        let result = f(sender, logger);
        handle.interrupt();
        // Same reason for using unchecked `unwrap`s.
        handle.join().unwrap().unwrap();
        Ok(result)
    })
    .map_err(UseClientError::from)
    .flatten()
}
