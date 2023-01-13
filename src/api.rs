use std::{convert::TryFrom, sync::Arc, time::Duration};

use crossbeam::channel::{self, Sender};

use self::{
    addresses::Addr,
    error::UseClientError,
    lib::{LocalUser, MircHost},
    logging::{EventLog, VerboseLevel},
};

pub mod addresses;
mod datetime;
pub mod error;
pub mod lib;
pub mod logging;
mod parse;
mod sync;
mod util;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum UseClientStatus {
    #[default]
    Initializing,
    Ready,
}

pub fn use_client<F, R>(
    port: u16,
    first_neighbour: &str,
    verbose: VerboseLevel,
    f: F,
) -> Result<R, UseClientError>
where
    F: for<'arena> FnOnce(Sender<String>, Arc<EventLog>) -> R,
{
    crossbeam::scope(|s| {
        let logger = Arc::new(EventLog::new(verbose));
        let logger_th = Arc::clone(&logger);

        let (sender, receiver) = channel::unbounded();

        let handle = sync::spawn_control(s, move |this| {
            let neighbour = Addr::try_from(first_neighbour)
                .map_err(|_err| UseClientError::InvalidNeighbourAddress)?;

            let alloc = bumpalo::Bump::new();
            let socket = MircHost::new(port, &logger_th)?;

            let mut client = LocalUser::new(neighbour, &alloc, &socket, receiver);

            this.set_user_status(UseClientStatus::Ready).unwrap();

            while this.should_run() {
                client.routine();
                std::thread::sleep(Duration::from_millis(50));
            }
            client.shutdown();
            Ok(())
        });

        while handle.is_running() && handle.get_user_status() == UseClientStatus::Initializing {
            std::thread::sleep(Duration::from_millis(50));
        }
        if !handle.is_running() || handle.get_user_status() != UseClientStatus::Ready {
            handle.interrupt();
            return Err(handle.join().unwrap().unwrap_err());
        }

        let result = f(sender, logger);
        handle.interrupt();
        handle.join().unwrap().unwrap();
        Ok(result)
    })
    .map_err(UseClientError::from)
    .flatten()
}
