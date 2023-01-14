//! This module contains an implementation of a "high-level" thread.

use std::{
    panic::UnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
};

use crossbeam::thread::{Scope, ScopedJoinHandle};

/// A structure that can be used to control and join the spawned thread.
/// Additionnaly, the child thread can share an "user status" (provided `S` implement
/// `Copy` and `Default` traits.)
pub struct ControlScopeJoinHandle<'scope, T, S> {
    raw: ScopedJoinHandle<'scope, T>,
    should_run: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    status: Arc<Mutex<S>>,
}

impl<'scope, T, S> ControlScopeJoinHandle<'scope, T, S> {
    /// Tells whether the thread is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    /// Asks the thread to interrupt. This only sets a bool flag that
    /// the closure used to spawn the thread should regularly check.
    pub fn interrupt(&self) {
        self.should_run.store(false, Ordering::SeqCst);
    }
    /// Waits for the thread to finish and return its result.
    /// If the child thread panics, an error is returned.
    pub fn join(self) -> std::thread::Result<T> {
        self.raw.join()
    }
}
impl<'scope, T, S: Default + Copy> ControlScopeJoinHandle<'scope, T, S> {
    /// Get the current status of the thread.
    /// This status must be set by the closure used to spawn the thread.
    /// If the closure has not set a status yet, the default value of the type
    /// is returned.
    pub fn get_user_status(&self) -> S {
        if let Ok(status) = self.status.lock() {
            *status
        } else {
            S::default()
        }
    }
}

/// A structure that can be used by the *child* thread to
/// check whether it should continue to run and, optionally, to
/// communicate a custom status to the parent thread.
pub struct ControlThread<S> {
    running: Arc<AtomicBool>,
    should_run: Arc<AtomicBool>,
    status: Arc<Mutex<S>>,
}

impl<S> ControlThread<S> {
    /// Indicates whether the thread should continue to run.
    /// This flag turns to `false` after the parent thread called `interrupt` on
    /// the join handle.
    pub fn should_run(&self) -> bool {
        self.should_run.load(Ordering::SeqCst)
    }
    /// Sets a custom user status that the parent thread may check.
    pub fn set_user_status(&self, status: S) -> Result<(), PoisonError<MutexGuard<S>>> {
        self.status.lock().map(|mut s| *s = status)
    }
}

/// Spawns a controllable, scoped thread.
/// `scope` is the value obtained by [`crossbeam::scope`].
/// `f` is a closure that takes a `ControlThread` object.
pub fn spawn_control<'env, 'scope, F, T, S>(
    scope: &'scope Scope<'env>,
    f: F,
) -> ControlScopeJoinHandle<'scope, T, S>
where
    F: FnOnce(&ControlThread<S>) -> T + Send + UnwindSafe + 'env,
    T: Send + 'env,
    S: Send + Copy + Default + 'env,
{
    let should_run = Arc::new(AtomicBool::new(true));
    let running = Arc::new(AtomicBool::new(true));
    let status = Arc::new(Mutex::new(S::default()));

    let control_thread = ControlThread {
        running: Arc::clone(&running),
        should_run: Arc::clone(&should_run),
        status: Arc::clone(&status),
    };

    let handle = scope.spawn(move |_| {
        let r = std::panic::catch_unwind(|| f(&control_thread));
        control_thread.running.store(false, Ordering::SeqCst);

        match r {
            Ok(result) => result,
            Err(err) => panic!("{:?}", err),
        }
    });

    ControlScopeJoinHandle {
        raw: handle,
        running,
        should_run,
        status,
    }
}
