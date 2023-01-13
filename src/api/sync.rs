use std::{
    panic::UnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
};

use crossbeam::thread::{Scope, ScopedJoinHandle};

pub struct ControlScopeJoinHandle<'scope, T, S> {
    raw: ScopedJoinHandle<'scope, T>,
    should_run: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    status: Arc<Mutex<S>>,
}

impl<'scope, T, S> ControlScopeJoinHandle<'scope, T, S> {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    pub fn interrupt(&self) {
        self.should_run.store(false, Ordering::SeqCst);
    }
    pub fn join(self) -> std::thread::Result<T> {
        self.raw.join()
    }
}
impl<'scope, T, S: Default + Copy> ControlScopeJoinHandle<'scope, T, S> {
    pub fn get_user_status(&self) -> S {
        if let Ok(status) = self.status.lock() {
            *status
        } else {
            S::default()
        }
    }
}

pub struct ControlThread<S> {
    running: Arc<AtomicBool>,
    should_run: Arc<AtomicBool>,
    status: Arc<Mutex<S>>,
}

impl<S> ControlThread<S> {
    pub fn should_run(&self) -> bool {
        self.should_run.load(Ordering::SeqCst)
    }
    pub fn set_user_status(&self, status: S) -> Result<(), PoisonError<MutexGuard<S>>> {
        self.status.lock().map(|mut s| *s = status)
    }
}

pub fn spawn_control<'env, 'scope, F, T, S>(
    scope: &'scope Scope<'env>,
    f: F,
) -> ControlScopeJoinHandle<'scope, T, S>
where
    F: FnOnce(&ControlThread<S>) -> T + Send + UnwindSafe + 'env,
    T: Send + 'env,
    S: Send + Default + 'env,
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
