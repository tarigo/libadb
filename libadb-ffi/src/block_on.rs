use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::{Mutex, MutexGuard, TryLockError};

use libadb::base::channel::ChannelId;
use libadb::base::error::Error;

use crate::connection::{FfiReader, FfiWriter};
use crate::transport::FfiTransportError;

/// How long a parked write goes without looking at the read lock again.
/// Its holder wakes the write only by dispatching what it waits for, and
/// may just as well go back to C without.
const TICK: Duration = Duration::from_millis(10);

struct ThreadWaker {
    thread: std::thread::Thread,
    notified: AtomicBool,
}

impl ThreadWaker {
    fn wait(&self) {
        while !self.notified.swap(false, Ordering::SeqCst) {
            std::thread::park();
        }
    }

    /// [`wait`](Self::wait), but no longer than `limit`.
    fn wait_at_most(&self, limit: Duration) {
        if !self.notified.swap(false, Ordering::SeqCst) {
            std::thread::park_timeout(limit);
            self.notified.store(false, Ordering::SeqCst);
        }
    }
}

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        Self::wake_by_ref(&self)
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notified.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

/// Poll `fut` to completion on this thread, with `wait` for what each
/// poll leaves pending.
fn run<F: Future>(fut: F, wait: impl Fn(&ThreadWaker)) -> F::Output {
    let tw = Arc::new(ThreadWaker {
        thread: std::thread::current(),
        notified: AtomicBool::new(false),
    });
    let waker = Waker::from(tw.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => wait(&tw),
        }
    }
}

pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    run(fut, ThreadWaker::wait)
}

/// [`block_on`] for a future writing on channel `ch`. Nothing reads the
/// connection in the background, so a write parked for the device with
/// no read call running reads for itself, one packet at a time.
///
/// The read is never raced against the write: on USB it could not be
/// dropped without losing data. While it runs the write is not polled,
/// which is why only a write with nothing to do but wait starts one.
///
/// A failed read fails the write, which only a parked write can have
/// started, so no packet is left half sent. A frame of several packets
/// can be.
pub(crate) fn block_on_write<T>(
    reader: &Mutex<FfiReader>,
    writer: &FfiWriter,
    ch: ChannelId,
    write: impl Future<Output = Result<T, Error<FfiTransportError>>>,
) -> Result<T, Error<FfiTransportError>> {
    let mut write = pin!(write);
    let writing = poll_fn(|cx| loop {
        if let Poll::Ready(done) = write.as_mut().poll(cx) {
            return Poll::Ready(done);
        }
        // Asked under the lock: a read that returned a moment ago may
        // have taken the OKAY, and then no packet may be coming.
        let Some(mut reader) = try_lock(reader).filter(|_| writer.waits_for_credit(ch)) else {
            return Poll::Pending;
        };
        if let Err(e) = block_on(reader.dispatch_one()) {
            return Poll::Ready(Err(e));
        }
    });
    run(writing, |tw| tw.wait_at_most(TICK))
}

fn try_lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}
