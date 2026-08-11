use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

struct ThreadWaker {
    thread: std::thread::Thread,
    notified: AtomicBool,
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

pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
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
            Poll::Pending => {
                while !tw.notified.swap(false, Ordering::SeqCst) {
                    std::thread::park();
                }
            }
        }
    }
}
