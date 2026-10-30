//! Receiving from an `async_channel` through its `Stream` impl.
//!
//! `Receiver::recv()` builds a fresh `EventListener` (one `Box`) on every
//! pending poll, so a `select!` loop pays one heap alloc/free per idle branch
//! per wakeup. The `Stream` impl parks its listener inside the `Receiver`
//! and reuses it, at the price of `&mut` access and of pinning the
//! `Receiver` (it is `!Unpin`) once, outside the loop.

use async_channel::{Receiver, RecvError};
use core::future::{poll_fn, Future};
use core::pin::Pin;
use futures_core::Stream;

/// Same output as `rx.recv()`, without re-creating the listener each poll.
pub fn recv_next<T>(mut rx: Pin<&mut Receiver<T>>) -> impl Future<Output = Result<T, RecvError>> + '_ {
    poll_fn(move |cx| rx.as_mut().poll_next(cx).map(|o| o.ok_or(RecvError)))
}
