//! Shared, pooled packet buffer for tailmicro's cross-actor channels.
//!
//! Every packet that crosses an `async_channel` between `tm_derp`,
//! `tm_runtime`'s event router, `tm_wg`, `tm_disco` and `tm_netstack` is a
//! [`PktBuf`]: ONE buffer type with ONE capacity ([`PKT_CAP`]). Before this
//! crate existed each crate had its own size (1532 / 1500 / 256), so the
//! router had to copy every packet into a freshly boxed buffer of a
//! different size at each hop, and every hop was a fresh ~1.5 KB heap
//! allocation freed moments later. Those alternating alloc/free pairs were
//! fragmenting the ESP32-C3 heap (see `ALLOCATIONS.md`).
//!
//! ## The pool
//!
//! A [`PktBuf`] is a boxed buffer that, when dropped, goes back into a
//! small process-wide free list ([`POOL_N`] entries) instead of being
//! deallocated; [`PktBuf::acquire`] pops from that list and only allocates
//! when it is empty. After [`prewarm`] (called once when the WireGuard
//! endpoint is created) the packet path does no heap traffic at all as long
//! as no more than `POOL_N` packets are in flight at once. Past that it
//! falls back to exactly the old behavior (one alloc, one free, same size)
//! and counts it in [`stats`].
//!
//! ## Safety argument
//!
//! There is no `unsafe` here. A `PktBuf` owns its `Box`; Rust's move
//! semantics guarantee exactly one owner at a time, and returning the
//! buffer to the pool *is* dropping it, which happens once and only after
//! its last use. That holds across `async_channel` hops too: a message
//! that is never received, or is handed back inside a `SendError`, is
//! dropped and so recycled.
//!
//! The pool is a `std::sync::Mutex` because one producer, lwIP's netif
//! output callback (`tm_netstack`), runs on the tcpip FreeRTOS thread, not
//! on the tokio task. The lock is held only for a single push/pop inside
//! [`PktBuf::acquire`] / `Drop` (never across an `.await`, which is
//! impossible from those sync functions anyway) and nothing is allocated or
//! freed while holding it.
//!
//! `acquire` NEVER waits for a buffer to come back. Waiting could deadlock:
//! e.g. `tm_derp` blocked on a buffer while the free buffers sit in its own
//! command channel, which only it drains. Falling back to an allocation
//! keeps the pipeline deadlock-free by construction.
//!
//! Leaf crate on purpose: it depends on nothing in the workspace, so every
//! packet-carrying crate (including `tm_netstack`, which depends on no other
//! `tm_*` crate) can use it.

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Capacity of every channel-facing packet buffer.
///
/// The superset of all previous per-crate sizes: `tm_derp::MAX_DERP_PAYLOAD`
/// (1500 + 32), `tm_wg`'s 1500 and `tm_disco`'s 256.
pub const PKT_CAP: usize = 1500 + 32;

/// Number of buffers the pool keeps (~1.5 KB each, so ~6 KB held once
/// warm). Realistic steady-state in-flight count is 2-4 (one packet per
/// hop being processed plus a couple queued); bursts beyond this fall back
/// to allocation and show up in [`PoolStats::allocs`]. Tune from that
/// counter rather than guessing.
pub const POOL_N: usize = 4;

/// The storage behind a packet buffer.
pub type PktInner = heapless::Vec<u8, PKT_CAP>;

static POOL: Mutex<heapless::Vec<Box<PktInner>, POOL_N>> = Mutex::new(heapless::Vec::new());
static PREWARMED: AtomicBool = AtomicBool::new(false);
/// Buffers allocated fresh (pool empty) -- includes the pre-warm ones.
static ALLOCS: AtomicU32 = AtomicU32::new(0);
/// Buffers deallocated on drop because the pool was already full.
static FREES: AtomicU32 = AtomicU32::new(0);

fn pool() -> MutexGuard<'static, heapless::Vec<Box<PktInner>, POOL_N>> {
    // A panic while holding this lock cannot leave the Vec inconsistent
    // (push/pop only), so a poisoned lock is safe to keep using.
    POOL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Allocate an empty buffer directly on the heap.
///
/// `Box::write(Box::new_uninit(), ..)` constructs the empty `Vec` in the
/// heap allocation instead of building a ~1.5 KB temporary on the stack and
/// copying it in (this matters on lwIP's 3 KB tcpip-thread stack).
fn alloc_inner() -> Box<PktInner> {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    Box::write(Box::new_uninit(), heapless::Vec::new())
}

/// A pooled packet buffer, as moved through the inter-actor channels.
///
/// Pointer-sized (`Option<Box<_>>` uses the null niche), so channel
/// messages stay small: `async_channel`'s ring buffer reserves 31 slots per
/// block and returns each block by value, and an unboxed ~1.5 KB payload
/// there overflowed the ESP32-C3 main-task stack at `Runtime::join()`.
///
/// Derefs to [`PktInner`] (a `heapless::Vec<u8, PKT_CAP>`). Dropping it
/// returns the storage to the pool.
pub struct PktBuf(Option<Box<PktInner>>);

impl PktBuf {
    /// Take an empty buffer from the pool, allocating only if it is empty.
    /// Never blocks or waits.
    pub fn acquire() -> Self {
        let pooled = pool().pop();
        // Allocate (if needed) after the guard above is released.
        PktBuf(Some(pooled.unwrap_or_else(alloc_inner)))
    }

    /// Acquire a buffer holding a copy of `data`, or `None` if `data` is
    /// longer than [`PKT_CAP`].
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        if data.len() > PKT_CAP {
            return None;
        }
        let mut b = Self::acquire();
        // Cannot fail: length checked above and `acquire` returns empty.
        let _ = b.extend_from_slice(data);
        Some(b)
    }

    fn inner(&self) -> &PktInner {
        // Only `Drop` takes the box out.
        self.0.as_deref().expect("PktBuf used after drop")
    }

    fn inner_mut(&mut self) -> &mut PktInner {
        self.0.as_deref_mut().expect("PktBuf used after drop")
    }
}

impl Deref for PktBuf {
    type Target = PktInner;
    fn deref(&self) -> &PktInner {
        self.inner()
    }
}

impl DerefMut for PktBuf {
    fn deref_mut(&mut self) -> &mut PktInner {
        self.inner_mut()
    }
}

impl Drop for PktBuf {
    fn drop(&mut self) {
        let Some(mut b) = self.0.take() else { return };
        b.clear();
        // `push` hands the box back on a full pool; it is then freed after
        // the lock guard (a temporary of this statement) is released.
        let rejected = pool().push(b).err();
        if rejected.is_some() {
            FREES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl fmt::Debug for PktBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PktBuf({} bytes)", self.len())
    }
}

/// Fill the pool up to [`POOL_N`] buffers, once. Later calls are no-ops.
///
/// Call it early, at a moment when the heap is known to be in good shape,
/// so the buffers are carved out before per-request churn fragments the
/// heap and then simply stay allocated. Returns how many were allocated.
pub fn prewarm() -> usize {
    if PREWARMED.swap(true, Ordering::Relaxed) {
        return 0;
    }
    let want = POOL_N - pool().len();
    for _ in 0..want {
        // Acquire-free cycle: allocate, then drop into the pool.
        drop(PktBuf(Some(alloc_inner())));
    }
    want
}

/// Snapshot of pool counters, for heap-debug logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Buffers currently idle in the pool.
    pub free: usize,
    /// Total fresh allocations so far (pre-warm included). Once warm, any
    /// growth here means more than `POOL_N` packets were in flight.
    pub allocs: u32,
    /// Total buffers freed because the pool was full on return.
    pub frees: u32,
}

/// Current pool counters.
pub fn stats() -> PoolStats {
    PoolStats {
        free: pool().len(),
        allocs: ALLOCS.load(Ordering::Relaxed),
        frees: FREES.load(Ordering::Relaxed),
    }
}

// ── Unpooled API (Step 0), removed once every crate uses `PktBuf` ─────────
/// A boxed, unpooled packet buffer.
pub type PktBox = Box<PktInner>;
/// Allocate an empty unpooled [`PktBox`].
pub fn new_box() -> PktBox {
    Box::write(Box::new_uninit(), heapless::Vec::new())
}
/// Allocate an unpooled [`PktBox`] holding `data`, if it fits.
pub fn box_from_slice(data: &[u8]) -> Option<PktBox> {
    if data.len() > PKT_CAP {
        return None;
    }
    let mut b = new_box();
    let _ = b.extend_from_slice(data);
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test: the pool and counters are process-wide statics, and cargo
    // runs tests on parallel threads.
    #[test]
    fn pool_lifecycle() {
        assert_eq!(prewarm(), POOL_N);
        assert_eq!(prewarm(), 0, "prewarm is once-only");
        let s0 = stats();
        assert_eq!(s0.free, POOL_N);

        // Reuse: a dropped buffer comes back as the next acquire, cleared.
        let mut a = PktBuf::acquire();
        a.extend_from_slice(&[1, 2, 3]).unwrap();
        let p = a.as_ptr();
        drop(a);
        let b = PktBuf::acquire();
        assert_eq!(b.as_ptr(), p);
        assert!(b.is_empty());
        drop(b);
        assert_eq!(stats().allocs, s0.allocs, "no allocation while warm");

        // Exhaustion falls back to allocation; overflow on return is freed.
        let held: Vec<PktBuf> = (0..POOL_N + 2).map(|_| PktBuf::acquire()).collect();
        assert_eq!(stats().free, 0);
        assert_eq!(stats().allocs, s0.allocs + 2);
        drop(held);
        let s1 = stats();
        assert_eq!(s1.free, POOL_N);
        assert_eq!(s1.frees, s0.frees + 2);

        // from_slice bounds.
        assert_eq!(PktBuf::from_slice(&[9, 8]).unwrap().as_slice(), &[9, 8]);
        assert!(PktBuf::from_slice(&[0u8; PKT_CAP]).is_some());
        assert!(PktBuf::from_slice(&[0u8; PKT_CAP + 1]).is_none());

        // Pointer-sized in channel messages.
        assert_eq!(core::mem::size_of::<PktBuf>(), core::mem::size_of::<usize>());
    }
}
