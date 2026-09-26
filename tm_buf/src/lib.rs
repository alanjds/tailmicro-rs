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
//! [`POOL_N`] buffers live in a static array (`.bss`, never on the heap),
//! handed to a `heapless::pool::object` pool (`object_pool!`: a lock-free,
//! ABA-tagged Treiber stack). [`PktBuf::acquire`] pops one; dropping the
//! `PktBuf` clears it and pushes it back. So the packet path does no heap
//! traffic at all while no more than `POOL_N` packets are in flight. Past
//! that, `acquire` falls back to exactly the old behavior (one heap
//! alloc/free of the same size) and counts it in [`stats`].
//!
//! Why `object_pool!` and not `box_pool!`: `BoxPool::alloc(value)` takes
//! the new value *by value*, i.e. a ~1.5 KB `heapless::Vec` temporary per
//! acquire, and one producer (lwIP's netif output callback) runs on the
//! tcpip thread's 3 KB stack. An object pool recycles the already
//! initialized buffer in place, so nothing packet-sized is ever built on a
//! stack -- and "reuse the buffer, just clear it" is exactly our semantics.
//!
//! ## Safety argument
//!
//! The pool itself (the lock-free stack, the raw node pointers) is
//! `heapless`'s audited code. Our only `unsafe` is creating the one
//! `&'static mut` to the static block array that `manage` requires, and it
//! runs at most once (guarded by an atomic flag). Beyond that, ownership
//! does the work: a `PktBuf` has exactly one owner, returning the buffer to
//! the pool *is* dropping it, which happens once and only after its last
//! use -- including across `async_channel` hops (an undelivered message, or
//! one handed back inside a `SendError`, is dropped and so recycled).
//!
//! Atomics: riscv32imc has no native 64-bit atomics, which heapless's
//! 32-bit tagged-pointer CAS needs, so the workspace enables heapless's
//! `portable-atomic-critical-section` feature and this crate enables
//! `critical-section/std` (a `std::sync::Mutex`-backed impl). That is
//! correct across FreeRTOS threads -- lwIP's tcpip thread is a producer --
//! unlike `unsafe-assume-single-core`, which FreeRTOS preemption breaks.
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use heapless::object_pool;
use heapless::pool::object::{Object, ObjectBlock};

/// Capacity of every channel-facing packet buffer.
///
/// The superset of all previous per-crate sizes: `tm_derp::MAX_DERP_PAYLOAD`
/// (1500 + 32), `tm_wg`'s 1500 and `tm_disco`'s 256.
pub const PKT_CAP: usize = 1500 + 32;

/// Number of pooled buffers (~1.5 KB each, ~6 KB of static RAM).
/// Realistic steady-state in-flight count is 2-4 (one packet per hop being
/// processed plus a couple queued); bursts beyond this fall back to heap
/// allocation and show up in [`PoolStats::allocs`]. Tune from that counter
/// rather than guessing.
pub const POOL_N: usize = 4;

/// The storage behind a packet buffer.
pub type PktInner = heapless::Vec<u8, PKT_CAP>;

object_pool!(PktPool: PktInner);

/// Backing storage for the pool, in `.bss`. Only ever touched through the
/// single `&'static mut` created in [`ensure_managed`].
static mut BLOCKS: [ObjectBlock<PktInner>; POOL_N] =
    [const { ObjectBlock::new(heapless::Vec::new()) }; POOL_N];
static MANAGED: AtomicBool = AtomicBool::new(false);
/// Pooled buffers currently checked out.
static POOL_OUT: AtomicUsize = AtomicUsize::new(0);
/// Fallback heap allocations (pool empty).
static ALLOCS: AtomicU32 = AtomicU32::new(0);
/// Fallback heap buffers freed again.
static FREES: AtomicU32 = AtomicU32::new(0);

/// Hand the static blocks to the pool, once. Returns how many were added.
fn ensure_managed() -> usize {
    if MANAGED.load(Ordering::Acquire) || MANAGED.swap(true, Ordering::AcqRel) {
        return 0;
    }
    // SAFETY: the swap above lets exactly one caller, ever, reach this
    // line, so this is the only reference to BLOCKS that will ever exist;
    // `manage` then owns each block for the rest of the program.
    let blocks: &'static mut [ObjectBlock<PktInner>; POOL_N] =
        unsafe { &mut *core::ptr::addr_of_mut!(BLOCKS) };
    for block in blocks.iter_mut() {
        PktPool.manage(block);
    }
    POOL_N
}

enum Storage {
    Pooled(Object<PktPool>),
    Heap(Box<PktInner>),
}

/// A pooled packet buffer, as moved through the inter-actor channels.
///
/// A couple of words (pool handle or heap pointer), so channel messages
/// stay small: `async_channel`'s ring buffer reserves 31 slots per block
/// and returns each block by value, and an unboxed ~1.5 KB payload there
/// overflowed the ESP32-C3 main-task stack at `Runtime::join()`.
///
/// Derefs to [`PktInner`] (a `heapless::Vec<u8, PKT_CAP>`). Dropping it
/// returns the storage to the pool (or frees a fallback heap buffer).
pub struct PktBuf(Storage);

impl PktBuf {
    /// Take an empty buffer from the pool, falling back to a heap
    /// allocation if the pool is empty. Never blocks or waits.
    pub fn acquire() -> Self {
        ensure_managed();
        match PktPool.request() {
            Some(obj) => {
                POOL_OUT.fetch_add(1, Ordering::Relaxed);
                debug_assert!(obj.is_empty());
                PktBuf(Storage::Pooled(obj))
            }
            None => {
                ALLOCS.fetch_add(1, Ordering::Relaxed);
                // Built directly in the heap allocation: no ~1.5 KB stack
                // temporary (this matters on lwIP's 3 KB tcpip stack).
                PktBuf(Storage::Heap(Box::write(Box::new_uninit(), heapless::Vec::new())))
            }
        }
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
}

impl Deref for PktBuf {
    type Target = PktInner;
    fn deref(&self) -> &PktInner {
        match &self.0 {
            Storage::Pooled(o) => o,
            Storage::Heap(b) => b,
        }
    }
}

impl DerefMut for PktBuf {
    fn deref_mut(&mut self) -> &mut PktInner {
        match &mut self.0 {
            Storage::Pooled(o) => o,
            Storage::Heap(b) => b,
        }
    }
}

impl Drop for PktBuf {
    fn drop(&mut self) {
        match &mut self.0 {
            // The Object's own Drop (right after this) pushes it back to
            // the pool without dropping its value, so clear it here: the
            // next `acquire` must get an empty buffer.
            Storage::Pooled(o) => {
                o.clear();
                POOL_OUT.fetch_sub(1, Ordering::Relaxed);
            }
            Storage::Heap(_) => {
                FREES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl fmt::Debug for PktBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PktBuf({} bytes)", self.len())
    }
}

/// Hand the pool its static buffers now (otherwise the first `acquire`
/// does it). Allocates nothing; kept so start-up can make it explicit.
/// Returns how many buffers were added (`POOL_N` the first time, then 0).
pub fn prewarm() -> usize {
    ensure_managed()
}

/// Snapshot of pool counters, for heap-debug logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Pooled buffers currently idle.
    pub free: usize,
    /// Total fallback heap allocations (pool was empty). Stays 0 while no
    /// more than `POOL_N` packets are ever in flight at once.
    pub allocs: u32,
    /// Total fallback heap buffers freed again.
    pub frees: u32,
}

/// Current pool counters.
pub fn stats() -> PoolStats {
    let managed = if MANAGED.load(Ordering::Acquire) { POOL_N } else { 0 };
    PoolStats {
        free: managed.saturating_sub(POOL_OUT.load(Ordering::Relaxed)),
        allocs: ALLOCS.load(Ordering::Relaxed),
        frees: FREES.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test: the pool and counters are process-wide statics, and cargo
    // runs tests on parallel threads.
    #[test]
    fn pool_lifecycle() {
        assert_eq!(stats().free, 0, "nothing managed before first use");
        assert_eq!(prewarm(), POOL_N);
        assert_eq!(prewarm(), 0, "managed once only");
        let s0 = stats();
        assert_eq!(s0.free, POOL_N);
        assert_eq!(s0.allocs, 0);

        // Reuse: a dropped buffer comes back cleared, from static storage.
        let mut a = PktBuf::acquire();
        a.extend_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(stats().free, POOL_N - 1);
        drop(a);
        let b = PktBuf::acquire();
        assert!(b.is_empty());
        assert!(matches!(b.0, Storage::Pooled(_)));
        drop(b);
        assert_eq!(stats().free, POOL_N);
        assert_eq!(stats().allocs, 0, "no heap allocation while the pool suffices");

        // Exhaustion falls back to the heap; those buffers are freed on drop.
        let held: Vec<PktBuf> = (0..POOL_N + 2).map(|_| PktBuf::acquire()).collect();
        assert_eq!(stats().free, 0);
        assert_eq!(stats().allocs, 2);
        assert_eq!(held.iter().filter(|p| matches!(p.0, Storage::Heap(_))).count(), 2);
        drop(held);
        let s1 = stats();
        assert_eq!(s1.free, POOL_N);
        assert_eq!(s1.frees, 2);

        // from_slice bounds.
        assert_eq!(PktBuf::from_slice(&[9, 8]).unwrap().as_slice(), &[9, 8]);
        assert!(PktBuf::from_slice(&[0u8; PKT_CAP]).is_some());
        assert!(PktBuf::from_slice(&[0u8; PKT_CAP + 1]).is_none());

        // Small in channel messages.
        assert!(core::mem::size_of::<PktBuf>() <= 4 * core::mem::size_of::<usize>());
    }
}
