//! Runtime-agnostic time for tailmicro.
//!
//! `Instant` is a monotonic microsecond count with an arbitrary epoch. Its
//! source is a pair of plain function pointers installed once with
//! [`set_clock`]; with the `std` feature (default) an unset clock falls back to
//! `std::time::Instant` / `SystemTime`, which is what the code used before this
//! crate existed. No heap, no locks: the clock lives in two atomics that are
//! only loaded and stored (no CAS), so it works on riscv32imc.
//!
//! `Duration` is `core::time::Duration`.
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::{Add, AddAssign, Sub};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

/// Monotonic instant: microseconds since an arbitrary epoch.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Instant(u64);

impl Instant {
    /// The current instant from the installed clock.
    pub fn now() -> Self {
        Instant(now_us())
    }

    pub const fn from_micros(us: u64) -> Self {
        Instant(us)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Time from `earlier` to `self`, saturating at zero.
    pub fn duration_since(self, earlier: Self) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    /// Time since `self`, per the installed clock.
    pub fn elapsed(self) -> Duration {
        Instant::now().duration_since(self)
    }

    pub fn checked_add(self, d: Duration) -> Option<Self> {
        let us = u64::try_from(d.as_micros()).ok()?;
        self.0.checked_add(us).map(Instant)
    }

    pub fn checked_sub(self, d: Duration) -> Option<Self> {
        let us = u64::try_from(d.as_micros()).ok()?;
        self.0.checked_sub(us).map(Instant)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, d: Duration) -> Instant {
        self.checked_add(d).expect("tm_time::Instant overflow")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;
    fn sub(self, d: Duration) -> Instant {
        self.checked_sub(d).expect("tm_time::Instant underflow")
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, earlier: Instant) -> Duration {
        self.duration_since(earlier)
    }
}

// Function pointers stored as usize; 0 means "not installed".
static NOW_US: AtomicUsize = AtomicUsize::new(0);
static UNIX_SECS: AtomicUsize = AtomicUsize::new(0);

/// Install the clock. Call once, before the first `Instant::now()` (a later
/// call replaces the clock; instants from the old clock are then meaningless).
///
/// `now_us` is a monotonic microsecond counter. `unix_secs` is wall-clock
/// seconds since the Unix epoch, or `None` while the wall clock is not set.
pub fn set_clock(now_us: fn() -> u64, unix_secs: fn() -> Option<u64>) {
    NOW_US.store(now_us as usize, Ordering::Release);
    UNIX_SECS.store(unix_secs as usize, Ordering::Release);
}

/// Wall-clock seconds since the Unix epoch, if the clock knows them.
pub fn unix_secs() -> Option<u64> {
    let p = UNIX_SECS.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: only `set_clock` stores here, and it stores a `fn() -> Option<u64>`.
        let f: fn() -> Option<u64> = unsafe { core::mem::transmute(p) };
        return f();
    }
    #[cfg(feature = "std")]
    {
        std_clock::unix_secs()
    }
    #[cfg(not(feature = "std"))]
    {
        None
    }
}

fn now_us() -> u64 {
    let p = NOW_US.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: only `set_clock` stores here, and it stores a `fn() -> u64`.
        let f: fn() -> u64 = unsafe { core::mem::transmute(p) };
        return f();
    }
    #[cfg(feature = "std")]
    {
        std_clock::now_us()
    }
    #[cfg(not(feature = "std"))]
    {
        panic!("tm_time: no clock installed; call tm_time::set_clock first")
    }
}

#[cfg(feature = "std")]
mod std_clock {
    use std::sync::OnceLock;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    // Epoch = first use of the clock. The first call may land a tick before
    // `now_us` returns 0; that is fine, only differences matter.
    static EPOCH: OnceLock<Instant> = OnceLock::new();

    pub fn now_us() -> u64 {
        let epoch = *EPOCH.get_or_init(Instant::now);
        epoch.elapsed().as_micros() as u64
    }

    pub fn unix_secs() -> Option<u64> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let a = Instant::from_micros(1_000);
        let b = a + Duration::from_millis(5);
        assert_eq!(b.as_micros(), 6_000);
        assert_eq!(b - a, Duration::from_millis(5));
        assert_eq!(b.duration_since(a), Duration::from_millis(5));
        // Saturating, never panics.
        assert_eq!(a.duration_since(b), Duration::ZERO);
        assert_eq!(a - b, Duration::ZERO);
        assert_eq!(b - Duration::from_millis(5), a);
        assert_eq!(a.checked_sub(Duration::from_secs(1)), None);
        assert_eq!(Instant::from_micros(u64::MAX).checked_add(Duration::from_micros(1)), None);
        let mut c = a;
        c += Duration::from_micros(1);
        assert_eq!(c.as_micros(), 1_001);
    }

    #[test]
    fn std_default_clock_is_monotonic() {
        let a = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        let b = Instant::now();
        assert!(b > a);
        assert!(b.duration_since(a) >= Duration::from_millis(2));
        assert!(a.elapsed() >= Duration::from_millis(2));
    }
}
