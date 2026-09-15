//! TAI64N timestamps for WireGuard handshakes. Vendored from ts_tunnel's
//! `time.rs`, plus a `from_unix`/`now_from_unix` path fed by the synced-clock
//! (`now > 1_700_000_000`) discipline from the control-key-pinning work so a
//! pre-SNTP boot clock never produces a bogus handshake timestamp.

use core::fmt::{Debug, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout,
    byteorder::big_endian::{U32, U64},
};

/// An instant in time in the TAI64 format. Big-endian so it compares
/// lexicographically for the handshake replay check.
#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct TAI64N {
    secs: U64,
    nanos: U32,
}

// The (deliberately bug-for-bug compatible) TAI64 seconds base for the Unix
// epoch. See https://blog.dave.tf/post/tai64-is-not-tai/.
const TAI_BASE: u64 = 0x400000000000000a;

// Whiten nanoseconds to multiples of ~16.8ms so timestamps can't be used for
// timing attacks.
const WHITEN_MASK: u32 = !0xFFFFFF;
const WHITEN_INCREMENT: u32 = !WHITEN_MASK + 1;

impl TAI64N {
    #[inline]
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    /// Build a timestamp directly from a synced Unix time (seconds since the
    /// epoch + sub-second nanos). Caller is responsible for ensuring the clock
    /// is synced (`secs > 1_700_000_000`).
    pub fn from_unix(secs: u64, nanos: u32) -> Self {
        TAI64N {
            secs: U64::from(TAI_BASE + secs),
            nanos: U32::from(nanos & WHITEN_MASK),
        }
    }

    /// Return self if it's a later timestamp than min, or a timestamp very
    /// shortly after min otherwise.
    pub fn clamp_after(self, min: TAI64N) -> Self {
        if self > min {
            self
        } else {
            let (nanos, carry) = u32::from(min.nanos).overflowing_add(WHITEN_INCREMENT);
            let secs = if carry { min.secs + 1 } else { min.secs };
            TAI64N {
                secs,
                nanos: U32::from(nanos & WHITEN_MASK),
            }
        }
    }
}

impl Debug for TAI64N {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "TAI64N({}.{})", self.secs, self.nanos)
    }
}

impl Display for TAI64N {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}.{}", self.secs, self.nanos)
    }
}

impl From<SystemTime> for TAI64N {
    fn from(v: SystemTime) -> Self {
        if v < UNIX_EPOCH {
            let now = UNIX_EPOCH.duration_since(v).unwrap();
            let (secs, nanos) = if now.subsec_nanos() == 0 {
                (now.as_secs(), 0)
            } else {
                (now.as_secs() + 1, 1_000_000_000 - now.subsec_nanos())
            };
            TAI64N {
                secs: U64::from(TAI_BASE - secs),
                nanos: U32::from(nanos & WHITEN_MASK),
            }
        } else {
            let now = v.duration_since(UNIX_EPOCH).unwrap();
            TAI64N {
                secs: U64::from(TAI_BASE + now.as_secs()),
                nanos: U32::from(now.subsec_nanos() & WHITEN_MASK),
            }
        }
    }
}

/// A clock that produces monotonic TAI64N timestamps.
#[derive(Debug)]
pub struct TAI64NClock {
    last: TAI64N,
}

impl TAI64NClock {
    pub fn new() -> Self {
        Self {
            last: TAI64N::new_zeroed(),
        }
    }

    pub fn now(&mut self) -> TAI64N {
        self.last = TAI64N::now().clamp_after(self.last);
        self.last
    }

    /// Monotonic `now` fed from a synced Unix timestamp.
    pub fn now_from_unix(&mut self, secs: u64, nanos: u32) -> TAI64N {
        self.last = TAI64N::from_unix(secs, nanos).clamp_after(self.last);
        self.last
    }

    #[cfg(test)]
    fn now_from_systemtime(&mut self, t: SystemTime) -> TAI64N {
        self.last = TAI64N::from(t).clamp_after(self.last);
        self.last
    }
}

impl Default for TAI64NClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use core::time::Duration;

    use super::*;

    #[test]
    fn tai64n() {
        let tai = TAI64N::from(UNIX_EPOCH);
        assert_eq!(tai.secs, TAI_BASE);
        assert_eq!(tai.nanos, 0);

        let delta = Duration::from_secs(2) + Duration::from_millis(200) + Duration::from_nanos(400);

        let stamp = UNIX_EPOCH + delta;
        let tai2 = TAI64N::from(stamp);
        assert_eq!(tai2.secs, TAI_BASE + 2);
        assert_eq!(tai2.nanos, 184_549_376);
        assert!(tai < tai2);

        let stamp = UNIX_EPOCH - delta;
        let tai3 = TAI64N::from(stamp);
        assert_eq!(tai3.secs, TAI_BASE - 3);
        assert_eq!(tai3.nanos, 788_529_152);
        assert!(tai3 < tai);
        assert!(tai3 < tai2);
    }

    #[test]
    fn from_unix_matches_systemtime() {
        let secs = 1_700_000_123u64;
        let a = TAI64N::from_unix(secs, 0);
        let b = TAI64N::from(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(a, b);
    }

    #[test]
    fn tai64n_clamp() {
        let now = TAI64N::now();
        let later = now.clamp_after(now);
        assert!(later > now);

        let epoch = TAI64N::from(UNIX_EPOCH);
        let later = epoch.clamp_after(epoch);
        assert_eq!(epoch.secs, later.secs);
        assert_eq!(epoch.nanos, 0);
        assert_eq!(later.nanos, WHITEN_INCREMENT);

        assert_eq!(now.clamp_after(epoch), now);
    }

    #[test]
    fn tai64n_clock() {
        let mut clock = TAI64NClock::new();
        let t1 = clock.now();
        let t2 = clock.now();
        assert!(t1 < t2);
    }

    #[test]
    fn tai64n_clock_rollback() {
        let mut clock = TAI64NClock::new();
        let st1 = SystemTime::now();
        let st2 = st1 - Duration::from_secs(3600);
        let st3 = st2 + Duration::from_secs(10);
        let st4 = st1 + Duration::from_secs(1);

        let t1 = clock.now_from_systemtime(st1);
        let t2 = clock.now_from_systemtime(st2);
        let t3 = clock.now_from_systemtime(st3);
        let t4 = clock.now_from_systemtime(st4);
        assert!(t1 < t2);
        assert!(t2 < t3);
        assert!(t3 < t4);
    }
}
