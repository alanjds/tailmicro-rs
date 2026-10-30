//! Process-wide "is the network link up" hint.
//!
//! tailmicro cannot tell "the radio is off" from "the relay is down": every
//! failed dial looks alike. The application knows (it owns the WiFi driver),
//! so it registers a cheap predicate (see `Config::with_link_check`) and the
//! actors consult it before dialing, instead of burning heap and CPU on
//! attempts that cannot succeed. With no predicate registered the link is
//! assumed up.
//!
//! # Heavy-dial exclusion
//!
//! When the link returns, the DERP actor (TLS handshake, ~20 KB contiguous
//! heap) and the control actor (Noise buffers, ~8 KB held for the whole
//! session) both want to dial at once. If control's buffers land first the
//! largest free block is too fragmented for DERP's handshake. [`try_dial`]
//! is a process-wide "one heavy dial at a time" flag: an actor takes the
//! [`DialGuard`] before its connect, and drops it as soon as the connect /
//! handshake / bring-up is done (never for the whole session). The guard is
//! RAII, so an error, early return or cancelled future always releases it.
//! The flag is non-blocking (no tokio here): callers poll it with a short
//! sleep of their own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static DIALING: AtomicBool = AtomicBool::new(false);

/// Proof that the holder is the one actor currently doing a heavy dial.
/// Releases the exclusion on drop.
#[derive(Debug)]
pub struct DialGuard(());

impl Drop for DialGuard {
    fn drop(&mut self) {
        DIALING.store(false, Ordering::Release);
    }
}

/// Take the heavy-dial exclusion, or `None` if another actor holds it.
pub fn try_dial() -> Option<DialGuard> {
    DIALING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()
        .map(|_| DialGuard(()))
}

static CHECK: Mutex<Option<fn() -> bool>> = Mutex::new(None);

/// Register the link predicate, replacing any earlier one. `None` clears it.
pub fn set_check(check: Option<fn() -> bool>) {
    *CHECK.lock().unwrap_or_else(|e| e.into_inner()) = check;
}

/// `true` unless a registered predicate says the link is down.
pub fn is_up() -> bool {
    // Copy the pointer out so the predicate never runs under the lock.
    let check = *CHECK.lock().unwrap_or_else(|e| e.into_inner());
    check.map_or(true, |check| check())
}

#[cfg(test)]
mod tests {
    #[test]
    fn defaults_to_up_and_the_last_registration_wins() {
        assert!(super::is_up());
        super::set_check(Some(|| false));
        assert!(!super::is_up());
        super::set_check(Some(|| true));
        assert!(super::is_up());
        super::set_check(Some(|| false));
        super::set_check(None);
        assert!(super::is_up());
    }

    // Own test (not shared with the link-check test) because DIALING is
    // process-wide; other crates' tests run in separate processes.
    #[test]
    fn dial_guard_excludes_until_dropped() {
        let first = super::try_dial().expect("free at start");
        assert!(super::try_dial().is_none(), "second dial must wait");
        drop(first);
        let again = super::try_dial().expect("free after drop");
        assert!(super::try_dial().is_none());
        drop(again);
    }
}
