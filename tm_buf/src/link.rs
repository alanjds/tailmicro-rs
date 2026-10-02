//! Process-wide "is the network link up" hint.
//!
//! tailmicro cannot tell "the radio is off" from "the relay is down": every
//! failed dial looks alike. The application knows (it owns the WiFi driver),
//! so it registers a cheap predicate (see `Config::with_link_check`) and the
//! actors consult it before dialing, instead of burning heap and CPU on
//! attempts that cannot succeed. With no predicate registered the link is
//! assumed up.

use std::sync::Mutex;

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
}
