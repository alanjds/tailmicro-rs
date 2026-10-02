//! Process-wide "is the network link up" hint.
//!
//! tailmicro cannot tell "the radio is off" from "the relay is down": every
//! failed dial looks alike. The application knows (it owns the WiFi driver),
//! so it registers a cheap predicate once and the actors consult it before
//! dialing, instead of burning heap and CPU on attempts that cannot succeed.
//! With no predicate registered the link is assumed up.

use std::sync::OnceLock;

static CHECK: OnceLock<fn() -> bool> = OnceLock::new();

/// Register the link predicate. Only the first call takes effect.
pub fn set_check(check: fn() -> bool) {
    let _ = CHECK.set(check);
}

/// `true` unless a registered predicate says the link is down.
pub fn is_up() -> bool {
    CHECK.get().map_or(true, |check| check())
}

#[cfg(test)]
mod tests {
    #[test]
    fn defaults_to_up() {
        assert!(super::is_up());
    }
}
