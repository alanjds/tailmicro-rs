//! Process-wide facts about this node that control tells us, readable from
//! application code (a status page), same pattern as [`crate::login`]: a small
//! static, so no channel and no allocation, and the application reads it from
//! any task without holding the netmap.

use std::sync::Mutex;

struct State {
    key_expiry: Option<i64>,
}

static STATE: Mutex<State> = Mutex::new(State { key_expiry: None });

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // A poisoned lock only means another thread panicked mid-update of plain
    // fields; the data is still usable.
    let mut g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g)
}

/// When our node key expires, in unix seconds, or `None` when it never does
/// (or no netmap has arrived yet).
pub fn key_expiry() -> Option<i64> {
    with(|s| s.key_expiry)
}

pub(crate) fn publish_key_expiry(key_expiry: Option<i64>) {
    with(|s| s.key_expiry = key_expiry);
}
