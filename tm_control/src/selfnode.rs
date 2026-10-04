//! Process-wide facts about this node that control tells us, readable from
//! application code (a status page), same pattern as [`crate::login`]: a small
//! static, so no channel and no allocation, and the application reads it from
//! any task without holding the netmap.
//!
//! The tailnet suffix is deliberately not kept here (see
//! [`set_suffix_hook`]): MagicDNS only needs its hash, and the one app that
//! shows the name can cache it in the shape it wants.

use std::sync::Mutex;

/// Receives the tailnet suffix of our own `Node.Name` (see [`set_suffix_hook`]).
pub type SuffixHook = fn(&str);

struct State {
    key_expiry: Option<i64>,
    suffix_hook: Option<SuffixHook>,
}

static STATE: Mutex<State> = Mutex::new(State { key_expiry: None, suffix_hook: None });

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

/// Register (or clear) the hook that is handed our tailnet suffix, for apps
/// that display the FQDN (`<label>.<suffix>`).
///
/// The hook runs on the control task, inside the map parser, each time our own
/// `Node.Name` is seen with a different suffix than before: once per control
/// connection, and again if the tailnet is renamed. The `&str` is the text
/// after the first label, no leading or trailing dot, case as control sent it
/// (empty when control names nodes with a bare label). It borrows the
/// parser's scratch space, so it is valid only during the call: copy it. It is
/// at most 127 bytes (the parser's value buffer; an over-long name is
/// truncated there), so a `heapless::String<48>` that drops what does not fit
/// matches the longest suffix tailmicro itself keeps. The hook must not block,
/// await or panic.
pub fn set_suffix_hook(hook: Option<SuffixHook>) {
    with(|s| s.suffix_hook = hook);
}

pub(crate) fn publish_key_expiry(key_expiry: Option<i64>) {
    with(|s| s.key_expiry = key_expiry);
}

/// Hand `suffix` to the hook. The lock is released first: the hook is app
/// code.
pub(crate) fn announce_suffix(suffix: &str) {
    if let Some(hook) = with(|s| s.suffix_hook) {
        hook(suffix);
    }
}
