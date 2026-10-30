//! Process-wide login and control-key status, readable from application code.
//!
//! Interactive login happens inside `Device::connect`, which does not return
//! until the user has approved the node. The application therefore cannot
//! receive the auth URL as a return value: it has to read it from another
//! task while `connect` is still pending (for example from a WebUI request
//! handler). A small static, the same pattern as `tm_buf::link`, is the
//! cheapest way to give both sides the value: no channel, no allocation, and
//! at most [`LOGIN_URL_MAX`] bytes of BSS.

use std::sync::Mutex;

/// Longest auth URL kept. A login.tailscale.com URL is about 45 bytes and a
/// headscale one carries the server's own domain; anything that does not fit
/// would be a truncated, useless link, so it is dropped instead (see
/// [`set_login_url`]).
pub const LOGIN_URL_MAX: usize = 160;

/// An interactive-login URL for the user to open in a browser.
pub type LoginUrl = heapless::String<LOGIN_URL_MAX>;

/// Why bring-up stopped on a control answer the application can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Control asked for an interactive login, which `Config::login_allowed`
    /// forbids. Nothing was published to [`login_url`] and nothing waits.
    LoginRequired,
    /// Control says the node key expired and offered no login to renew it.
    NodeKeyExpired,
}

struct State {
    url: LoginUrl,
    key_rejected: bool,
    refusal: Option<Refusal>,
}

static STATE: Mutex<State> =
    Mutex::new(State { url: heapless::String::new(), key_rejected: false, refusal: None });

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // A poisoned lock only means another thread panicked mid-update of two
    // plain fields; the data is still usable.
    let mut g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g)
}

/// The URL the user must open to log this device in, or `None` when no login
/// is pending (not needed yet, or already approved).
pub fn login_url() -> Option<LoginUrl> {
    with(|s| if s.url.is_empty() { None } else { Some(s.url.clone()) })
}

/// True once bring-up concluded that the pinned control key does not match
/// the server (see `ControlError::ControlKeyRejected`). Cleared when a new
/// `ControlCmd::Start` begins.
pub fn control_key_rejected() -> bool {
    with(|s| s.key_rejected)
}

/// The control answer that ended bring-up, when it is one of [`Refusal`].
/// Cleared when a new `ControlCmd::Start` begins.
pub fn refusal() -> Option<Refusal> {
    with(|s| s.refusal)
}

/// Store the pending URL. Returns false (and clears any old URL) if it does
/// not fit, so the application never shows a truncated link.
pub(crate) fn set_login_url(url: &str) -> bool {
    with(|s| {
        s.url.clear();
        s.url.push_str(url).is_ok() || { s.url.clear(); false }
    })
}

pub(crate) fn clear_login_url() {
    with(|s| s.url.clear());
}

pub(crate) fn set_control_key_rejected(v: bool) {
    with(|s| s.key_rejected = v);
}

pub(crate) fn set_refusal(v: Option<Refusal>) {
    with(|s| s.refusal = v);
}
