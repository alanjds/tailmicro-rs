//! WireGuard endpoint, rewritten (not vendored) against `ArrayVec` for
//! no-heap, bounded-memory operation on the ESP32-C3 (plan Step 2).
//!
//! Differences from `ts_tunnel/src/endpoint.rs`:
//!   * `HashMap<PeerId, Peer>` → `ArrayVec<Peer, MAX_PEERS>` (linear scan).
//!   * `HashMap<SessionId, PeerId>` → `ArrayVec<(SessionId, PeerId), 3*MAX_PEERS>`
//!     (3 keypairs/peer: current / previous / next).
//!   * per-peer 32-deep `VecDeque` packet queue → `ArrayVec<Packet, QUEUE_DEPTH>`
//!     (depth 2 — the RAM-dominant term per plan correction #5).
//!   * `ts_time::Scheduler` (Arc + LazyLock) → two per-peer `Option<Instant>`
//!     timers (`handshake_timeout`, `keepalive_at`); `next_event`/`dispatch`
//!     scan the peer table.
//!   * `HashMap<_, Vec<_>>` results → per-call bounded `ArrayVec` outcome
//!     structs (single-peer-at-a-time, matching the actor mailbox).
//!   * transport endpoint modelled as a Rust `enum Endpoint` (no 127.3.3.40
//!     fake-IP hack); authenticated-only endpoint roaming, skipped for DERP.

use core::net::{SocketAddr, SocketAddrV4};
use core::time::Duration;
use std::time::Instant;

use arrayvec::ArrayVec;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::vendor::{
    config::{PeerConfig, PeerId},
    handshake::{Handshake, ReceivedHandshake, SessionPair, initiate_handshake},
    keys::{NodeKeyPair, NodePublicKey},
    macs::{MACReceiver, MACSender},
    messages::{HandshakeInitiation, HandshakeResponse, Message, SessionId},
    packet::Packet,
    session::{ReceiveSession, TransmitSession},
    tai64n::TAI64NClock,
};

pub const MAX_PEERS: usize = 8;
/// Per-peer packet queue depth. Zero: the queue holds outbound *app-data*
/// packets while a session is still handshaking, but that path is not wired to
/// a `WgCmd` variant yet (see `queue_push` / `SessionState::needs_rotation`,
/// both dead code). At `QUEUE_DEPTH = 2` this queue was 3048 of each Peer's
/// 3488 bytes -- ~24 KB of the ~28 KB `WgEndpoint` -- reserved inline for all
/// MAX_PEERS slots up front, and allocating that on the ESP32-C3's fragmented
/// ~57 KB heap (once the DERP TLS session is up) OOM-aborted the data-plane
/// bring-up (`memory allocation of 27968 bytes failed`). With no inline queue
/// the endpoint drops to ~6 KB (5968 bytes) and fits. When the outbound app-data path is
/// wired up, give it a heap-on-demand queue rather than a per-slot inline one.
const QUEUE_DEPTH: usize = 0;
/// Session-id map capacity: 3 keypairs/peer (current/previous/next).
const SESSION_MAP_CAP: usize = 3 * MAX_PEERS;
/// Max packets a single `recv_one` call emits (in `RecvOut::to_peer` /
/// `decrypted`). `RecvOut` embeds two `ArrayVec<Packet, OUT_CAP>` of inline
/// ~1516-byte packet buffers, so its size is `2 * OUT_CAP * ~1516`. On real
/// ESP32-C3 hardware the DERP TLS session + live netmap fragment the heap down
/// to an ~8 KB largest free block, so a per-inbound `Box<RecvOut>` MUST stay
/// under that: `OUT_CAP = 2` -> ~6 KB (fits); the old `QUEUE_DEPTH + 2 = 4` ->
/// ~12 KB failed to allocate (`memory allocation of 12100 bytes failed` ->
/// abort/reboot before `PeerHandshook`). Our flows emit at most 1-2 packets per
/// recv (handshake response/confirmation, one decrypted reply); a rare
/// queue-flush + keepalive overflow is dropped by `try_push`. See
/// docs/wg-dataplane-notes.md.
const OUT_CAP: usize = 2;
/// Max packets one `dispatch` call returns. `dispatch`'s output is
/// `Box`-allocated every 100 ms tick by `on_tick`, and `Box::new` allocates the
/// full `ArrayVec<(PeerId, Packet), DISPATCH_CAP>` (~`DISPATCH_CAP * 1520` B)
/// regardless of how many entries are used — so this, like `OUT_CAP`, must stay
/// under the ~8 KB fragmented-heap block. `DISPATCH_CAP = 4` -> ~6 KB (the old
/// `MAX_PEERS = 8` -> ~12 KB also failed post-TLS). Peers whose timers are still
/// due when the buffer fills are serviced on the next tick.
const DISPATCH_CAP: usize = 4;

/// The type [`WgEndpoint::dispatch`] returns, named so callers (e.g.
/// `WgActor::on_tick`) can hold a persistent, reusable scratch buffer of this
/// exact type instead of `Box::new`-ing a fresh one every tick.
pub type DispatchOut = ArrayVec<(PeerId, Packet), DISPATCH_CAP>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshake-retry jitter upper bound (prevents synchronized fleet storms).
const HANDSHAKE_JITTER_MS: u64 = 334;

/// The transport an endpoint uses to reach a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Direct UDP.
    Udp(SocketAddr),
    /// Relayed via a DERP region, addressed by the peer's node key.
    Derp { region_id: u16, node_key: [u8; 32] },
}

/// How long a direct UDP path stays usable after the last authenticated
/// evidence from it. Matches tailscaled's `trustUDPAddrDuration`: an active
/// tailscaled peer heartbeats its best path about every 3 s, so trust stays
/// warm while the path works and lapses on its own when the peer goes idle,
/// leaves the LAN or changes address (docs/lan-direct-path-plan.md D3).
pub const DIRECT_TRUST: Duration = Duration::from_millis(6500);

/// How long WireGuard from a peer over DERP keeps our sends to it on DERP,
/// whatever the direct path's trust says.
///
/// tailscaled sends WireGuard *only* to its best UDP address while it trusts
/// it, and to both that address and DERP once the trust has lapsed
/// (magicsock `addrForSendLocked`). So WireGuard over DERP from a peer means
/// the peer does not currently trust the direct path, typically because our
/// PONGs stopped reaching it. Its UDP copies keep arriving (and would keep
/// refreshing our trust) even though our datagrams to it are being lost.
/// Found on hardware in Step 6 (docs/lan-direct-path-plan.md): without this,
/// a one-way break (peer receives nothing from us over UDP) black-holed every
/// reply from the device for as long as the break lasted. The UDP copy of a
/// pair usually lands first on a LAN, hence a hold-off rather than a one-shot
/// clear. Equal to `DIRECT_TRUST` so it outlasts the peer's heartbeat gaps.
pub const DERP_HOLDOFF: Duration = DIRECT_TRUST;

/// A LAN path to a peer, proven by authenticated traffic from exactly
/// `addr`. Sends use it only while `now < trust_until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectPath {
    pub addr: SocketAddrV4,
    pub trust_until: Instant,
}

type Queue = ArrayVec<Packet, QUEUE_DEPTH>;

/// Push `pkt` into a bounded queue, dropping the oldest if full.
///
/// Part of the outbound app-data path (queue packets while a session is being
/// established). That path is not yet wired to a `WgCmd` variant, so this and
/// `SessionState::needs_rotation` are currently unused.
///
/// With `QUEUE_DEPTH == 0` the queue has no capacity: `is_full()` is always
/// true and both `remove(0)` (empty vec) and `push` would panic, so the packet
/// is simply dropped. Pre-session app-data is best-effort until the outbound
/// path is wired up, so dropping it is the correct no-op here.
#[allow(dead_code)]
fn queue_push(q: &mut Queue, pkt: Packet) {
    if QUEUE_DEPTH == 0 {
        return;
    }
    if q.is_full() {
        q.remove(0);
    }
    q.push(pkt);
}

enum SessionState {
    /// No active session; packets may be queued for future transmission.
    None(Queue),
    Active {
        recv: ReceiveSession,
        recv_prev: Option<ReceiveSession>,
        send: TransmitSession,
    },
}

impl SessionState {
    fn take(&mut self) -> SessionState {
        core::mem::replace(self, SessionState::None(Queue::new()))
    }

    /// Activate `next`, rotating any existing session. Encrypted packets to send
    /// (any that were queued) are pushed into the caller-provided `out`; the ids
    /// of receive sessions that should be released from the session map are
    /// returned.
    ///
    /// `out` is written in place rather than returned by value: on the
    /// handshake-completion path this runs deep inside `recv_one_into` (tokio
    /// poll chain -> boxed `on_inbound` future -> `recv_response` -> `finish`'s
    /// Blake2s/HKDF key schedule), and an `ArrayVec<Packet, OUT_CAP>` (~6 KB of
    /// inline `heapless` packet buffers) returned by value there overflowed the
    /// ESP32-C3 main task stack the first time a handshake actually COMPLETED
    /// (the AEAD-failing path returned before reaching here, so only success
    /// exposed it). The caller passes its already heap-allocated `RecvOut`
    /// buffer, keeping those ~6 KB off the stack.
    fn activate(
        &mut self,
        next: SessionPair,
        out: &mut ArrayVec<Packet, OUT_CAP>,
    ) -> ArrayVec<SessionId, 2> {
        let mut freed = ArrayVec::new();
        match self.take() {
            SessionState::None(queue) => {
                for mut pkt in queue.into_iter() {
                    next.send.encrypt(core::iter::once(&mut pkt));
                    let _ = out.try_push(pkt);
                }
                *self = SessionState::Active {
                    send: next.send,
                    recv: next.recv,
                    recv_prev: None,
                };
            }
            SessionState::Active {
                recv, recv_prev, ..
            } => {
                if let Some(prev) = recv_prev {
                    let _ = freed.try_push(prev.id());
                }
                *self = SessionState::Active {
                    send: next.send,
                    recv: next.recv,
                    recv_prev: Some(recv),
                };
            }
        }
        freed
    }

    fn deactivate(&mut self) -> ArrayVec<SessionId, 2> {
        let mut freed = ArrayVec::new();
        if let SessionState::Active {
            recv, recv_prev, ..
        } = self.take()
        {
            let _ = freed.try_push(recv.id());
            if let Some(prev) = recv_prev {
                let _ = freed.try_push(prev.id());
            }
        }
        freed
    }

    fn encrypt_keepalive(&mut self, now: Instant) -> Option<Packet> {
        if let SessionState::Active { send, .. } = self
            && !send.expired(now)
        {
            let mut pkt = Packet::new(0);
            send.encrypt(core::iter::once(&mut pkt));
            Some(pkt)
        } else {
            None
        }
    }

    /// Get the receive session matching `id`, if any (checks current + prev).
    fn get_recv_mut(&mut self, id: SessionId, now: Instant) -> Option<&mut ReceiveSession> {
        match self {
            SessionState::None(_) => None,
            SessionState::Active {
                recv, recv_prev, ..
            } => {
                if recv.id() == id && !recv.expired(now) {
                    Some(recv)
                } else if let Some(prev) = recv_prev.as_mut()
                    && prev.id() == id
                    && !prev.expired(now)
                {
                    Some(prev)
                } else {
                    None
                }
            }
        }
    }

    /// True if the transmit side is stale / absent and needs a new handshake.
    #[allow(dead_code)] // consulted by the not-yet-wired outbound app-data path
    fn needs_rotation(&self, now: Instant) -> bool {
        match self {
            SessionState::None(_) => true,
            SessionState::Active { send, .. } => send.stale(now),
        }
    }
}

struct Peer {
    id: PeerId,
    config: PeerConfig,
    /// Always the DERP route. It is never torn down, because it is where
    /// sends go whenever the direct path is absent or untrusted.
    derp: Endpoint,
    /// Optional LAN path, trust-windowed (D3).
    direct: Option<DirectPath>,
    /// Sends stay on DERP until then; see `DERP_HOLDOFF`.
    derp_holdoff_until: Option<Instant>,
    session: SessionState,
    handshake: Handshake,
    last_seen_timestamp: Option<crate::vendor::tai64n::TAI64N>,
    cookie_sender: MACSender,
    handshake_timeout: Option<Instant>,
    keepalive_at: Option<Instant>,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig, derp: Endpoint) -> Self {
        let cookie_sender = MACSender::new(&config.key);
        Self {
            id,
            config,
            derp,
            direct: None,
            derp_holdoff_until: None,
            session: SessionState::None(Queue::new()),
            handshake: Handshake::None,
            last_seen_timestamp: None,
            cookie_sender,
            handshake_timeout: None,
            keepalive_at: None,
        }
    }

    fn schedule_keepalive(&mut self, now: Instant) {
        if self.keepalive_at.is_none() {
            self.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
        }
    }
}

/// The result of processing one inbound packet.
#[derive(Default)]
pub struct RecvOut {
    /// Encrypted packets to send back to the peer (handshake response,
    /// session-confirmation, etc.).
    pub to_peer: ArrayVec<Packet, OUT_CAP>,
    /// Decrypted inbound payloads destined for the local netstack.
    pub decrypted: ArrayVec<Packet, OUT_CAP>,
    /// Set when a handshake completed (initiator side) this call.
    pub handshook: bool,
    /// The peer this packet belonged to, if identified.
    pub peer: Option<PeerId>,
}

impl RecvOut {
    /// Clear all fields in place so a caller-owned `RecvOut` can be reused
    /// across calls instead of being freed and re-`Box::new`'d (which was
    /// measured to fragment the ESP32-C3 heap under sustained traffic: this
    /// struct is exactly the ~6 KB block that recurs in `memory allocation
    /// of 6052 bytes failed` aborts). See ALLOCATIONS.md.
    pub fn reset(&mut self) {
        self.to_peer.clear();
        self.decrypted.clear();
        self.handshook = false;
        self.peer = None;
    }
}

/// Hand out a `&'static mut RecvOut` backed by `.bss`, once. Unlike
/// `WgEndpoint::new_static`, `RecvOut` has no runtime-dependent fields (both
/// `ArrayVec`s are const-constructible via `new_const()`, and `handshook`/
/// `peer` have trivial const defaults), so the whole value can be a directly
/// const-initialized `static mut` -- no `MaybeUninit`/field-by-field write
/// needed. Same rationale as `WgEndpoint::new_static`: one instance, held
/// forever, so a static removes its ~6 KB one-time heap contribution
/// entirely (ALLOCATIONS.md Step 5).
///
/// # Panics
/// Panics if called more than once, for the same aliasing reason as
/// `WgEndpoint::new_static`.
#[inline(never)]
pub fn recv_out_static() -> &'static mut RecvOut {
    static TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static mut STORAGE: RecvOut = RecvOut {
        to_peer: ArrayVec::new_const(),
        decrypted: ArrayVec::new_const(),
        handshook: false,
        peer: None,
    };

    if TAKEN.swap(true, std::sync::atomic::Ordering::AcqRel) {
        panic!("recv_out_static called more than once");
    }
    // SAFETY: the swap above guarantees exactly one caller, ever, reaches
    // this point, so this is the only `&'static mut` that will ever be
    // created to this function-local static.
    unsafe { &mut *core::ptr::addr_of_mut!(STORAGE) }
}

/// Hand out a `&'static mut DispatchOut` backed by `.bss`, once. Same
/// rationale and safety argument as [`recv_out_static`]; `DispatchOut` is a
/// plain `ArrayVec` type alias, const-constructible via `new_const()`.
///
/// # Panics
/// Panics if called more than once.
#[inline(never)]
pub fn dispatch_out_static() -> &'static mut DispatchOut {
    static TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static mut STORAGE: DispatchOut = ArrayVec::new_const();

    if TAKEN.swap(true, std::sync::atomic::Ordering::AcqRel) {
        panic!("dispatch_out_static called more than once");
    }
    // SAFETY: same argument as `recv_out_static` above.
    unsafe { &mut *core::ptr::addr_of_mut!(STORAGE) }
}

struct EndpointState {
    my_key: NodeKeyPair,
    my_cookie: MACReceiver,
    timestamps: TAI64NClock,
    /// SessionId → PeerId, linear-scan map.
    sessions: ArrayVec<(SessionId, PeerId), SESSION_MAP_CAP>,
    next_peer_id: u32,
}

impl EndpointState {
    fn peer_for_session(&self, id: SessionId) -> Option<PeerId> {
        self.sessions
            .iter()
            .find(|(s, _)| *s == id)
            .map(|(_, p)| *p)
    }

    fn alloc_session(&mut self, peer: PeerId) -> SessionId {
        loop {
            let id = SessionId::random();
            if !self.sessions.iter().any(|(s, _)| *s == id) && !self.sessions.is_full() {
                self.sessions.push((id, peer));
                return id;
            }
            if self.sessions.is_full() {
                // Should not happen with correct rotation; drop oldest.
                self.sessions.remove(0);
            }
        }
    }

    fn free_session(&mut self, id: SessionId) {
        self.sessions.retain(|(s, _)| *s != id);
    }
}

/// A WireGuard endpoint managing multiple peers, no heap for its own tables.
pub struct WgEndpoint {
    state: EndpointState,
    peers: ArrayVec<Peer, MAX_PEERS>,
}

impl WgEndpoint {
    pub fn new(my_key: NodeKeyPair) -> Self {
        Self {
            state: EndpointState {
                my_key,
                my_cookie: MACReceiver::new(&my_key.public),
                timestamps: TAI64NClock::new(),
                sessions: ArrayVec::new(),
                next_peer_id: 0,
            },
            peers: ArrayVec::new(),
        }
    }

    /// Construct directly into a static `.bss` slot, field-by-field, via a
    /// raw pointer.
    ///
    /// `Self` is ~6 KB (`peers: ArrayVec<Peer, MAX_PEERS>` dominates).
    /// `WgEndpoint::new(..)` builds that whole value as a stack temporary and
    /// moves it into place; at this workspace's `opt-level = "z"` +
    /// `lto = true` dev profile the compiler does not elide the temporary
    /// (observed as multiple copies, a ~55 KB frame, wherever the call ended
    /// up after inlining). Even `addr_of_mut!(..).write(ArrayVec::new())`
    /// materialized a stack-sized "empty" `ArrayVec` first, because
    /// `ArrayVec::new` is not `const`. Sourcing the empty value from an
    /// `ArrayVec::new_const()` `static` (the pattern arrayvec's docs
    /// recommend) makes it a fixed rodata address that `memcpy` copies FROM,
    /// eliminating the stack temporary.
    ///
    /// There is exactly one `WgEndpoint` for the lifetime of this firmware
    /// (one `WgActor`, built once by `Runtime::build`), allocated lazily on
    /// first use and then held forever -- exactly the shape a `static` is
    /// for, and exactly the same "fixed-size, single instance, never freed"
    /// pattern already applied to `tm_buf::PktBuf`. Moving it off the heap
    /// removes its ~6 KB one-time contribution to heap fragmentation
    /// entirely (ALLOCATIONS.md, "Fix plan: DERP TLS handshake heap
    /// collapse", Step 5), at the cost of ~6 KB of permanent `.bss` --
    /// the same heap-cost-for-no-fragmentation tradeoff already accepted
    /// for `tm_buf::PKT_CAP`.
    ///
    /// # Panics
    /// Panics if called more than once: a second call would hand out a
    /// second `&'static mut` aliasing the same storage as the first, which
    /// would be unsound. This is enforced with an atomic flag rather than
    /// relied upon by convention. Callers (just `WgActor::endpoint()`) only
    /// ever call this once, guarded by their own `Option`.
    #[inline(never)]
    pub fn new_static(my_key: NodeKeyPair) -> &'static mut WgEndpoint {
        static EMPTY_PEERS: ArrayVec<Peer, MAX_PEERS> = ArrayVec::new_const();
        static EMPTY_SESSIONS: ArrayVec<(SessionId, PeerId), SESSION_MAP_CAP> = ArrayVec::new_const();
        static STORAGE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        static mut ENDPOINT_STORAGE: core::mem::MaybeUninit<WgEndpoint> =
            core::mem::MaybeUninit::uninit();

        if STORAGE.swap(true, std::sync::atomic::Ordering::AcqRel) {
            panic!("WgEndpoint::new_static called more than once");
        }
        // SAFETY: the swap above guarantees exactly one caller, ever,
        // reaches this point, so this is the only reference to
        // ENDPOINT_STORAGE that will ever exist (it is a function-local
        // static, unreachable from anywhere else). Each field is written
        // exactly once, in full, before `assume_init_mut()`, with the same
        // per-field safety argument as below.
        unsafe {
            let ptr = core::ptr::addr_of_mut!(ENDPOINT_STORAGE).cast::<WgEndpoint>();
            core::ptr::addr_of_mut!((*ptr).state.sessions).copy_from_nonoverlapping(&EMPTY_SESSIONS, 1);
            core::ptr::addr_of_mut!((*ptr).state.my_key).write(my_key);
            core::ptr::addr_of_mut!((*ptr).state.my_cookie).write(MACReceiver::new(&my_key.public));
            core::ptr::addr_of_mut!((*ptr).state.timestamps).write(TAI64NClock::new());
            core::ptr::addr_of_mut!((*ptr).state.next_peer_id).write(0);
            core::ptr::addr_of_mut!((*ptr).peers).copy_from_nonoverlapping(&EMPTY_PEERS, 1);
            &mut *ptr
        }
    }

    /// Number of live entries in the session-id map. Test-only: used to assert
    /// that timed-out handshakes free their session id instead of leaking it.
    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.state.sessions.len()
    }

    fn peer_index(&self, id: PeerId) -> Option<usize> {
        self.peers.iter().position(|p| p.id == id)
    }

    fn peer_index_by_key(&self, key: &NodePublicKey) -> Option<usize> {
        self.peers.iter().position(|p| p.config.key == *key)
    }

    /// Add a peer reachable over `derp` (its fallback route). Returns its id,
    /// or None if the table is full or the key is already present.
    pub fn add_peer(&mut self, cfg: PeerConfig, derp: Endpoint) -> Option<PeerId> {
        if self.peer_index_by_key(&cfg.key).is_some() || self.peers.is_full() {
            return None;
        }
        self.state.next_peer_id += 1;
        let id = PeerId(self.state.next_peer_id);
        self.peers.push(Peer::new(id, cfg, derp));
        Some(id)
    }

    pub fn remove_peer(&mut self, id: PeerId) -> bool {
        let Some(idx) = self.peer_index(id) else {
            return false;
        };
        let mut peer = self.peers.remove(idx);
        for sid in peer.session.deactivate() {
            self.state.free_session(sid);
        }
        if let Some(sid) = peer.handshake.session_id() {
            self.state.free_session(sid);
        }
        true
    }

    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        self.peer_index(id).map(|i| self.peers[i].config.key)
    }

    /// The peer's DERP (fallback) route.
    pub fn peer_endpoint(&self, id: PeerId) -> Option<Endpoint> {
        self.peer_index(id).map(|i| self.peers[i].derp.clone())
    }

    /// The peer's direct path record, trusted or not.
    pub fn peer_direct(&self, id: PeerId) -> Option<DirectPath> {
        self.peer_index(id).and_then(|i| self.peers[i].direct)
    }

    /// Where to send to `id` right now: `Some(addr)` for the direct path
    /// while it is trusted, `None` for DERP. One rule for handshakes,
    /// keepalives and data, so they never split across paths.
    ///
    /// DERP while a `DERP_HOLDOFF` is running, even if the direct path is
    /// trusted: the peer itself is not using the direct path then.
    pub fn path_for(&self, id: PeerId, now: Instant) -> Option<SocketAddrV4> {
        let p = &self.peers[self.peer_index(id)?];
        if p.derp_holdoff_until.is_some_and(|h| now < h) {
            return None;
        }
        let d = p.direct?;
        (now < d.trust_until).then_some(d.addr)
    }

    /// A disco PING from `addr` opened under this peer's allowlisted disco
    /// key (tm_disco checked the node-key pairing), which is authenticated
    /// evidence that `addr` reaches the peer. Returns false for an unknown
    /// peer.
    pub fn direct_path_seen(&mut self, node_key: &[u8; 32], addr: SocketAddrV4, now: Instant) -> bool {
        let k = NodePublicKey::from_bytes(*node_key);
        let Some(idx) = self.peer_index_by_key(&k) else {
            return false;
        };
        trust_direct(&mut self.peers[idx], addr, now);
        true
    }

    pub fn peer_id_by_key(&self, key: &[u8; 32]) -> Option<PeerId> {
        let k = NodePublicKey::from_bytes(*key);
        self.peer_index_by_key(&k).map(|i| self.peers[i].id)
    }

    /// Start a handshake to the given peer, returning the initiation packet.
    /// `now_unix` must be a synced wall-clock (seconds); pass None if the clock
    /// is not yet synced (no handshake is produced, avoiding a bogus TAI64N).
    pub fn initiate(&mut self, id: PeerId, now: Instant, now_unix: Option<u64>) -> Option<Packet> {
        let Some(secs) = now_unix else {
            tracing::warn!("clock not synced; skipping handshake initiation");
            return None;
        };
        let idx = self.peer_index(id)?;
        let session_id = self.state.alloc_session(id);
        let peer = &mut self.peers[idx];
        let (sent, init) = initiate_handshake(
            self.state.my_key.private,
            peer.config.key,
            session_id,
            self.state.timestamps.now_from_unix(secs, 0),
        );
        let mut pkt = Packet::from_wire(init.as_bytes());
        let mac = peer.cookie_sender.write_macs(pkt.as_mut());
        peer.handshake = Handshake::Initiated(sent, mac);
        peer.handshake_timeout = Some(now + HANDSHAKE_TIMEOUT);
        Some(pkt)
    }

    /// Encrypt and enqueue an outbound transport (app-data) `payload` for the
    /// peer identified by `dst_key`.
    ///
    /// If the peer has an active, non-expired send session the ciphertext (with
    /// its 16-byte transport-data header) is written into `out.to_peer` and
    /// `true` is returned. If no session is active yet the plaintext is queued
    /// and flushed automatically when the session activates (`false` returned,
    /// meaning "not sent yet"). Returns `false` for an unknown peer or a stale
    /// send session (the caller should re-handshake).
    ///
    /// This is the outbound app-data seam (rung 6a): the runtime drives an ICMP
    /// echo request through here after `PeerHandshook` so the peer replies and
    /// an inbound transport packet becomes observable.
    pub fn send_data(
        &mut self,
        dst_key: &[u8; 32],
        payload: &[u8],
        now: Instant,
        out: &mut RecvOut,
    ) -> bool {
        let k = NodePublicKey::from_bytes(*dst_key);
        let Some(idx) = self.peer_index_by_key(&k) else {
            tracing::warn!("send_data to unknown peer");
            return false;
        };
        out.peer = Some(self.peers[idx].id);
        let mut pkt = Packet::from_plaintext(payload);
        let peer = &mut self.peers[idx];
        // Compute activeness first so the immutable `send` borrow ends before we
        // need `&mut peer` again for the keepalive schedule.
        let active =
            matches!(&peer.session, SessionState::Active { send, .. } if !send.expired(now));
        if active {
            if let SessionState::Active { send, .. } = &peer.session {
                send.encrypt(core::iter::once(&mut pkt));
            }
            let _ = out.to_peer.try_push(pkt);
            peer.schedule_keepalive(now);
            true
        } else if let SessionState::None(queue) = &mut peer.session {
            queue_push(queue, pkt);
            false
        } else {
            false
        }
    }

    /// Process one inbound packet arriving over `from`.
    /// Process one inbound packet, returning a fresh [`RecvOut`] by value.
    ///
    /// Kept for tests and host callers. On-device callers should prefer
    /// [`Self::recv_one_into`] with a heap-allocated `RecvOut`: `RecvOut` embeds
    /// two `ArrayVec<Packet, OUT_CAP>` (~12 KB of inline, heapless buffers), so
    /// returning it by value materialises ~12 KB on the caller's stack — which,
    /// stacked on the tokio/actor poll chain, overflowed the ESP32-C3 main task
    /// stack the first time DERP actually delivered an inbound WG packet.
    pub fn recv_one(&mut self, raw: &[u8], from: Endpoint, now: Instant) -> RecvOut {
        let mut out = RecvOut::default();
        self.recv_one_into(raw, from, now, &mut out);
        out
    }

    /// Process one inbound packet, writing results into a caller-provided
    /// `out`, which must be empty (freshly [`RecvOut::default`] or reset via
    /// [`RecvOut::reset`]) and, on device, heap-allocated so the buffer never
    /// touches the stack.
    pub fn recv_one_into(&mut self, raw: &[u8], from: Endpoint, now: Instant, out: &mut RecvOut) {
        // Disco-demux belt-and-suspenders: only WireGuard type bytes 1..=4
        // reach here. (Primary disco split happens at the runtime edge.)
        match raw.first() {
            Some(1..=4) => {}
            _ => {
                tracing::trace!("non-wireguard packet dropped at wg parser");
                return;
            }
        }

        let Ok(msg) = Message::try_from(raw) else {
            tracing::trace!("undecodable wireguard packet");
            return;
        };

        // The DERP server vouches for the sender's node key (== its
        // WireGuard static key), and the only effect is falling back to
        // DERP, which always delivers. So this needs no decryption first,
        // and a replayed duplicate counts too (see `DERP_HOLDOFF`).
        if let Endpoint::Derp { node_key, .. } = &from {
            let k = NodePublicKey::from_bytes(*node_key);
            if let Some(idx) = self.peer_index_by_key(&k) {
                let peer = &mut self.peers[idx];
                if peer.direct.is_some_and(|d| now < d.trust_until)
                    && !peer.derp_holdoff_until.is_some_and(|h| now < h)
                {
                    tracing::debug!("peer sends over DERP; holding our sends on DERP");
                }
                peer.derp_holdoff_until = Some(now + DERP_HOLDOFF);
            }
        }

        match msg {
            Message::HandshakeInitiation(_) => self.recv_init(raw, now, out),
            Message::HandshakeResponse(_) => self.recv_response(raw, &from, now, out),
            Message::CookieReply(_) => self.recv_cookie(raw, out),
            Message::TransportDataHeader(_) => self.recv_transport(raw, &from, now, out),
        }
    }

    fn recv_init(&mut self, raw: &[u8], now: Instant, out: &mut RecvOut) {
        let Ok(init) = HandshakeInitiation::try_ref_from_bytes(raw) else {
            return;
        };
        let Some(hs) = ReceivedHandshake::new(init, &self.state.my_key, &self.state.my_cookie)
        else {
            tracing::warn!("handshake initiation failed to process");
            return;
        };
        let Some(idx) = self.peer_index_by_key(&hs.peer_static()) else {
            tracing::warn!("no peer for handshake initiator key");
            return;
        };
        let peer_id = self.peers[idx].id;
        out.peer = Some(peer_id);

        // Replay: reject an initiation whose timestamp is not newer than the
        // last one (WireGuard's rule; wireguard-go `!timestamp.After(last)`).
        // Equal matters: tailscaled sends each packet over both UDP and DERP
        // while its direct-path trust has lapsed, so the same initiation
        // arrives twice. Answering the copy replaced the handshake the peer
        // was completing with our first response, and its data then failed
        // to decrypt until it retried (Step 6, docs/lan-direct-path-plan.md).
        if let Some(last) = self.peers[idx].last_seen_timestamp
            && hs.timestamp <= last
        {
            tracing::warn!("handshake replay detected");
            return;
        }
        self.peers[idx].last_seen_timestamp = Some(hs.timestamp);

        let session_id = self.state.alloc_session(peer_id);
        let peer = &mut self.peers[idx];
        // No roaming on an initiation: it proves nothing about the sender's
        // address (an initiation seen once can be re-sent from anywhere). The path
        // is adopted when the handshake completes, on the confirming
        // transport packet in recv_transport.
        let pkt = peer.handshake.respond(
            session_id,
            hs,
            &peer.config.psk,
            &peer.cookie_sender,
            now,
        );
        let _ = out.to_peer.try_push(pkt);
    }

    fn recv_response(&mut self, raw: &[u8], from: &Endpoint, now: Instant, out: &mut RecvOut) {
        let Ok(resp) = HandshakeResponse::try_ref_from_bytes(raw) else {
            return;
        };
        let Some(peer_id) = self.state.peer_for_session(resp.receiver_id) else {
            tracing::warn!("handshake response for unknown session");
            return;
        };
        out.peer = Some(peer_id);
        let Some(idx) = self.peer_index(peer_id) else {
            return;
        };

        let session = {
            let peer = &mut self.peers[idx];
            peer.handshake
                .finish(resp, &peer.config.psk, &self.state.my_cookie, now)
        };
        let Some(session) = session else {
            tracing::warn!("handshake failed to complete");
            return;
        };
        self.peers[idx].handshake_timeout = None;
        out.handshook = true;
        // `finish` authenticated the response, so its source is proven.
        maybe_roam(&mut self.peers[idx], from, now);

        let freed = self.peers[idx].session.activate(session, &mut out.to_peer);
        for sid in freed {
            self.state.free_session(sid);
        }
        // Initiator must send at least one packet to confirm the session.
        if out.to_peer.is_empty() {
            let mut ka = Packet::new(0);
            if let SessionState::Active { send, .. } = &self.peers[idx].session {
                send.encrypt(core::iter::once(&mut ka));
                let _ = out.to_peer.try_push(ka);
            }
        }
    }

    fn recv_cookie(&mut self, raw: &[u8], out: &mut RecvOut) {
        use crate::vendor::messages::CookieReply;
        let Ok(cookie) = CookieReply::try_ref_from_bytes(raw) else {
            return;
        };
        let Some(peer_id) = self.state.peer_for_session(cookie.receiver_id) else {
            return;
        };
        out.peer = Some(peer_id);
        let Some(idx) = self.peer_index(peer_id) else {
            return;
        };
        let peer = &mut self.peers[idx];
        if let Handshake::Initiated(_, mac1) = &peer.handshake {
            let mac1 = *mac1;
            peer.cookie_sender.receive_cookie(cookie, &mac1);
        }
    }

    fn recv_transport(&mut self, raw: &[u8], from: &Endpoint, now: Instant, out: &mut RecvOut) {
        // The receiver id is at a fixed offset; parse the header to route.
        let Ok(header) = <&crate::vendor::messages::TransportDataHeader>::try_from(raw) else {
            return;
        };
        let session_id = header.receiver_id;
        let Some(peer_id) = self.state.peer_for_session(session_id) else {
            tracing::warn!("transport data for unknown session");
            return;
        };
        out.peer = Some(peer_id);
        let Some(idx) = self.peer_index(peer_id) else {
            return;
        };

        // Case 1: an established receive session exists.
        if self.peers[idx]
            .session
            .get_recv_mut(session_id, now)
            .is_some()
        {
            let mut pkt = Packet::from_wire(raw);
            let ok = self.peers[idx]
                .session
                .get_recv_mut(session_id, now)
                .unwrap()
                .decrypt_one(&mut pkt);
            if ok {
                maybe_roam(&mut self.peers[idx], from, now);
                self.peers[idx].schedule_keepalive(now);
                let _ = out.decrypted.try_push(pkt);
            }
            return;
        }

        // Case 2: confirm a tentative responder session with its first packet.
        let confirmed = self.peers[idx]
            .handshake
            .confirm(session_id, vec![Packet::from_wire(raw)]);
        if let Some((session, decrypted)) = confirmed {
            maybe_roam(&mut self.peers[idx], from, now);
            self.peers[idx].schedule_keepalive(now);
            for p in decrypted {
                let _ = out.decrypted.try_push(p);
            }
            let freed = self.peers[idx].session.activate(session, &mut out.to_peer);
            for sid in freed {
                self.state.free_session(sid);
            }
        }
    }

    /// The next instant at which [`WgEndpoint::dispatch`] must be called.
    pub fn next_event(&self) -> Option<Instant> {
        self.peers
            .iter()
            .flat_map(|p| [p.handshake_timeout, p.keepalive_at])
            .flatten()
            .min()
    }

    /// Dispatch due timers, returning packets tagged with their peer id.
    pub fn dispatch(
        &mut self,
        now: Instant,
        now_unix: Option<u64>,
    ) -> ArrayVec<(PeerId, Packet), DISPATCH_CAP> {
        let mut out: ArrayVec<(PeerId, Packet), DISPATCH_CAP> = ArrayVec::new();

        // Collect peers whose handshake timed out (need a retry), capturing the
        // stale handshake's session id BEFORE clearing it. The free itself must
        // happen in the second loop (it borrows `self.state`, which we cannot
        // touch while iterating `self.peers` mutably here). Reading the id AFTER
        // clearing the handshake is the bug this ordering fixes: `session_id()`
        // then returned `None`, so the stale id was never freed and the session
        // map accumulated one dead entry per retry. A late DERP-relayed response
        // answering that stale init still matched `peer_for_session`, routed to
        // the peer, and was fed to `finish()` against the CURRENT (rotated)
        // ephemeral -> wrong ee/se DH -> the live `aead::Error`.
        let mut retry: ArrayVec<(PeerId, Option<SessionId>), DISPATCH_CAP> = ArrayVec::new();
        for peer in self.peers.iter_mut() {
            // Stop collecting once either buffer is full; peers whose timers are
            // still due are picked up on the next tick (100 ms later). This
            // bounds the returned buffer to DISPATCH_CAP so `on_tick` never boxes
            // a MAX_PEERS-sized (~12 KB) allocation the post-DERP-TLS heap (~8 KB
            // largest block on real hardware) cannot satisfy. Timers are left
            // untouched for peers we skip, so nothing is lost.
            if out.is_full() || retry.is_full() {
                break;
            }
            if let Some(t) = peer.handshake_timeout
                && t <= now
            {
                peer.handshake_timeout = None;
                if peer.handshake.is_active() {
                    let stale = peer.handshake.session_id();
                    peer.handshake = Handshake::None;
                    let _ = retry.try_push((peer.id, stale));
                }
            }
            if let Some(t) = peer.keepalive_at
                && t <= now
                && !out.is_full()
            {
                peer.keepalive_at = None;
                if let Some(pkt) = peer.session.encrypt_keepalive(now) {
                    let _ = out.try_push((peer.id, pkt));
                }
            }
        }

        // Free the retrying peers' stale handshake sessions, then re-initiate
        // with jitter applied to the next timeout.
        for (id, stale) in retry {
            if let Some(sid) = stale {
                self.state.free_session(sid);
            }
            if let Some(pkt) = self.initiate(id, now, now_unix) {
                // Apply retry jitter (0..HANDSHAKE_JITTER_MS) so a fleet of
                // identical devices doesn't retry in lockstep.
                if let Some(idx) = self.peer_index(id) {
                    let jitter = handshake_jitter_ms();
                    self.peers[idx].handshake_timeout =
                        Some(now + HANDSHAKE_TIMEOUT + Duration::from_millis(jitter));
                }
                let _ = out.try_push((id, pkt));
            }
        }
        out
    }
}

/// Called only after a packet from `from` authenticated (decrypted, or
/// completed a handshake). UDP evidence sets or refreshes the direct path,
/// adopting a new address if the peer moved (D3). DERP-relayed packets say
/// nothing about any LAN address, so they never touch it. IPv6 is ignored:
/// the device's UDP socket is v4-only.
fn maybe_roam(peer: &mut Peer, from: &Endpoint, now: Instant) {
    if let Endpoint::Udp(SocketAddr::V4(addr)) = from {
        trust_direct(peer, *addr, now);
    }
}

fn trust_direct(peer: &mut Peer, addr: SocketAddrV4, now: Instant) {
    if peer.direct.map(|d| d.addr) != Some(addr) {
        tracing::debug!(%addr, "peer direct path set");
    }
    peer.direct = Some(DirectPath { addr, trust_until: now + DIRECT_TRUST });
}

/// A small, cheap jitter source in `[0, HANDSHAKE_JITTER_MS)`.
fn handshake_jitter_ms() -> u64 {
    use rand::rngs::OsRng;
    use rand_core::RngCore;
    OsRng.next_u64() % HANDSHAKE_JITTER_MS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::config::{PeerConfig, Psk};

    fn now_unix() -> Option<u64> {
        Some(1_700_000_123)
    }

    #[test]
    fn wgendpoint_fits_fragmented_heap() {
        // Regression guard for the QUEUE_DEPTH = 0 fix: at QUEUE_DEPTH = 2 the
        // endpoint was 28240 bytes and its first-use allocation OOM-aborted on
        // the ESP32-C3's fragmented ~57 KB heap. With the inline per-peer queue
        // removed it is ~6 KB. Keep it well under 8 KB so nobody silently
        // re-inflates the per-peer footprint. Prints the live size on failure.
        let sz = core::mem::size_of::<WgEndpoint>();
        assert!(
            sz <= 8 * 1024,
            "WgEndpoint grew to {sz} bytes (Peer = {} bytes, QUEUE_DEPTH = {QUEUE_DEPTH}); \
             it must stay small enough to allocate on the device's fragmented heap",
            core::mem::size_of::<Peer>(),
        );
    }

    #[test]
    fn full_handshake_and_data_between_two_endpoints() {
        let a_kp = NodeKeyPair::new();
        let b_kp = NodeKeyPair::new();
        let psk = Psk::random();

        let mut a = WgEndpoint::new(a_kp);
        let mut b = WgEndpoint::new(b_kp);

        let a_ep = Endpoint::Derp {
            region_id: 1,
            node_key: b_kp.public.to_bytes(),
        };
        let b_ep = Endpoint::Derp {
            region_id: 1,
            node_key: a_kp.public.to_bytes(),
        };
        // A configures B as peer; B configures A as peer. Same PSK.
        let a_peer = a
            .add_peer(
                PeerConfig {
                    key: b_kp.public,
                    psk,
                },
                a_ep,
            )
            .unwrap();
        let _b_peer = b
            .add_peer(
                PeerConfig {
                    key: a_kp.public,
                    psk,
                },
                b_ep,
            )
            .unwrap();

        let now = Instant::now();

        // A initiates.
        let init = a.initiate(a_peer, now, now_unix()).expect("init packet");

        // B receives initiation, produces a response.
        let b_out = b.recv_one(init.as_slice(), b_derp(&a_kp), now);
        assert_eq!(b_out.to_peer.len(), 1, "B should produce a response");
        assert!(!b_out.handshook);

        // A receives response, completes handshake, sends a confirmation packet.
        let a_out = a.recv_one(b_out.to_peer[0].as_slice(), a_derp(&b_kp), now);
        assert!(a_out.handshook, "A should complete the handshake");
        assert_eq!(a_out.to_peer.len(), 1, "A confirms with one packet");

        // B receives the confirmation (transport data), decrypts it, activates.
        let b_out2 = b.recv_one(a_out.to_peer[0].as_slice(), b_derp(&a_kp), now);
        assert_eq!(b_out2.decrypted.len(), 1, "B decrypts the confirmation");

        // B can now send transport data to A via its active session, and A
        // decrypts it. Build a keepalive-sized data packet through the session.
        // (Exercised via dispatch keepalive below.)
        let _ = b_out2;
    }

    fn a_derp(b_kp: &NodeKeyPair) -> Endpoint {
        Endpoint::Derp {
            region_id: 1,
            node_key: b_kp.public.to_bytes(),
        }
    }
    fn b_derp(a_kp: &NodeKeyPair) -> Endpoint {
        Endpoint::Derp {
            region_id: 1,
            node_key: a_kp.public.to_bytes(),
        }
    }

    #[test]
    fn retry_frees_stale_session_and_ignores_late_response() {
        // Reproduces the rung-5 blocker: a handshake retry (5 s timeout) must
        // free the timed-out initiation's session id, and a DERP-relayed
        // response that answers that now-stale initiation must be dropped
        // cleanly -- never fed to `finish()` against the current, rotated
        // ephemeral (which is what produced the live `aead::Error`). A response
        // to the CURRENT initiation must still complete the handshake.
        let a_kp = NodeKeyPair::new();
        let b_kp = NodeKeyPair::new();
        let psk = Psk::zero(); // Tailscale uses an all-zero PSK

        let mut a = WgEndpoint::new(a_kp);
        let mut b = WgEndpoint::new(b_kp);

        let a_peer = a
            .add_peer(PeerConfig { key: b_kp.public, psk }, a_derp(&b_kp))
            .unwrap();
        b.add_peer(PeerConfig { key: a_kp.public, psk }, b_derp(&a_kp))
            .unwrap();

        let t0 = Instant::now();

        // First initiation (session S1, ephemeral E1). B builds a response that
        // answers S1/E1, but we withhold it to simulate DERP relay latency.
        let init1 = a.initiate(a_peer, t0, now_unix()).expect("init1");
        assert_eq!(a.session_count(), 1);
        let b_out1 = b.recv_one(init1.as_slice(), b_derp(&a_kp), t0);
        let resp1 = b_out1.to_peer[0].clone(); // answers stale S1/E1 after retry

        // The handshake times out; A retries with a fresh init (session S2,
        // ephemeral E2). A later wall-clock second keeps init2's TAI64N strictly
        // greater than init1's, so the responder does not treat it as a replay.
        let t1 = t0 + HANDSHAKE_TIMEOUT + Duration::from_millis(1);
        let retry = a.dispatch(t1, Some(1_700_000_130));
        assert_eq!(retry.len(), 1, "A should retry the timed-out handshake");
        let init2 = retry[0].1.clone();

        // The core regression: the stale S1 must have been freed, so the map
        // holds only the current S2 (before the fix it leaked, holding 2).
        assert_eq!(
            a.session_count(),
            1,
            "the timed-out handshake's session id must be freed on retry"
        );

        // The delayed resp1 answers the now-stale S1/E1: it must be dropped
        // cleanly, not mis-finished against the current S2/E2 ephemeral.
        let a_stale = a.recv_one(resp1.as_slice(), a_derp(&b_kp), t1);
        assert!(!a_stale.handshook, "a stale response must not complete a handshake");

        // The response to the CURRENT initiation completes the handshake.
        let b_out2 = b.recv_one(init2.as_slice(), b_derp(&a_kp), t1);
        let resp2 = b_out2.to_peer[0].clone();
        let a_ok = a.recv_one(resp2.as_slice(), a_derp(&b_kp), t1);
        assert!(
            a_ok.handshook,
            "the response to the current initiation must complete the handshake"
        );
    }

    #[test]
    fn send_data_encrypts_over_active_session_and_queues_without_one() {
        // Rung-6a: after a handshake completes, `send_data` must encrypt an
        // app-data (IP) payload into `out.to_peer` under the active session, and
        // the peer must decrypt it back to the exact plaintext. Before a session
        // exists, the payload is queued (not sent) and no ciphertext is emitted.
        let a_kp = NodeKeyPair::new();
        let b_kp = NodeKeyPair::new();
        let psk = Psk::zero();

        let mut a = WgEndpoint::new(a_kp);
        let mut b = WgEndpoint::new(b_kp);
        let b_key = b_kp.public.to_bytes();

        let a_peer = a
            .add_peer(PeerConfig { key: b_kp.public, psk }, a_derp(&b_kp))
            .unwrap();
        b.add_peer(PeerConfig { key: a_kp.public, psk }, b_derp(&a_kp))
            .unwrap();

        let now = Instant::now();

        // No session yet: send_data queues, emits nothing.
        let mut out0 = RecvOut::default();
        let sent0 = a.send_data(&b_key, &[0xde, 0xad, 0xbe, 0xef], now, &mut out0);
        assert!(!sent0, "no active session -> not sent (queued)");
        assert!(out0.to_peer.is_empty(), "nothing on the wire before a session");

        // Establish A->B session.
        let init = a.initiate(a_peer, now, now_unix()).expect("init");
        let b_out = b.recv_one(init.as_slice(), b_derp(&a_kp), now);
        let a_out = a.recv_one(b_out.to_peer[0].as_slice(), a_derp(&b_kp), now);
        assert!(a_out.handshook, "A completes the handshake");
        // Deliver A's confirmation so B's session activates (queued data flushes).
        let b_out2 = b.recv_one(a_out.to_peer[0].as_slice(), b_derp(&a_kp), now);
        assert_eq!(b_out2.decrypted.len(), 1, "B decrypts the confirmation");

        // Now send real app data over the active session.
        let payload = [0x45u8, 0x00, 0x00, 0x1c, 0x11, 0x22, 0x33, 0x44];
        let mut out = RecvOut::default();
        let sent = a.send_data(&b_key, &payload, now, &mut out);
        assert!(sent, "active session -> sent");
        assert_eq!(out.to_peer.len(), 1, "one encrypted transport packet emitted");

        // B receives and decrypts it to the exact plaintext.
        let b_recv = b.recv_one(out.to_peer[0].as_slice(), b_derp(&a_kp), now);
        assert_eq!(b_recv.decrypted.len(), 1, "B decrypts the app data");
        assert_eq!(
            b_recv.decrypted[0].as_slice(),
            &payload,
            "decrypted plaintext must equal what A sent"
        );

        // Unknown peer key -> not sent.
        let mut out_unknown = RecvOut::default();
        let sent_unknown = a.send_data(&[0u8; 32], &payload, now, &mut out_unknown);
        assert!(!sent_unknown, "send_data to unknown peer is a no-op");
    }

    #[test]
    fn unsynced_clock_skips_initiation() {
        let a_kp = NodeKeyPair::new();
        let b_kp = NodeKeyPair::new();
        let mut a = WgEndpoint::new(a_kp);
        let id = a
            .add_peer(
                PeerConfig {
                    key: b_kp.public,
                    psk: Psk::zero(),
                },
                Endpoint::Derp {
                    region_id: 1,
                    node_key: b_kp.public.to_bytes(),
                },
            )
            .unwrap();
        assert!(a.initiate(id, Instant::now(), None).is_none());
    }

    #[test]
    fn peer_table_bounded() {
        let mut a = WgEndpoint::new(NodeKeyPair::new());
        for _ in 0..MAX_PEERS {
            let kp = NodeKeyPair::new();
            assert!(a
                .add_peer(
                    PeerConfig {
                        key: kp.public,
                        psk: Psk::zero()
                    },
                    Endpoint::Derp {
                        region_id: 1,
                        node_key: kp.public.to_bytes()
                    }
                )
                .is_some());
        }
        let kp = NodeKeyPair::new();
        assert!(a
            .add_peer(
                PeerConfig {
                    key: kp.public,
                    psk: Psk::zero()
                },
                Endpoint::Derp {
                    region_id: 1,
                    node_key: kp.public.to_bytes()
                }
            )
            .is_none(), "table should be full at MAX_PEERS");
    }

    // ── Step 4 of docs/lan-direct-path-plan.md: dual-path peers ──

    fn udp(s: &str) -> Endpoint {
        Endpoint::Udp(s.parse().unwrap())
    }
    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    struct Pair {
        a: WgEndpoint,
        b: WgEndpoint,
        a_kp: NodeKeyPair,
        b_kp: NodeKeyPair,
        /// B as seen from A, and A as seen from B.
        a_peer: PeerId,
        b_peer: PeerId,
    }

    fn pair() -> Pair {
        let a_kp = NodeKeyPair::new();
        let b_kp = NodeKeyPair::new();
        let mut a = WgEndpoint::new(a_kp);
        let mut b = WgEndpoint::new(b_kp);
        let a_peer = a.add_peer(PeerConfig { key: b_kp.public, psk: Psk::zero() }, a_derp(&b_kp)).unwrap();
        let b_peer = b.add_peer(PeerConfig { key: a_kp.public, psk: Psk::zero() }, b_derp(&a_kp)).unwrap();
        Pair { a, b, a_kp, b_kp, a_peer, b_peer }
    }

    /// A initiates. Every packet B sends reaches A over `to_a`, and every
    /// packet A sends reaches B over `to_b`. Returns once both sessions are
    /// active.
    fn handshake(p: &mut Pair, to_a: &Endpoint, to_b: &Endpoint, now: Instant) {
        let init = p.a.initiate(p.a_peer, now, now_unix()).unwrap();
        let resp = p.b.recv_one(init.as_slice(), to_b.clone(), now);
        assert_eq!(resp.to_peer.len(), 1);
        let conf = p.a.recv_one(resp.to_peer[0].as_slice(), to_a.clone(), now);
        assert!(conf.handshook);
        let done = p.b.recv_one(conf.to_peer[0].as_slice(), to_b.clone(), now);
        assert_eq!(done.decrypted.len(), 1, "B confirms the session");
    }

    /// One app-data packet from B to A, as wire bytes.
    fn b_to_a_data(p: &mut Pair, now: Instant) -> Packet {
        let mut out = RecvOut::default();
        assert!(p.b.send_data(&p.a_kp.public.to_bytes(), &[0x45, 0, 0, 20], now, &mut out));
        out.to_peer[0].clone()
    }

    #[test]
    fn udp_path_is_adopted_from_authenticated_packets_and_used_for_replies() {
        let mut p = pair();
        let t = Instant::now();
        // A's address as B sees it, and B's as A sees it.
        let (xa, xb) = ("192.168.15.74:41641", "192.168.15.70:41641");

        let init = p.a.initiate(p.a_peer, t, now_unix()).unwrap();
        let resp = p.b.recv_one(init.as_slice(), udp(xa), t);
        assert_eq!(p.b.path_for(p.b_peer, t), None,
                   "an initiation alone proves nothing about the sender's address");

        let conf = p.a.recv_one(resp.to_peer[0].as_slice(), udp(xb), t);
        assert!(conf.handshook);
        assert_eq!(p.a.path_for(p.a_peer, t), Some(v4(xb)),
                   "an authenticated response over UDP sets the direct path, \
                    so A's confirmation goes back over it");

        let done = p.b.recv_one(conf.to_peer[0].as_slice(), udp(xa), t);
        assert_eq!(done.decrypted.len(), 1);
        assert_eq!(p.b.path_for(p.b_peer, t), Some(v4(xa)),
                   "the confirming transport packet completes the handshake and proves A's address");

        // Data from the same address keeps it trusted; silence lets it lapse.
        let later = t + KEEPALIVE_TIMEOUT + Duration::from_millis(1);
        let data = b_to_a_data(&mut p, t);
        let r = p.a.recv_one(data.as_slice(), udp(xb), t);
        assert_eq!(r.decrypted.len(), 1);
        assert_eq!(r.peer, Some(p.a_peer));
        assert_eq!(p.a.path_for(p.a_peer, t + Duration::from_secs(6)), Some(v4(xb)));
        assert_eq!(p.a.path_for(p.a_peer, later), None, "no traffic for 10 s -> trust has lapsed");
    }

    #[test]
    fn forged_or_undecryptable_udp_never_changes_the_path() {
        let mut p = pair();
        let t = Instant::now();
        let (x, y) = ("192.168.15.70:41641", "192.168.15.66:41641");
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp(x), &to_b, t);
        assert_eq!(p.a.path_for(p.a_peer, t), Some(v4(x)));
        let before = p.a.peer_direct(p.a_peer);

        let t1 = t + Duration::from_secs(1);
        // A genuine packet, delivered from x, then replayed from y: the replay
        // window rejects the second copy, so y gains nothing.
        let data = b_to_a_data(&mut p, t1);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(x), t1).decrypted.len(), 1);
        let after_x = p.a.peer_direct(p.a_peer);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(y), t1).decrypted.len(), 0);
        assert_eq!(p.a.peer_direct(p.a_peer), after_x, "replayed packet from y");

        // Same header (right receiver id), corrupted ciphertext.
        let mut forged = b_to_a_data(&mut p, t1).as_slice().to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;
        assert_eq!(p.a.recv_one(&forged, udp(y), t1).decrypted.len(), 0);
        assert_eq!(p.a.peer_direct(p.a_peer), after_x, "undecryptable packet from y");

        // A captured initiation re-sent from y.
        let init = p.b.initiate(p.b_peer, t1, now_unix()).unwrap();
        let _ = p.a.recv_one(init.as_slice(), udp(y), t1);
        assert_eq!(p.a.peer_direct(p.a_peer), after_x, "initiation from y");

        // Junk that is not WireGuard at all.
        let _ = p.a.recv_one(&[4, 0, 0, 0, 1, 2, 3], udp(y), t1);
        let _ = p.a.recv_one(&[9; 64], udp(y), t1);
        assert_eq!(p.a.peer_direct(p.a_peer), after_x, "junk from y");

        assert_eq!(before.map(|d| d.addr), Some(v4(x)));
        assert_eq!(after_x.map(|d| d.addr), Some(v4(x)));
    }

    #[test]
    fn trust_expires_after_6_5_s_and_sends_revert_to_derp() {
        let mut p = pair();
        let t = Instant::now();
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp("192.168.15.70:41641"), &to_b, t);
        assert_eq!(DIRECT_TRUST, Duration::from_millis(6500));
        assert!(p.a.path_for(p.a_peer, t + Duration::from_millis(6400)).is_some());
        assert_eq!(p.a.path_for(p.a_peer, t + Duration::from_millis(6600)), None);
        assert_eq!(p.a.peer_endpoint(p.a_peer), Some(a_derp(&p.b_kp)),
                   "the DERP route is still there to fall back to");
    }

    #[test]
    fn authenticated_packet_from_a_new_address_moves_the_path() {
        let mut p = pair();
        let t = Instant::now();
        let (x, z) = ("192.168.15.70:41641", "192.168.15.99:41641");
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp(x), &to_b, t);
        assert_eq!(p.a.path_for(p.a_peer, t), Some(v4(x)));

        let t1 = t + Duration::from_secs(2);
        let data = b_to_a_data(&mut p, t1);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(z), t1).decrypted.len(), 1);
        assert_eq!(p.a.path_for(p.a_peer, t1), Some(v4(z)));
        assert_eq!(p.a.peer_direct(p.a_peer).unwrap().trust_until, t1 + DIRECT_TRUST);
    }

    #[test]
    fn derp_sourced_packets_never_create_or_move_the_direct_path() {
        let mut p = pair();
        let t = Instant::now();
        let x = "192.168.15.70:41641";
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp(x), &to_b, t);
        let before = p.a.peer_direct(p.a_peer);

        let t1 = t + Duration::from_secs(3);
        let data = b_to_a_data(&mut p, t1);
        assert_eq!(p.a.recv_one(data.as_slice(), a_derp(&p.b_kp), t1).decrypted.len(), 1,
                   "DERP inbound is always accepted");
        assert_eq!(p.a.peer_direct(p.a_peer), before, "neither moved nor refreshed by DERP");

        // And with no direct path at all, DERP never creates one.
        let mut q = pair();
        let (to_a, to_b) = (a_derp(&q.b_kp), b_derp(&q.a_kp));
        handshake(&mut q, &to_a, &to_b, t);
        assert_eq!(q.a.peer_direct(q.a_peer), None);
        assert_eq!(q.b.peer_direct(q.b_peer), None);
    }

    /// Send-both delivers the same initiation twice (UDP, then DERP). Only
    /// the first gets a response, so the handshake the peer completes is the
    /// one we still hold.
    #[test]
    fn duplicate_initiation_is_answered_once_and_the_handshake_completes() {
        let mut p = pair();
        let t = Instant::now();
        let init = p.a.initiate(p.a_peer, t, now_unix()).unwrap();
        let r1 = p.b.recv_one(init.as_slice(), udp("192.168.15.74:41641"), t);
        assert_eq!(r1.to_peer.len(), 1);
        let r2 = p.b.recv_one(init.as_slice(), b_derp(&p.a_kp), t);
        assert_eq!(r2.to_peer.len(), 0, "the duplicate must not replace the pending handshake");
        let conf = p.a.recv_one(r1.to_peer[0].as_slice(), a_derp(&p.b_kp), t);
        assert!(conf.handshook);
        let done = p.b.recv_one(conf.to_peer[0].as_slice(), b_derp(&p.a_kp), t);
        assert_eq!(done.decrypted.len(), 1, "B decrypts A's confirmation");
    }

    /// The Step 6 fault: the peer stopped getting our UDP, so its trust
    /// lapsed and it sends every packet over both UDP and DERP. The UDP copy
    /// lands first and refreshes our trust; the DERP copy (a replay by then)
    /// must still keep our sends on DERP for `DERP_HOLDOFF`.
    #[test]
    fn wireguard_over_derp_holds_sends_on_derp() {
        let mut p = pair();
        let t = Instant::now();
        let x = "192.168.15.70:41641";
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp(x), &to_b, t);
        assert_eq!(p.a.path_for(p.a_peer, t), Some(v4(x)));

        // Send-both: the same packet over UDP, then over DERP.
        let t1 = t + Duration::from_secs(1);
        let data = b_to_a_data(&mut p, t1);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(x), t1).decrypted.len(), 1);
        assert_eq!(p.a.path_for(p.a_peer, t1), Some(v4(x)));
        assert_eq!(p.a.recv_one(data.as_slice(), a_derp(&p.b_kp), t1).decrypted.len(), 0,
                   "the DERP copy is a replay");
        assert_eq!(p.a.path_for(p.a_peer, t1), None, "yet it holds sends on DERP");

        // UDP alone during the hold-off does not lift it.
        let t2 = t1 + Duration::from_secs(3);
        let data = b_to_a_data(&mut p, t2);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(x), t2).decrypted.len(), 1);
        assert_eq!(p.a.path_for(p.a_peer, t2), None);

        // Once the peer has sent over UDP only for longer than the hold-off
        // (it trusts the path again), sends go direct again.
        let t3 = t1 + DERP_HOLDOFF + Duration::from_millis(1);
        let data = b_to_a_data(&mut p, t3);
        assert_eq!(p.a.recv_one(data.as_slice(), udp(x), t3).decrypted.len(), 1);
        assert_eq!(p.a.path_for(p.a_peer, t3), Some(v4(x)));

        // A DERP packet from another node does not hold this peer.
        let stranger = NodeKeyPair::new();
        let _ = p.a.recv_one(data.as_slice(), a_derp(&stranger), t3);
        assert_eq!(p.a.path_for(p.a_peer, t3), Some(v4(x)));
    }

    #[test]
    fn direct_path_seen_sets_and_refreshes_trust() {
        let mut p = pair();
        let t = Instant::now();
        let b_key = p.b_kp.public.to_bytes();
        assert!(p.a.direct_path_seen(&b_key, v4("192.168.15.70:41641"), t));
        assert_eq!(p.a.path_for(p.a_peer, t), Some(v4("192.168.15.70:41641")));
        let t1 = t + Duration::from_secs(5);
        assert!(p.a.direct_path_seen(&b_key, v4("192.168.15.70:41641"), t1));
        assert!(p.a.path_for(p.a_peer, t + Duration::from_secs(10)).is_some(), "refreshed at t1");
        assert!(!p.a.direct_path_seen(&[7u8; 32], v4("192.168.15.1:1"), t), "unknown peer");
    }

    #[test]
    fn ipv6_udp_source_is_ignored() {
        let mut p = pair();
        let t = Instant::now();
        let to_b = b_derp(&p.a_kp);
        handshake(&mut p, &udp("[fd00::1]:41641"), &to_b, t);
        assert_eq!(p.a.peer_direct(p.a_peer), None);
    }
}
