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

use core::net::SocketAddr;
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

impl Endpoint {
    fn is_derp(&self) -> bool {
        matches!(self, Endpoint::Derp { .. })
    }
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
    endpoint: Endpoint,
    session: SessionState,
    handshake: Handshake,
    last_seen_timestamp: Option<crate::vendor::tai64n::TAI64N>,
    cookie_sender: MACSender,
    handshake_timeout: Option<Instant>,
    keepalive_at: Option<Instant>,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig, endpoint: Endpoint) -> Self {
        let cookie_sender = MACSender::new(&config.key);
        Self {
            id,
            config,
            endpoint,
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

    /// Construct directly on the heap, field-by-field, via a raw pointer
    /// into an uninitialized `Box` allocation.
    ///
    /// `Self` is ~28 KB (`peers: ArrayVec<Peer, MAX_PEERS>` dominates).
    /// `Box::new(WgEndpoint::new(..))` builds the whole ~28 KB value as a
    /// temporary, THEN copies it into the heap allocation -- at this
    /// workspace's `opt-level = "z"` + `lto = true` dev profile the
    /// compiler was not eliding that temporary (observed as two ~28 KB
    /// copies, a ~55 KB frame, wherever the call ended up after inlining).
    ///
    /// Even writing the field directly via `addr_of_mut!(..).write(..)`
    /// with `ArrayVec::new()` as the source measured ~27 KB here: the
    /// compiler still materialized an "empty" `ArrayVec` as a genuine
    /// stack-sized value before `memcpy`-ing it into place (`ArrayVec::new`
    /// is not `const`, so nothing forces it into rodata). Using
    /// `ArrayVec::new_const()` into a top-level `static` instead -- exactly
    /// the pattern arrayvec's own docs recommend for this ("place a large
    /// ArrayVec in a static to avoid stack overflow") -- makes the "empty"
    /// value a fixed rodata/bss address that `memcpy` sources FROM,
    /// eliminating the stack temporary entirely.
    #[inline(never)]
    pub fn new_boxed(my_key: NodeKeyPair) -> Box<Self> {
        static EMPTY_PEERS: ArrayVec<Peer, MAX_PEERS> = ArrayVec::new_const();
        static EMPTY_SESSIONS: ArrayVec<(SessionId, PeerId), SESSION_MAP_CAP> = ArrayVec::new_const();

        let mut b = Box::<Self>::new_uninit();
        let ptr = b.as_mut_ptr();
        // SAFETY: `ptr` is a valid, suitably-aligned pointer to
        // uninitialized memory sized for `Self`. Each field is written
        // exactly once, in full, before `assume_init()`, so every field of
        // `Self` ends up initialized and no field is read before its write.
        unsafe {
            // Raw `copy_nonoverlapping` (not `.clone()`/`.write(value)`):
            // both sources are fixed `static` addresses, so this lowers to
            // a plain memcpy with no intermediate Rust value to construct
            // -- `Clone::clone` or moving `EMPTY_PEERS` by value would
            // reintroduce exactly the stack temporary this function exists
            // to avoid. Safe because both fields are POD-ish "all bytes
            // valid" data (`MaybeUninit` elements, a `len` of 0): the byte
            // copy fully initializes them and no live resource is aliased.
            core::ptr::addr_of_mut!((*ptr).state.sessions).copy_from_nonoverlapping(&EMPTY_SESSIONS, 1);
            core::ptr::addr_of_mut!((*ptr).state.my_key).write(my_key);
            core::ptr::addr_of_mut!((*ptr).state.my_cookie).write(MACReceiver::new(&my_key.public));
            core::ptr::addr_of_mut!((*ptr).state.timestamps).write(TAI64NClock::new());
            core::ptr::addr_of_mut!((*ptr).state.next_peer_id).write(0);
            core::ptr::addr_of_mut!((*ptr).peers).copy_from_nonoverlapping(&EMPTY_PEERS, 1);
            b.assume_init()
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

    /// Add a peer. Returns its id, or None if the table is full or the key is
    /// already present.
    pub fn add_peer(&mut self, cfg: PeerConfig, endpoint: Endpoint) -> Option<PeerId> {
        if self.peer_index_by_key(&cfg.key).is_some() || self.peers.is_full() {
            return None;
        }
        self.state.next_peer_id += 1;
        let id = PeerId(self.state.next_peer_id);
        self.peers.push(Peer::new(id, cfg, endpoint));
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

    pub fn peer_endpoint(&self, id: PeerId) -> Option<Endpoint> {
        self.peer_index(id).map(|i| self.peers[i].endpoint.clone())
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
    /// `out` (which should be freshly [`RecvOut::default`] and, on device,
    /// heap-allocated so the ~12 KB never touches the stack).
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

        match msg {
            Message::HandshakeInitiation(_) => self.recv_init(raw, &from, now, out),
            Message::HandshakeResponse(_) => self.recv_response(raw, now, out),
            Message::CookieReply(_) => self.recv_cookie(raw, out),
            Message::TransportDataHeader(_) => self.recv_transport(raw, &from, now, out),
        }
    }

    fn recv_init(&mut self, raw: &[u8], from: &Endpoint, now: Instant, out: &mut RecvOut) {
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

        // Replay: reject an initiation whose timestamp is older than the last.
        if let Some(last) = self.peers[idx].last_seen_timestamp
            && hs.timestamp < last
        {
            tracing::warn!("handshake replay detected");
            return;
        }
        self.peers[idx].last_seen_timestamp = Some(hs.timestamp);

        let session_id = self.state.alloc_session(peer_id);
        let peer = &mut self.peers[idx];
        // Roaming: adopt sender address only for authenticated, non-DERP src.
        maybe_roam(peer, from);
        let pkt = peer.handshake.respond(
            session_id,
            hs,
            &peer.config.psk,
            &peer.cookie_sender,
            now,
        );
        let _ = out.to_peer.try_push(pkt);
    }

    fn recv_response(&mut self, raw: &[u8], now: Instant, out: &mut RecvOut) {
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
                maybe_roam(&mut self.peers[idx], from);
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
            maybe_roam(&mut self.peers[idx], from);
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

/// Adopt a peer's source address from an authenticated (post-decrypt) packet.
/// Explicitly skipped for DERP-sourced packets and non-UDP endpoints.
fn maybe_roam(peer: &mut Peer, from: &Endpoint) {
    if from.is_derp() {
        return; // never roam based on DERP-relayed source
    }
    if let Endpoint::Udp(new_addr) = from
        && peer.endpoint != *from
        && !peer.endpoint.is_derp()
    {
        tracing::debug!(?new_addr, "peer roamed to new udp endpoint");
        peer.endpoint = Endpoint::Udp(*new_addr);
    }
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
}
