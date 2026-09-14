//! WireGuard peer management actor.
//!
//! Rather than reimplementing the WireGuard handshake in Rust (which would add
//! ~20 KB of code), this module wraps the battle-tested `wireguard-lwip` C
//! library via ESP-IDF component system.  On the host (for testing), a stub
//! implementation is used.
//!
//! ## Peer table
//!
//! A static array of `MAX_PEERS` entries avoids any heap allocation for
//! the peer table.  At ~200 bytes/peer and MAX_PEERS=8, total cost is 1.6 KB.
//!
//! From MicroLink: peers beyond `MAX_PEERS` trigger LRU eviction, with a
//! configurable "priority peer" that is never evicted.

use arrayvec::ArrayVec;
use tm_control::{MapState, PeerInfo, TailnetIp};
use tm_keys::NodePublicKey;
use async_channel;

pub const MAX_PEERS: usize = 8;

// ── Peer state ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct WgPeerState {
    pub node_key:   [u8; 32],
    pub tailnet_ip: TailnetIp,
    /// Is the WireGuard session for this peer currently active?
    pub active:     bool,
    /// Last seen timestamp (used for LRU eviction).
    pub last_seen:  u64,
}

// ── FFI declarations (wireguard-lwip) ─────────────────────────────────────────
//
// On ESP32-C3 these link against the wireguard-lwip ESP-IDF component.
// If wireguard-lwip is not available (wireguard_stub cfg), use no-op stubs.
//
// The build.rs sets wireguard_stub when wireguard-lwip is not available.


// Stub implementation when wireguard-lwip is not available
#[cfg(all(target_os = "espidf", wireguard_stub))]
mod ffi {
    #[repr(C)]
    pub struct WgPeerC {
        pub public_key:    [u8; 32],
        pub preshared_key: [u8; 32],
        pub allowed_ip:    u32,
        pub allowed_mask:  u32,
        pub endpoint_ip:   u32,
        pub endpoint_port: u16,
    }

    pub fn wireguard_setup(_: *const ()) -> i32 { 0 }
    pub fn wireguard_add_peer(peer: *const WgPeerC) -> i32 { 0 }
    pub fn wireguard_remove_peer(pubkey: *const u8) -> i32 { 0 }
    pub fn wireguard_is_peer_active(pubkey: *const u8) -> bool { false }
}

// Real FFI when wireguard-lwip IS available (not stubbed)
#[cfg(all(target_os = "espidf", not(wireguard_stub)))]
mod ffi {
    extern "C" {
        pub fn wireguard_setup(config: *const ()) -> i32;
        pub fn wireguard_add_peer(peer: *const WgPeerC) -> i32;
        pub fn wireguard_remove_peer(pubkey: *const u8) -> i32;
        pub fn wireguard_is_peer_active(pubkey: *const u8) -> bool;
    }

    #[repr(C)]
    pub struct WgPeerC {
        pub public_key:    [u8; 32],
        pub preshared_key: [u8; 32],
        pub allowed_ip:    u32,
        pub allowed_mask:  u32,
        pub endpoint_ip:   u32,
        pub endpoint_port: u16,
    }
}

// ── Message types ─────────────────────────────────────────────────────────────

pub enum WgCmd {
    /// Apply a fresh MapState — add new peers, remove gone ones.
    ///
    /// Boxed: `async_channel`'s unbounded ring buffer (`concurrent-queue`)
    /// reserves 31 slots per block and returns each block by value, so an
    /// unboxed ~1.5KB variant here balloons the caller's stack frame (the
    /// combined `tokio::join!()` poll function in `tm_runtime::Runtime::join`)
    /// by 31x, even though these channels are actually bounded and this path
    /// never runs. See tailmicro-rs commit fixing the ESP32-C3 stack overflow
    /// at Runtime::join()'s tokio::join! entry.
    ApplyMap(Box<MapState<MAX_PEERS, 4>>),
    /// Route an incoming WireGuard packet from DERP.
    InboundPacket {
        src_key: [u8; 32],
        payload: Box<heapless::Vec<u8, 1500>>,
    },
    Shutdown,
}

pub enum WgEvent {
    /// An outbound packet to send via DERP.
    OutboundPacket {
        dst_key: [u8; 32],
        payload: Box<heapless::Vec<u8, 1500>>,
    },
    /// A WireGuard handshake completed.
    PeerHandshook([u8; 32]),
}

// ── WgActor ───────────────────────────────────────────────────────────────────

pub struct WgActor {
    peers:          ArrayVec<WgPeerState, MAX_PEERS>,
    /// If set, this peer is never evicted (MicroLink: priority_peer).
    priority_peer:  Option<[u8; 32]>,
}

impl WgActor {
    pub fn new(priority_peer: Option<[u8; 32]>) -> Self {
        Self {
            peers: ArrayVec::new(),
            priority_peer,
        }
    }

    pub async fn run(
        mut self,
        mut cmds:  async_channel::Receiver<WgCmd>,
        events:    async_channel::Sender<WgEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Ok(WgCmd::ApplyMap(map)) => {
                    self.apply_map(&map);
                }
                Ok(WgCmd::InboundPacket { src_key, payload }) => {
                    // Route to wireguard-lwip (lwIP handles the actual packet)
                    // wireguard-lwip injects the decrypted packet into lwIP's
                    // packet processing pipeline directly.
                }
                Ok(WgCmd::Shutdown) | Err(_) => break,
            }
        }
    }

    fn apply_map(&mut self, map: &MapState<MAX_PEERS, 4>) {
        // 1. Remove peers no longer in the map
        let new_keys: ArrayVec<[u8; 32], MAX_PEERS> =
            map.peers.iter().map(|p| p.node_key).collect();

        let to_remove: ArrayVec<[u8; 32], MAX_PEERS> = self.peers.iter()
            .filter(|p| !new_keys.contains(&p.node_key))
            .map(|p| p.node_key)
            .collect();

        for key in &to_remove {
            self.remove_peer(key);
        }

        // 2. Add new peers
        for peer in &map.peers {
            if !self.peers.iter().any(|p| p.node_key == peer.node_key) {
                self.add_peer(peer);
            }
        }
    }

    fn add_peer(&mut self, peer: &PeerInfo) {
        // LRU eviction when table is full (MicroLink pattern)
        if self.peers.is_full() {
            self.evict_lru();
        }

        if self.peers.is_full() {
            // Still full — all slots are priority peers or eviction failed
            return;
        }

        self.peers.push(WgPeerState {
            node_key:   peer.node_key,
            tailnet_ip: peer.tailnet_ip.clone(),
            active:     false,
            last_seen:  0,
        });

        // Call wireguard-lwip to register the peer
        #[cfg(target_os = "espidf")]
        unsafe {
            let peer_c = ffi::WgPeerC {
                public_key:    peer.node_key,
                preshared_key: [0u8; 32],
                allowed_ip:    u32::from_ne_bytes(peer.tailnet_ip.0),
                allowed_mask:  0xFFFFFFFF, // /32
                endpoint_ip:   0,          // DERP-routed, no direct endpoint
                endpoint_port: 0,
            };
            ffi::wireguard_add_peer(&peer_c as *const _);
        }
    }

    fn remove_peer(&mut self, key: &[u8; 32]) {
        self.peers.retain(|p| &p.node_key != key);
        #[cfg(target_os = "espidf")]
        unsafe { ffi::wireguard_remove_peer(key.as_ptr()); }
    }

    fn evict_lru(&mut self) {
        // Find the oldest non-priority peer
        let evict_idx = self.peers.iter().enumerate()
            .filter(|(_, p)| {
                match &self.priority_peer {
                    Some(pp) => &p.node_key != pp,
                    None     => true,
                }
            })
            .min_by_key(|(_, p)| p.last_seen)
            .map(|(i, _)| i);

        if let Some(idx) = evict_idx {
            let key = self.peers[idx].node_key;
            self.remove_peer(&key);
        }
    }
}
