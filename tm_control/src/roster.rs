//! The peer roster: the netmap state that streamed deltas are merged into.
//!
//! The control server sends one full map and then deltas (`PeersChanged`,
//! `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`, ...). A delta only
//! means something against the state it was computed from, so that state has
//! to be kept between messages. [`Roster`] is that state, and every
//! [`MapState`] the runtime sees is a whole snapshot of it, so the consumers
//! (router, WG, disco) never see a delta and need no merge logic of their own.
//!
//! Memory: one fixed-size roster per control connection, boxed once by the
//! actor. Nothing here allocates after that, and every bound is a constant:
//!
//! * `ROSTER_CAP` (16) entries, online or not. Offline peers are kept because
//!   headscale reports a peer coming online as a patch that carries only
//!   `NodeID` and `Online`: without the key, IP and DERP home we kept from the
//!   full map, that peer could never become routable. The cap is twice the
//!   snapshot size so a couple of offline peers do not use up the room.
//! * `MAX_PEERS` (8) is the snapshot size, i.e. what WG/disco can hold. Only
//!   online peers go into a snapshot, in control's order (ascending `NodeID`,
//!   which is how control sorts `Peers`). Peers beyond the eighth are dropped
//!   with an error log; there is no rotation, so which peers are reachable is
//!   stable from one snapshot to the next.
//!
//! Policy: a peer that control reports offline is out of the snapshot and so
//! out of WG. A peer that flaps offline then online is therefore removed and
//! re-added, with a fresh WG handshake. There is deliberately no hysteresis.

use arrayvec::ArrayVec;

use crate::{DerpRegion, MapNames, MapState, PeerInfo, TailnetIp};

/// Peers one snapshot (and so WG and the disco allowlist) can hold.
pub const MAX_PEERS: usize = 8;
/// DERP regions one snapshot can hold.
pub const MAX_REGIONS: usize = 4;
/// Peers the roster remembers, online or not.
pub const ROSTER_CAP: usize = 2 * MAX_PEERS;

struct Entry {
    /// Control's `NodeID`, the key deltas use. 0 when the server did not send
    /// one (then the node key is the only identity).
    id: u64,
    /// `Roster::clock` when a message last touched this entry; see
    /// [`Roster::tick`].
    stamp: u32,
    info: PeerInfo,
}

/// A `PeersChangedPatch` element, reduced to the fields we act on. Endpoints,
/// key expiry and last-seen are not used by the data plane and are skipped.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerPatch {
    pub id: u64,
    pub derp_region: u16,
    pub key: Option<[u8; 32]>,
    pub disco_key: Option<[u8; 32]>,
    pub online: Option<bool>,
}

pub struct Roster {
    our_ip: TailnetIp,
    names: MapNames,
    regions: ArrayVec<DerpRegion, MAX_REGIONS>,
    /// Sorted by `id` (ties in arrival order), which is control's order.
    peers: ArrayVec<Entry, ROSTER_CAP>,
    /// Counts messages that started a replace; see [`Roster::tick`].
    clock: u32,
    /// Something a snapshot shows changed since the last [`take_dirty`](Self::take_dirty).
    dirty: bool,
    /// Our node key's expiry. Not in `MapNames`: a snapshot does not show it,
    /// so it goes to [`selfnode`](crate::selfnode) instead.
    self_key_expiry: Option<i64>,
    self_dirty: bool,
}

impl Roster {
    pub fn new() -> Self {
        Self {
            our_ip: TailnetIp([0; 4]),
            names: MapNames::default(),
            regions: ArrayVec::new(),
            peers: ArrayVec::new(),
            clock: 0,
            dirty: false,
            self_key_expiry: None,
            self_dirty: false,
        }
    }

    /// Forget everything (a fresh control connection starts from nothing).
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Start a message that will replace the peer list: returns the floor to
    /// pass to [`upsert`](Self::upsert) and [`sweep`](Self::sweep).
    ///
    /// Replace is mark-and-sweep instead of clear-then-fill so that a message
    /// which fails half way leaves the old roster intact (nothing is swept
    /// unless the message completes), and so that two overlapping messages
    /// (the long poll and a re-poll) cannot sweep each other's entries: a
    /// touch stamps the entry with the current clock, and a sweep removes only
    /// entries older than its own floor.
    pub fn tick(&mut self) -> u32 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    pub fn our_ip(&self) -> &TailnetIp { &self.our_ip }
    pub fn names(&self) -> &MapNames { &self.names }
    pub fn regions(&self) -> &[DerpRegion] { &self.regions }
    pub fn len(&self) -> usize { self.peers.len() }
    pub fn is_empty(&self) -> bool { self.peers.is_empty() }

    pub fn online_count(&self) -> usize {
        self.peers.iter().filter(|e| e.info.is_online).count()
    }

    /// True once if the roster changed in a way a snapshot shows.
    pub fn take_dirty(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }


    pub(crate) fn set_our_ip(&mut self, ip: [u8; 4]) {
        if self.our_ip.0 != ip {
            self.our_ip = TailnetIp(ip);
            self.dirty = true;
        }
    }

    /// Our own MagicDNS name, from `Node.Name`. An over-long suffix is
    /// dropped whole (names then stay unresolvable by FQDN) rather than kept
    /// truncated, which would mismatch.
    pub(crate) fn set_self_name(&mut self, label: heapless::String<{ crate::MAX_NAME_LABEL }>, suffix: &str) {
        let mut fitted: heapless::String<{ crate::MAX_NAME_SUFFIX }> = heapless::String::new();
        if fitted.push_str(suffix).is_err() {
            fitted.clear();
        }
        // Hashed over the real suffix even when it did not fit, so peers of
        // the same tailnet still match it.
        let hash = crate::suffix_hash(suffix);
        if self.names.self_label != label || self.names.suffix != fitted || self.names.suffix_hash != hash {
            self.names.self_label = label;
            self.names.suffix = fitted;
            self.names.suffix_hash = hash;
            self.dirty = true;
        }
    }

    /// Our node key's expiry in unix seconds; `None` means it never expires.
    pub(crate) fn set_self_key_expiry(&mut self, expiry: Option<i64>) {
        if self.self_key_expiry != expiry {
            self.self_key_expiry = expiry;
            self.self_dirty = true;
        }
    }

    pub fn self_key_expiry(&self) -> Option<i64> { self.self_key_expiry }

    /// Copy our key expiry to [`selfnode`](crate::selfnode) if it changed.
    /// Not part of `dirty`: a snapshot does not show it.
    pub fn publish_self(&mut self) {
        if core::mem::take(&mut self.self_dirty) {
            crate::selfnode::publish_key_expiry(self.self_key_expiry);
        }
    }

    /// `DNSConfig.Proxied`: MagicDNS is on.
    pub(crate) fn set_proxied(&mut self, on: bool) {
        if self.names.proxied != on {
            self.names.proxied = on;
            self.dirty = true;
        }
    }

    /// What control last said about a peer's presence, if we know the peer.
    pub(crate) fn online_of(&self, id: u64, key: &[u8; 32]) -> Option<bool> {
        self.peers.iter()
            .find(|e| (id != 0 && e.id == id) || e.info.node_key == *key)
            .map(|e| e.info.is_online)
    }

    /// Replace the DERP regions. An empty set is ignored: control never means
    /// "no DERP at all", and an empty parse would strand the data plane.
    pub(crate) fn set_regions(&mut self, regions: &[DerpRegion]) {
        if regions.is_empty() { return; }
        let same = regions.len() == self.regions.len()
            && regions.iter().zip(self.regions.iter()).all(|(a, b)| {
                a.region_id == b.region_id && a.region_code == b.region_code
                    && a.host == b.host && a.port == b.port
            });
        if !same {
            self.regions.clear();
            self.regions.extend(regions.iter().take(MAX_REGIONS).cloned());
            self.dirty = true;
        }
    }

    /// Insert or replace a peer. `floor` is the active replace's floor, if
    /// any: when the roster is full, an entry older than it is about to be
    /// swept anyway and is the first victim. Returns false if the peer did
    /// not fit (logged).
    pub(crate) fn upsert(&mut self, id: u64, info: PeerInfo, floor: Option<u32>) -> bool {
        let found = self.peers.iter().position(|e| {
            (id != 0 && e.id == id) || e.info.node_key == info.node_key
        });
        if let Some(i) = found {
            let e = &mut self.peers[i];
            e.stamp = self.clock;
            if e.id == id {
                if e.info != info {
                    e.info = info;
                    self.dirty = true;
                }
                return true;
            }
            // Same key under another id (or an id arriving for an id-less
            // entry): re-file it so the order by id holds.
            self.peers.remove(i);
        } else if self.peers.is_full() {
            let victim = floor
                .and_then(|f| self.peers.iter().position(|e| e.stamp < f))
                .or_else(|| {
                    if info.is_online {
                        self.peers.iter().position(|e| !e.info.is_online)
                    } else {
                        None
                    }
                });
            match victim {
                Some(v) => { self.peers.remove(v); }
                None => {
                    log::error!(
                        "netmap roster full ({} peers): dropping peer id {} ({})",
                        ROSTER_CAP, id, info.hostname.as_str()
                    );
                    return false;
                }
            }
        }
        let at = self.peers.partition_point(|e| e.id <= id);
        self.peers.insert(at, Entry { id, stamp: self.clock, info });
        self.dirty = true;
        true
    }

    /// Remove a peer by id. Unknown ids are normal (we may have filtered it).
    pub(crate) fn remove(&mut self, id: u64) -> bool {
        if id == 0 { return false; }
        match self.peers.iter().position(|e| e.id == id) {
            Some(i) => {
                self.peers.remove(i);
                self.dirty = true;
                true
            }
            None => false,
        }
    }

    /// Drop every peer no message has touched since `floor` was taken.
    pub(crate) fn sweep(&mut self, floor: u32) {
        let before = self.peers.len();
        self.peers.retain(|e| e.stamp >= floor);
        if self.peers.len() != before {
            self.dirty = true;
        }
    }

    pub(crate) fn set_online(&mut self, id: u64, online: bool) -> bool {
        if id == 0 { return false; }
        let Some(e) = self.peers.iter_mut().find(|e| e.id == id) else { return false };
        if e.info.is_online != online {
            e.info.is_online = online;
            self.dirty = true;
        }
        true
    }

    /// Apply a `PeersChangedPatch` element. Returns false for an unknown id
    /// (control says to ignore those).
    pub(crate) fn patch(&mut self, p: &PeerPatch) -> bool {
        if p.id == 0 { return false; }
        let Some(e) = self.peers.iter_mut().find(|e| e.id == p.id) else { return false };
        let mut changed = false;
        if p.derp_region != 0 && e.info.derp_region != p.derp_region {
            e.info.derp_region = p.derp_region;
            changed = true;
        }
        if let Some(k) = p.key {
            if e.info.node_key != k { e.info.node_key = k; changed = true; }
        }
        if let Some(k) = p.disco_key {
            if e.info.disco_key != k { e.info.disco_key = k; changed = true; }
        }
        if let Some(o) = p.online {
            if e.info.is_online != o { e.info.is_online = o; changed = true; }
        }
        if changed { self.dirty = true; }
        true
    }

    /// Write a whole snapshot into `out` (reusing the caller's allocation).
    /// Only online peers, in control's order, at most `MAX_PEERS`.
    pub fn snapshot_into(&self, out: &mut MapState) {
        out.our_ip = self.our_ip.clone();
        out.names = self.names.clone();
        out.derp_regions.clear();
        out.derp_regions.extend(self.regions.iter().cloned());
        out.peers.clear();
        let mut dropped = 0usize;
        for e in self.peers.iter().filter(|e| e.info.is_online) {
            if out.peers.try_push(e.info.clone()).is_err() {
                dropped += 1;
            }
        }
        if dropped > 0 {
            log::error!(
                "{} online peers but WG holds {}: dropping the last {} (control's order)",
                out.peers.len() + dropped, MAX_PEERS, dropped
            );
        }
    }

    /// A snapshot in a fresh box (events carry `Box<MapState>`).
    pub fn snapshot(&self) -> Box<MapState> {
        let mut m = Box::new(MapState {
            our_ip: TailnetIp([0; 4]),
            peers: ArrayVec::new(),
            derp_regions: ArrayVec::new(),
            names: MapNames::default(),
        });
        self.snapshot_into(&mut m);
        m
    }

    /// Whether a snapshot would carry anything (an IP, a peer or a region);
    /// an all-empty one is skipped rather than sent, so a near-empty message
    /// can never blank the runtime's netmap.
    pub fn has_content(&self) -> bool {
        self.our_ip.0 != [0; 4] || self.online_count() > 0 || !self.regions.is_empty()
    }
}

impl Default for Roster {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8, online: bool) -> PeerInfo {
        PeerInfo {
            node_key: [n; 32], disco_key: [n.wrapping_add(100); 32],
            tailnet_ip: TailnetIp([100, 64, 0, n]), prefix_len: 32,
            hostname: heapless::String::new(), name: Default::default(),
            derp_region: 1, is_online: online,
        }
    }

    fn keys(r: &Roster) -> Vec<u8> {
        r.snapshot().peers.iter().map(|x| x.node_key[0]).collect()
    }

    #[test]
    fn upsert_keeps_control_order_and_replaces_in_place() {
        let mut r = Roster::new();
        r.upsert(30, p(3, true), None);
        r.upsert(10, p(1, true), None);
        r.upsert(20, p(2, true), None);
        assert_eq!(keys(&r), [1, 2, 3]);
        let mut changed = p(2, true);
        changed.derp_region = 9;
        assert!(r.take_dirty());
        r.upsert(20, changed, None);
        assert!(r.take_dirty());
        assert_eq!(r.snapshot().peers[1].derp_region, 9);
        // An identical upsert is not a change.
        r.upsert(20, r.snapshot().peers[1].clone(), None);
        assert!(!r.take_dirty());
    }

    #[test]
    fn snapshot_is_online_only_but_offline_peers_are_remembered() {
        let mut r = Roster::new();
        r.upsert(1, p(1, true), None);
        r.upsert(2, p(2, false), None);
        assert_eq!(keys(&r), [1]);
        assert_eq!(r.len(), 2);
        // Going online later needs no more than the id: the rest was kept.
        assert!(r.patch(&PeerPatch { id: 2, online: Some(true), ..Default::default() }));
        assert_eq!(keys(&r), [1, 2]);
        assert_eq!(r.snapshot().peers[1].tailnet_ip.0, [100, 64, 0, 2]);
        // And back: the flap removes it from the snapshot (no hysteresis).
        assert!(r.set_online(2, false));
        assert_eq!(keys(&r), [1]);
    }

    #[test]
    fn replace_sweeps_only_what_the_message_did_not_touch() {
        let mut r = Roster::new();
        for i in 1..=4u8 { r.upsert(u64::from(i), p(i, true), None); }
        let floor = r.tick();
        r.upsert(2, p(2, true), Some(floor));
        r.upsert(5, p(5, true), Some(floor));
        r.sweep(floor);
        assert_eq!(keys(&r), [2, 5]);
    }

    #[test]
    fn failed_replace_leaves_the_roster_alone() {
        let mut r = Roster::new();
        for i in 1..=3u8 { r.upsert(u64::from(i), p(i, true), None); }
        let floor = r.tick();
        r.upsert(1, p(1, true), Some(floor));
        // ...message fails here, so sweep(floor) is never called.
        assert_eq!(keys(&r), [1, 2, 3]);
    }

    #[test]
    fn overlapping_replaces_do_not_sweep_each_other() {
        let mut r = Roster::new();
        for i in 1..=3u8 { r.upsert(u64::from(i), p(i, true), None); }
        let a = r.tick();
        r.upsert(1, p(1, true), Some(a));
        let b = r.tick();
        r.upsert(2, p(2, true), Some(b));
        r.upsert(3, p(3, true), Some(b));
        // A finishes after B started: 2 and 3 were touched by B, so they stay.
        r.upsert(2, p(2, true), Some(a));
        r.sweep(a);
        assert_eq!(keys(&r), [1, 2, 3]);
        r.sweep(b);
        assert_eq!(keys(&r), [2, 3], "1 was not touched since B started");
    }

    #[test]
    fn full_roster_policy_prefers_online_and_never_panics() {
        let mut r = Roster::new();
        for i in 0..ROSTER_CAP as u8 {
            assert!(r.upsert(u64::from(i) + 1, p(i + 1, i % 2 == 0), None));
        }
        assert_eq!(r.len(), ROSTER_CAP);
        // An online newcomer displaces an offline resident.
        assert!(r.upsert(99, p(99, true), None));
        assert_eq!(r.len(), ROSTER_CAP);
        // (Not visible in `keys`: the snapshot shows the first 8 online by id
        // and 99 sorts last, so count it instead.)
        assert_eq!(r.online_count(), ROSTER_CAP / 2 + 1);
        // An offline newcomer does not displace anyone.
        let mut r2 = Roster::new();
        for i in 0..ROSTER_CAP as u8 {
            r2.upsert(u64::from(i) + 1, p(i + 1, true), None);
        }
        assert!(!r2.upsert(99, p(99, false), None));
        assert!(!r2.upsert(98, p(98, true), None), "all online and not stale: dropped");
        assert_eq!(r2.len(), ROSTER_CAP);
    }

    #[test]
    fn snapshot_keeps_the_first_max_peers_online_in_order() {
        let mut r = Roster::new();
        for i in 1..=ROSTER_CAP as u8 { r.upsert(u64::from(i), p(i, true), None); }
        let k = keys(&r);
        assert_eq!(k.len(), MAX_PEERS);
        assert_eq!(k, (1..=MAX_PEERS as u8).collect::<Vec<_>>());
    }

    #[test]
    fn replace_displaces_stale_entries_when_full() {
        let mut r = Roster::new();
        for i in 1..=ROSTER_CAP as u8 { r.upsert(u64::from(i), p(i, true), None); }
        let floor = r.tick();
        // The new list is entirely different ids; each displaces a stale one.
        for i in 101..=100 + ROSTER_CAP as u8 {
            assert!(r.upsert(u64::from(i), p(i, true), Some(floor)), "id {}", i);
        }
        r.sweep(floor);
        assert_eq!(r.len(), ROSTER_CAP);
        assert_eq!(keys(&r)[0], 101);
    }

    #[test]
    fn patch_for_unknown_id_is_ignored() {
        let mut r = Roster::new();
        r.upsert(1, p(1, true), None);
        r.take_dirty();
        assert!(!r.patch(&PeerPatch { id: 7, derp_region: 3, ..Default::default() }));
        assert!(!r.set_online(7, false));
        assert!(!r.remove(7));
        assert!(!r.take_dirty());
    }

    #[test]
    fn same_key_under_a_new_id_replaces_the_old_entry() {
        let mut r = Roster::new();
        r.upsert(5, p(1, true), None);
        r.upsert(9, p(1, true), None);
        assert_eq!(r.len(), 1);
        assert!(r.patch(&PeerPatch { id: 9, derp_region: 4, ..Default::default() }));
    }

    #[test]
    fn empty_region_set_is_ignored() {
        let mut r = Roster::new();
        r.set_regions(&[]);
        assert!(r.regions().is_empty());
        assert!(!r.has_content());
    }
}
