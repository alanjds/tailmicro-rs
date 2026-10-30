# Investigation: keeping the netmap fresh after boot

Scope: read-only. Branch `simplification-survey`. Consumer: tasmolike-rs on ESP32-C3 (400 KB SRAM, tokio `current_thread`). Tags: **[V]** verified in code or source with file:line, **[I]** inference, **[U]** could not be verified. Go line numbers are from tailscale/tailscale `main` and headscale as fetched on 2026-10-01 (not pinned to a release).

## Summary

The device takes one netmap at boot and never again applies a later one. The long-poll stream stays open, but `stream_map_response` skips every DATA payload without parsing (`tm_control/src/lib.rs:860,896`). The only refresh is a full reconnect after a stream or transport error. Peers that join, leave, change IP, DERP home or key are therefore invisible until the TCP connection dies, which has no scheduled trigger.

Recommendation: ship a rate-limited re-poll first (phase 1, small, reuses the working publish path), then streamed deltas (phase 2) only if the on-device RAM and radio measurements justify it. Details below.

## Q1. What happens to the poll today

**[V]** `connect_and_poll` (`tm_control/src/lib.rs:538-619`) runs `bring_up` once, then loops:

1. Send a `Stream=true`, `omit_peers: true` MapRequest on stream 7 (`:590`, stream IDs at `:126-134`).
2. Call `stream_map_response(..., MAP_STREAM_ID, true)` (`:789-1008`).
3. On return (Ok or Err) log "reconnecting", sleep `backoff` (1 s doubling to 30 s), call `bring_up()` again; success resets the backoff to 1 s, failure warns and retries.

Inside `stream_map_response`, `discarding = streaming` (`:860`) and `pos = payload.len()` (`:896`): the payload is never parsed or buffered. The loop still sends WINDOW_UPDATE (`:889-891`), SETTINGS ack and PING ack (`:998-1003`). It returns Err on GoAway (`:1004`) and Ok only on `end_stream` (`:996`). Other exits: transport read error, frame over 4096 B (`FrameTooLarge`), H2 parse error.

**[V]** There is no read timeout or watchdog on the poll; `connect_timeout` covers bring-up only (`:153-158`). `open_tcp` sets no socket options (`:1017-1021`).

**[U]** Whether a half-open TCP connection (AP drops, NAT mapping expires) is ever detected. Without keepalive sockopts or a watchdog the device may sit on a dead stream indefinitely. This matters independently of the refresh work, because control also learns nothing about the tailnet in that state. tailscaled has a watchdog for exactly this (`control_controlclient_direct.go` read loop, around L1255-1366).

**[V]** The first bring-up failure propagates out of `run()` with no retry; only later reconnects retry (`:538-619`).

State machine today:

```
BringUp --ok--> Publish#1 (stream 3, parsed, emits MapUpdate + OurIpAssigned)
        --> Publish#2 (stream 5, drained)
        --> Poll (stream 7, Stream=true, all DATA discarded)
Poll --END_STREAM | GoAway | read err | FrameTooLarge | H2 err--> Backoff(1..30 s) --> BringUp
BringUp --fail (first time)--> run() exits
BringUp --fail (later)--> Backoff
```

Reconnect cadence: unbounded. Server-side idle policies (headscale keepalives about every 50-59 s, Tailscale control similar) keep the stream alive, so a healthy device never reconnects. **[I]** The first refresh after a long healthy session is therefore "whenever Wi-Fi or the server glitches".

## Q2. What the real protocol sends after the first full map

**[V]** (`tailcfg.go` MapResponse docs L1990-2150; `controlclient/map.go` `updateStateFromResponse` L368-483, `updatePeersStateFromResponse` L550-672.) On a `Stream=true` poll, the first message is a full map; later messages are partial and a zero or nil field means "unchanged". Fields relevant here, applied in this order by tailscaled:

| Field | Meaning | Matters for a tiny device? |
|---|---|---|
| `Peers` (non-empty) | Full replacement; overrides the delta fields | Yes (first message) |
| `PeersChanged` | Upsert full Node entries by NodeID | Yes: add, IP, key, hostname, DERP home |
| `PeersRemoved` | NodeIDs to delete | Yes |
| `PeersChangedPatch` (`PeerChange`, `tailcfg.go` L3031-3070) | Partial per node: DERPRegion, Endpoints, Key, DiscoKey, Online, LastSeen, KeyExpiry, Cap, CapMap | Yes: DERPRegion, Key, DiscoKey, Online. Endpoints only if direct-path discovery wants them |
| `OnlineChange`, `PeerSeenChange` | maps NodeID to bool | Online yes; LastSeen no |
| `KeepAlive` | no state change; tailscaled just `continue`s | Needed only as liveness signal |
| `DERPMap` | Full or incremental map of relays | Yes if DERP regions change (we hold 4 regions) |
| `DNSConfig` | resolver and MagicDNS settings | Only for the planned MagicDNS table (`docs/investigation-magicdns.md`) |
| `PacketFilter(s)` | ACL deltas | No: the device does not enforce a filter **[I]**, not audited |
| `Domain`, `UserProfiles` | names | Hostname/MagicDNS only |

Notes:

- **[V]** Version >= 68 makes `Stream=true` read-only for the server: Hostinfo, DiscoKey and Endpoints in the streaming request are ignored (cap history, `tailcfg.go` L119). Writes need a separate non-streaming request, which tailmicro already does with publish #1 and #2.
- **[V]** The "lite update" is `Stream=false` plus `OmitPeers=true`: the server replies with a bare 200 and leaves the long poll alone (`tailcfg.go` L1436-1527; headscale `hscontrol_poll.go` L88, L119-145). tailscaled sets `OmitPeers: nu == nil`, so its streaming request always has `OmitPeers=false` (`control_controlclient_direct.go` L1102).
- **[V]** tailmicro sends `Stream=true` with `omit_peers: true` (`lib.rs:590`). That combination is non-standard. **[U]** What real Tailscale control sends in this case (full peers, no peers, or deltas only). Headscale ignores `OmitPeers` on streaming requests (`hscontrol_poll.go` L119-145), so on headscale the stream carries peers regardless. Moot today because the payload is discarded.
- **[I]** The comment at `lib.rs:108` ("avoids PeerChangesDelta (cap 72+)") looks wrong: the capability list shows `PeersChangedPatch` predates cap 72 (patches are in tailscale since 2022; `Cap` in patches arrived at cap 54, `tailcfg.go` L105). The server may already send patches to a v72 client. Treat patches as expected.
- **[V]** Upstream tailscale-rs applies `Full` and `Delta{upsert, remove}` but only warns on `peers_changed_patch`, and ignores OnlineChange and PeerSeenChange (`ts_control/src/tokio/map_stream.rs:120-142`). It sends `omit_peers(false)` on the stream (`client.rs:79-84,233-236`), uses the lite update `stream=false, omit_peers=true` for DERP-home changes on the same h2 connection (`client.rs:276-292`), and has a TODO for resumption (`client.rs:201`). We cannot copy upstream's delta handling for patches; it does not have it.
- **[V]** Headscale: keepalive every 50 s plus jitter, `serveLongPoll` fans in updates from a batcher; `mapRequestDelta` sends patches for derp and endpoint changes and whole-node updates for key changes; it waits 10 s for a reconnect before marking a node offline (`hscontrol_poll.go` L26,58,151-355; `hscontrol_state_maprequest.go`). So on headscale both patches and PeersChanged are live traffic.

## Q3. What happens on the device when the tailnet changes

State: **[V]** `peer_ips` and `ip_to_key` (`tm_runtime/src/lib.rs:783,788`) are rebuilt by clear+push only inside the `MapUpdate` handler (`:822-917`, rebuild at `:908-914`). `AllowPeer` is sent per peer there (`:892-898`). WG gets `ApplyMap` (`:916`).

| Event | Device behavior | Evidence |
|---|---|---|
| Peer joins | Not in `ip_to_key`: outbound packet dropped, logged by `log_unknown_netif_dest` (`:587`, miss at `:1224`). Not in disco allowlist: its disco PINGs are dropped. Not in WG peer table | `lib.rs` (runtime) above; `tm_disco/src/lib.rs:346` (allowlist is only filled by `AllowPeer`) |
| Peer leaves | Stays in `ip_to_key`, disco allowlist and WG peer table. Packets still sent via the stale DERP home | same; `RemovePeer` exists in disco (`:259,351`) but **[V]** nothing in tm_runtime sends it |
| Peer changes IP | Stale `ip_to_key` entry maps the old IP to the key; new IP unknown | rebuild only on MapUpdate |
| Peer changes DERP home | WG endpoint stays on the old region: `apply_map` skips any key already present (`tm_wg/src/lib.rs:279-340`, `continue` for existing peers) | **[V]** |
| Peer endpoints change | Not stored anywhere (parser skips them: `map_stream.rs:293-316`) | **[V]** |
| Peer goes offline/online | Offline peers are never admitted (`commit_peer`, `map_stream.rs:373-393`), so a peer that comes online after boot is the "joins" row | **[V]** |

Positive finding: **[V]** a fresh `MapUpdate` is idempotent and complete for WG: `apply_map` removes keys absent from the map, adds new ones and starts a handshake (`tm_wg/src/lib.rs:279-340`). Router tables are rebuilt from scratch. So snapshot-based refresh needs no new commands for the add/remove case; only the DERP-home and IP-change cases need `apply_map` to compare more than the key.

User-visible symptom **[I]**: from the tailnet, "the ESP32 is unreachable from the new laptop/phone until it reboots or reconnects"; from the device, a command or MagicDNS lookup toward a newly added node fails with no log beyond one drop line. A removed or re-keyed node keeps getting traffic until the next reconnect. The MagicDNS plan already lists this stale-snapshot risk (`docs/investigation-magicdns.md:66-73,113`).

**[U]** Whether the WG endpoint accepts an inbound handshake from a key it has not been told about. It is expected to reject (peer not in table) **[I]**.

## Q4. Options

Constraints **[V]**: RX frames are capped at 4096 B (`FB_CAP`, `lib.rs` `read_one_h2_body`), stream window is 4096 (`tm_h2/src/lib.rs:73`), `MAX_PEERS=8`, `MAX_REGIONS=4`, `MapStreamParser<8,4>` is a push parser with fixed stack (`map_stream.rs`), and ALLOCATIONS.md documents a fragmented heap with a small largest block (about 20-43 KB) and a DERP TLS collapse. Publish #1 response is about 29 KB of JSON on the real tailnet (live-measured per the code comment in `read_one_h2_body`), consumed through the parser without buffering.

| | (a) Stream + incremental parser | (b) Periodic lite re-poll with peers | (c) Reconnect on timer | (d) Hybrid |
|---|---|---|---|---|
| Mechanism | Keep stream 7, parse every message, apply deltas | Non-streaming `OmitPeers=false` on new odd stream ID (9, 11, ...) on the same h2 connection, parse like publish #1 | Force the existing reconnect path | Deltas plus a rate-limited re-poll on router miss or timer |
| RAM peak | Parser state only (about the same as today's); needs NodeID-keyed merge table, +about 8 x 40 B. Plus the duplicate first full map **[I]** | Same as today's publish #1 parse; no new heap | Noise + h2 + two publishes again; the heavy phase that ALLOCATIONS.md flags | (a) + (b) |
| Radio/battery | Lowest: bytes only when something changes, plus keepalives already received today | 30-48 KB RX per poll **[I]** (29 KB measured for publish #1 plus framing); at 10 min that is about 4-7 MB/day | Highest: TCP, Noise, register, two maps, plus online flapping on the server side | Low steady, bounded bursts |
| Latency | Seconds | Up to interval; can be cut by miss-triggered poll | Up to timer | Seconds, with a safety net |
| Complexity | High: parser (NodeID, PeersChanged, PeersRemoved, PeersChangedPatch, OnlineChange with numeric-string keys, KeepAlive, DERPMap deltas), merge semantics distinct from the online-only snapshot filter, patch DERPRegion int vs the existing "DERP" string branch (`map_stream.rs:340`) | Low-medium: a timer `select!` inside the frame loop (`docs/investigation-service-advertisement.md:57,147` rates this effort M), new stream-ID allocation | Lowest: a deadline check | Highest |
| Failure modes | Patch for unknown NodeID; out-of-order seq; silent drift if one delta is mis-parsed; `MAX_PEERS` overflow handling under merge | Long poll starves while the re-poll body is read (single frame loop); HOL on h2 window; stream-ID exhaustion after about 1e9 (not a concern); server rate limits **[U]** | Heap collapse during re-handshake; DERP session reset; TS marks node offline then online | Union |
| Host-testable | Yes, with a fake control (JSON frames into the parser) | Yes, with the same | Yes (existing local-listener style, `lib.rs:1212-1300`) | Yes |
| Fit with `plan-runtime-backends.md` | Parser and merge are pure code, runtime-agnostic. Poll loop uses `select` with `R::sleep` (plan phase 4-5 combinators) | Needs `select(frame, R::sleep_until)`; same combinators; no `tokio::time` calls to add if written against the plan's `Reactor` (`:74,85,155-156`) | Uses `R::sleep` already planned (`:156`) | Same |

Cross-cutting **[I]**:

- (a) forces `omit_peers=false` (matching tailscaled and upstream), so the first streamed message duplicates publish #1 and costs another 29 KB parse right after bring-up. Mitigation: skip the MapUpdate emit from publish #1 and treat the stream's first message as authoritative, or accept the duplicate once per connect.
- Do the merge in `tm_control` so the router stays on whole-snapshot `MapUpdate`s (idempotent per Q3). Cost: the router and WG re-run `AllowPeer`/`ApplyMap` for every delta, which `apply_map` tolerates, but `docs/simplification-survey.md:290` (P-06) already flags the cost of `apply_map`; coalesce.
- Under (b), removals are detected by absence, which needs the online-only filter semantics to stay. A blip where control reports a peer offline briefly will remove it from WG; same as today at boot.
- The plan's fake control server (`plan-runtime-backends.md` phase 8, `:263-265`) is large. Delta parser tests do not need it: feed byte frames straight into `MapStreamParser`, as the current tests do (`map_stream.rs:423-516`).

## Q5. Recommendation

**Phase 0 (host only, no radio change).** Extend `MapStreamParser` to produce a delta enum: NodeID in Peer, PeersChanged, PeersRemoved, PeersChangedPatch (DERPRegion, Key, DiscoKey, Online), OnlineChange, KeepAlive, DERPMap. Golden JSON tests from tailscale and headscale captures. Fix the `lib.rs:108` comment once verified. Also add a read watchdog on the poll (deadline slightly over the server keepalive; reconnect on expiry). This closes the dead-connection gap with a few lines.

**Phase 1 (safety net).** Add a rate-limited re-poll (option b) via a `select!` between the poll frame loop and a timer, also triggered by a router `ip_to_key` miss (cap: one per N minutes). It reuses the proven publish response parser and the idempotent MapUpdate path. Measure heap minimum and largest block on a real device before and after.

**Phase 2 (only if measurements say so).** Streamed deltas (option a) with the merge in `tm_control`; `omit_peers=false`; reject or coalesce the duplicate first map. Teach `apply_map` to update existing peers (DERP region, IP). Send `DiscoCmd::RemovePeer` from the router for removed keys.

Test plan:

- Host: parser golden frames (adds, removes, patches, keepalive, malformed, oversize), merge unit tests against `MAX_PEERS`, local-listener test that a second MapResponse changes the emitted `MapUpdate`, and a watchdog-expiry test with a silent stream.
- Router test: a MapUpdate removing a key clears `ip_to_key` and sends `RemovePeer` (new).
- Device (D): heap minimum and largest block over a soak with peers added and removed on the tailnet; main-stack HWM (about 7.4 KB free today per the plan); radio bytes per hour.

Risks:

- Heap fragmentation from extra parse/merge state; the project's history is full of OOMs from small doubling allocations (`docs/wg-dataplane-notes.md:263-268,884-917`). Keep everything `heapless`.
- Server semantics for `Stream=true` plus `omit_peers=true` are unverified; do not rely on them. Phase 0 should capture a real stream (host-side, not on the device) to settle this.
- Peers above `MAX_PEERS=8` are dropped silently (`map_stream.rs:373-393`); a refresh makes the truncation order visible, since a new peer may now displace nothing and be dropped.
- Offline peers are filtered, so flapping presence shows up as WG add/remove churn and re-handshakes.

## Decisions needed

1. Re-poll first (phase 1) or go straight to streamed deltas (phase 2)? Recommended: re-poll first.
2. Re-poll interval and miss trigger (for example 10 min plus on-miss limited to once per 2 min), balancing about 29 KB per poll against staleness.
3. Accept the duplicate first full map with `omit_peers=false` for option (a), or invest in suppressing it?
4. `MAX_PEERS=8` policy when the tailnet has more peers: keep first-N, or prioritize by recent online or by what the user pings?
5. Extend `apply_map` and the router with removal and update commands (`RemovePeer`, DERP region and IP changes), or keep snapshot-only semantics and rely on full rebuilds?

## Not verified

Real-control behavior for `Stream=true` plus `omit_peers=true`; half-open TCP detection; WG behavior for inbound handshakes from unknown keys; the actual size of a mid-session delta on a real tailnet; whether control rate-limits repeated non-streaming map requests; per-poll heap behavior on device.

## Implementation status

Branch `simplification-survey`. Each phase below says what is done, what was measured and what is unverified.

### Phase 0 (watchdog): done
- `d4f126a`: the streaming poll has a read watchdog (`POLL_IDLE_TIMEOUT`, a little over the server keepalive); expiry returns an error so the actor reconnects. Host test with a silent stream.
- Measured: nothing on device. Unverified: half-open TCP detection on a real network (the host test uses a silent local socket).

### Phase 1 (re-poll safety net): done
- `75ae17d`: rate-limited full re-poll on the live connection, by timer (`Config::refresh_interval`, off unless the firmware sets it) and on a router `ip_to_key` miss (`request_refresh_on_miss`). The re-poll resends the publish body, because a non-streaming `OmitPeers=false` request is a write at cap 68 and above.
- Finding: Headscale answers a non-streaming `OmitPeers=false` request with an empty 200, so the timed and miss re-poll only yields a netmap on Tailscale SaaS. On Headscale the stream's first message and deltas are the only path. The firmware does not set `refresh_interval`, so only the miss trigger is live.
- Fix found on the way (same commit): per-stream HTTP/2 credit in `tm_h2`. The old shared counter double counted and could send the stream WINDOW_UPDATE for the wrong stream, which over-granted the server window beyond the 4096-byte frame cap.
- Unverified on device: a real re-poll against Tailscale SaaS.

### Phase 2 (router/WG/disco diff, streamed deltas): done
- `feaaf06`: `apply_map` diffs existing peers (disco key, WG endpoint, DERP region, IP) and removes vanished ones from the router, WG and disco. Also fixed a WG peer-id bug found by the new diff tests.
- `03fb48d`: `MapStreamParser` decodes streamed messages (full `Peers`, `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`, `DERPMap`, `KeepAlive`) into a bounded `Roster`. Golden JSON frames are constructed from the Go field names (no real capture), with chunk size sweeps down to one byte.
- `56a08c9`: the stream asks for `OmitPeers=false` and its first message is the bring-up netmap. Publishes #1 and #2 are lite (`OmitPeers=true`, empty 200). `Device::connect` still returns on `OurIpAssigned` and keeps `connect_timeout`, now as a readiness deadline in the poll loop. The timed and miss re-poll stays as a rare fallback. Stream ids are 3 (publish #1), 5 (poll), 7 (publish #2), 9 and up (re-polls).
- Measured on a real ESP32-C3 (one boot of the final build, 330 s soak): bring-up reached `100.75.48.69` from the stream's first message, 3 peers and 4 DERP regions, MagicDNS table built with 4 names including `bospill`, WG synced 3 peers, DERP home 11 connected, direct LAN path established, no panic, OOM or watchdog. Registration to IP took 7.0 s against 7.9 s for the pre-series build. Numbers in `ALLOCATIONS.md` Step 13.
- The 29 KB first message arrives one 4096-byte frame per roughly 0.92 s. The parse itself costs about 10 ms per frame (measured with a temporary timer, removed), so the pacing is the HTTP/2 window (`INITIAL_WINDOW=4096`) times the control round trip. Raising the window needs `FRAME_BUF_CAP` to grow with it and is not done.

### Policies as implemented
- `MAX_PEERS=8` is applied to the snapshot, not the roster. Every refresh replaces the whole peer list, keeps control's order, and logs an error for the 9th and later.
- `ROSTER_CAP=16` retains offline peers, because Headscale sends presence as `PeersChangedPatch [{NodeID, Online}]` only.
- Online-only filtering stays. A peer reported offline is removed from WG at the next snapshot and re-added (with a new handshake) when it reports online again. There is no hysteresis, so a flapping peer churns.
- The MagicDNS table is rebuilt on every snapshot.
- Headscale sends `HomeDERP` (an int), not the legacy `DERP` string. The old parser ignored it, so Headscale peers had `derp_region` 0; it is read now.
- `CAPABILITY_VERSION` stays 72. Only the comment was wrong: `OnlineChange` is from cap 16, `PeersChangedPatch` from 33 (`DERPRegion`) and 36 (`Key`, `DiscoKey`, `Online`), and 72 added only a UPnP fix.

### Known gaps
- A change of our own home DERP region is not applied: `DerpCmd::Connect` is ignored once connected. Peers' DERP homes are updated.
- An undecodable stream message reconnects instead of continuing, because a missed delta would drift silently. A first-session failure still ends `run()` without a retry (unchanged).
- Per-poll heap with a real delta, the stack high-water mark, `bospill` name resolution through the lwIP hook (only the table contents were observed), a peer going offline and online on a real tailnet, and a re-poll against Tailscale SaaS were not exercised on the device.
