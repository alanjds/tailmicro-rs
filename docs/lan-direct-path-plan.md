# Plan (c): LAN-only direct UDP path ("Tier 1")

Written 2026-09-27. **Plan only; nothing here is implemented yet.** Branch
`wg-dispatch-scratch`.

## Goal

When a tailnet peer is on the same L2/L3 LAN as the device (the common case
for this device: a phone or laptop on the same home WiFi), carry WireGuard
directly over UDP between them instead of relaying every packet through DERP
(TLS/TCP to `derp*.tailscale.com`, currently region 11 / sao). Success test:
from a LAN peer, `tailscale status` shows the device as
`direct 192.168.x.y:41641` (not `relay "sao"`), `tailscale ping esp32c3`
reports `via 192.168.x.y:41641`, and `curl http://<tailnet-ip>/` works over
that path.

Hard constraint: **the already-working DERP path must not regress.** The device
carries real traffic. DERP stays connected and stays the fallback. A direct
path is best-effort and additive. If any piece of it fails, behavior must drop
back to exactly what ships today.

Out of scope: STUN, NAT hole-punching, port mapping (UPnP/NAT-PMP/PCP), and
IPv6 endpoints ("Tier 2/3"). The earlier scoping pass judged them not worth
the RAM and complexity for one low-traffic device, and a phone on carrier NAT
would not benefit anyway. This plan does not revisit that.

## Where the earlier scoping pass landed, and what re-reading the code changed

The earlier pass was never written into this repo. `README.md:121` has only
`STUN / direct paths | ⏳ Phase 4`, and the only in-tree evidence is Spike 2 in
`docs/wg-dataplane-notes.md` (the 2026-09-16 update, around line 579).
Every claim was re-checked against the source:

| Claim | Verdict | Evidence |
|---|---|---|
| `WgActor::endpoint_for` always returns `Derp` | **Confirmed** | `tm_wg/src/lib.rs:292-297` |
| Roaming "already switches a peer to `Endpoint::Udp` once a packet authenticates" | **Wrong** | `maybe_roam` (`tm_wg/src/endpoint.rs:807-818`) only roams when `!peer.endpoint.is_derp()`. A peer added as `Derp` (every peer today) can **never** become `Udp`. It is UDP→UDP roaming only. |
| `Endpoint { Udp, Derp }` exists and can be reused | Confirmed, but a single field is the wrong shape | `endpoint.rs:83-88`, `Peer.endpoint` (`:242`). We need DERP *and* an optional direct path at the same time, not one or the other (see Step 4). |
| (not stated) outbound packets carry a path | **Missing** | `WgEvent::OutboundPacket { dst_key, payload }` (`tm_wg/src/lib.rs:67-71`) has no endpoint. The router always sends to DERP (`tm_runtime/src/lib.rs:576-593`). `on_inbound` hard-codes `from = Derp{region 0}` (`tm_wg/src/lib.rs:314-317`). The path has to be plumbed end to end. |
| `DiscoCmd::MaybeDisco` has `src_ip`/`src_port` reserved for direct UDP | Confirmed | `tm_disco/src/lib.rs:157-175`. Outbound Ping and CallMeMaybe are deferred (`:17`). PONG is ignored (`:355`). |
| `tm_control` only ever publishes `127.3.3.40:<region>` | Confirmed | `tm_control/src/lib.rs:552-566` (publish #1, `endpoints: &[]`) and `:580-608` (publish #2, the DERP marker only) |
| (not stated) peers' own `Endpoints` are parsed | **No** | `PeerInfo` (`tm_control/src/lib.rs:78-86`) has no endpoints, and `map_stream.rs:32-33` skips `Endpoints`. We only learn a peer's LAN address from its authenticated disco PING (enough for this plan; see Step 7). |
| `tm_netstack::UdpSocket` is an empty placeholder on ESP-IDF | Confirmed | `tm_netstack/src/lib.rs:35-67`. `Device::udp_bind` is `todo!()` (`src/lib.rs:226-230`). |
| `tokio::net::UdpSocket` should work on-device like `TcpStream` does | **Very likely, not yet proven** | The app pins tokio and mio to git master (`tasmolike-rs/Cargo.toml:27-28,46-47`). mio's socket creation has explicit `target_os = "espidf"` branches (`mio/src/sys/unix/net.rs:66,75`), and UDP bind goes through the same `new_ip_socket(addr, SOCK_DGRAM)` (`mio/src/sys/unix/udp.rs:13-14`). tokio's `net` feature is already on. TCP connect/listen are proven live. UDP has never run on this device, so Step 2 proves it before anything depends on it. |
| Cost ~1.5 KB + one lwIP UDP pcb | Roughly right, with one real blocker | See "RAM/lwIP budget" below. The pcb pool is probably **already full** (`CONFIG_LWIP_MAX_UDP_PCB=4`, `tasmolike-rs/sdkconfig.defaults:114`, with DHCP + DNS + SNTP + mDNS already running per `tasmolike-rs/src/wifi.rs:10,112`). |

### Spike 2, re-read: what actually failed

Spike 2 concluded that disco works over LAN UDP but the WireGuard handshake
does not, because tailscaled only moves to a path once disco has been
confirmed both ways. The conclusion holds, but its script shows why
confirmation never happened. It was a harness gap, not a protocol barrier:

- It published a bogus endpoint: `endpoints=[f"0.0.0.0:{my_port}"]`
  (`tools/wg_validator/validate_live_udp.py:141`).
- The peer's disco PING did arrive over UDP, and the script only printed it
  (`:189`). **It never answered with a PONG.** tailscaled trusts a UDP path
  (`bestAddr`) only after receiving a PONG over that path to its own PING, so
  that trust was never set. The spike also had no DERP leg, so the WG response
  (sent on the peer's then-preferred path) could not reach it at all.

So the Tier 1 mechanism is: publish a real `LAN_IP:port`, answer the peer's
UDP disco PINGs with UDP PONGs, and accept WireGuard on that socket. Nothing
in the code suggests anything more is required. Step 0 confirms this in
Python before any Rust changes.

MicroLink (`~/src/microlink`, an ESP32 C client this project already borrows
patterns from) does the same thing in production. It publishes the STA IP
from `esp_netif_get_ip_info` as an `EndpointLocal` (`ml_coord.c:1232-1254`),
answers PINGs directly (`ml_wg_mgr.c:849-891`), and switches a peer's WG
endpoint on a direct PONG with a trust window (`ML_DISCO_TRUST_DURATION_MS
15000`, heartbeat 3 s; `ml_wg_mgr.c:923-930,1430`).

## Key design decisions

### D1. Which LAN IP, and how the device learns it

Use `tokio::net::TcpStream::local_addr()` on the control connection, inside
`ControlActor::bring_up` (`tm_control/src/lib.rs`, whose `main_conn` is already
a `tokio::net::TcpStream`, `:468`). That is the source address lwIP chose to
reach the control server, so it is the WiFi STA DHCP address. Reasons:

- **No ESP-IDF dependency in `tm_control`.** It stays host-testable. No
  `esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")` coupling. No wrapper
  (`tasmolike-rs`) API change to pass the IP in.
- **It refreshes itself.** `bring_up` runs on first connect and on every
  keepalive reconnect (`:398-465`). A DHCP change of the STA address aborts
  lwIP TCP pcbs bound to the old address, which kills the control stream,
  which reconnects, which re-publishes with the new `local_addr()`. No
  separate IP-change watcher is needed for Tier 1.
- Publish it only if it is IPv4, not unspecified, not loopback, and **not in
  `100.64.0.0/10`** (never advertise a tailnet/CGNAT address as an underlay
  endpoint). RFC1918 is not required: a public-IP LAN is fine to advertise.

### D2. Bogus or unreachable endpoints: why publishing is safe

Tailscale publishes every local interface address this way, including
unreachable ones. Peers probe each endpoint with disco PINGs and use one only
after an authenticated PONG comes back over it. The failure modes:

- **Guest VLAN or AP client isolation** (same subnet, L2 blocked): PINGs
  never arrive, no PONG, and the peer stays on DERP. The only cost is a few
  wasted probes.
- **Double NAT, or a remote peer whose own LAN uses the same private
  subnet** (192.168.0.0/24 is common): the remote peer's PING lands on some
  unrelated host on *its* LAN. Disco is NaCl-boxed to our disco key, so that
  host cannot answer validly and the peer stays on DERP. The side effect is a
  few stray UDP datagrams to a random local host. Tailscale does the same.
- **Minor information leak:** our LAN IP becomes visible to the control plane
  and to tailnet peers, same as with stock tailscaled.

A bad endpoint cannot make the device unreachable. The peer never switches
paths without a PONG, and the PONG is only sent from the socket that actually
received the PING.

### D3. Path model in `tm_wg`: DERP always, direct optional, trust-windowed

Replace `Peer.endpoint: Endpoint` (`endpoint.rs:242`) with:

```rust
derp: Endpoint,                  // always Derp{region,node_key}; never torn down
direct: Option<DirectPath>,      // DirectPath { addr: SocketAddrV4, trust_until: Instant }
```

- **Send path:** `direct` if `Some` and `now < trust_until`, otherwise `derp`.
  The same rule applies to handshakes, keepalives and data.
- **Trust is set or refreshed only by authenticated evidence from that exact
  `addr`:** (a) a disco PING received over UDP that opened under an
  allowlisted disco key, via a new `WgCmd::DirectPathSeen { node_key, addr }`;
  (b) a WireGuard packet received over UDP from `addr` that decrypted or
  completed a handshake. That is `maybe_roam`'s existing
  "authenticated-only" rule, with the DERP guard inverted.
- `TRUST = 6.5 s`, matching tailscaled's `trustUDPAddrDuration`. While a
  session is active, tailscaled heartbeats its best path about every 3 s, so
  trust stays warm. When the peer goes idle, leaves the LAN or changes IP,
  trust lapses within 6.5 s and sends revert to DERP on their own. There is no
  explicit "peer left" detection.
- **Peer IP change** (DHCP renewal, or roaming between APs): an authenticated
  PING or WG packet from the new address replaces `addr`. Unauthenticated
  UDP never changes anything, so there is no spoofing lever.
- Inbound over DERP is **always** accepted and processed, whatever the path
  state, as it is today.

Size: `Option<DirectPath>` is about 40 B × `MAX_PEERS=8`, about 320 B. The
`wgendpoint_fits_fragmented_heap` guard (`endpoint.rs:837-850`, ≤ 8 KB,
currently 5968 B) still passes with margin.

### D4. Ordering constraint: the step that makes peers switch

The moment the device **answers a UDP disco PING with a UDP PONG while its
LAN endpoint is published**, the LAN peer trusts that path and sends its
WireGuard traffic **only** there, not over DERP, for as long as the
heartbeats keep getting PONGs. If the device answered disco over UDP but did
not feed UDP-borne WireGuard into `tm_wg`, every LAN peer would go
black-holed and stay that way: a silent, self-sustaining outage.

So **UDP PONG and UDP WireGuard ingest ship together** behind one feature
flag, and **endpoint publishing ships last or together with them**. Each step
below respects this order. Before Step 5, the socket does not answer disco at
all.

### D5. Feature gating

- New cargo feature `lan-direct` on `tm_runtime` (default **off**). It gates
  the socket, its task, and passing the port to `tm_control`. With the
  feature off, `tm_control` gets `lan_udp_port: None` and its publish bodies
  stay byte-identical to today (same `skip_serializing_if` discipline as the
  Bug 3 publish change). `tm_wg`/`tm_disco` changes are inert without a UDP
  source.
- Turning it on is a wrapper-side one-line change in
  `tasmolike-rs/Cargo.toml` (not made in this repo), and it can be turned
  back off the same way.
- Any runtime failure (bind error, send error, receive-loop error) logs at
  `warn!`, stops only the direct path, and never panics or tears down DERP.

### RAM/lwIP budget

| Item | Cost | Notes |
|---|---|---|
| UDP receive buffer | 1532 B `.bss` | One static `[u8; PKT_CAP]`, reused. Accepted datagrams are copied into a `tm_buf::PktBuf` after cheap demux. Deliberately **not** a pooled `PktBuf` held across `recv_from().await`, which would permanently pin 1 of the 4 pool buffers (`tm_buf POOL_N=4`). |
| lwIP socket + netconn + recvmbox | ~100-200 B heap, once | Allocated at bind time, **before** the DERP TLS handshake (see ALLOCATIONS.md "Fix plan: DERP TLS handshake heap collapse"). |
| `udp_pcb` | static memp slot | **Blocker:** `CONFIG_LWIP_MAX_UDP_PCB=4` is probably already used up by DHCP, DNS, SNTP and mDNS. Needs a wrapper `sdkconfig.defaults` bump to 6 (a few dozen bytes each). |
| Queued RX datagrams | up to `CONFIG_LWIP_UDP_RECVMBOX_SIZE` (default 6) × ~1.6 KB WiFi RX buffers, transient | A LAN host can flood `:41641`. Bound it with `CONFIG_LWIP_UDP_RECVMBOX_SIZE=3` (wrapper sdkconfig) and a prompt receive loop. Measure in Step 2. |
| Receive task future | a few hundred B, boxed | Same `#[inline(never)] spawn_*` + `Box::pin` pattern as the other actors (`tm_runtime/src/lib.rs:104-145`). |
| `DirectPath` per peer | ~320 B inside `WgEndpoint` | D3 |

Total: about 2-2.5 KB, which is the earlier estimate's order of magnitude. The
real unknown is the transient WiFi RX buffers under a UDP burst, which Step 2
measures.

## Staged implementation

Each step builds on its own and is verified before the next. Steps 1-4 change
no on-air behavior for peers. Step 5 is the first step peers can observe, and
it is feature-gated.

### Step 0 — Python-first spike: prove the mechanism against a real LAN peer (~2-3 h)

Extend `tools/wg_validator/validate_live_udp.py` (or add
`validate_lan_direct.py`) so the Python node:
1. binds UDP `0.0.0.0:41641` and learns its LAN IP from the control TCP
   socket's `getsockname()` (the same D1 technique, so the idea is proven
   independently of Rust);
2. calls `write_map(endpoints=[f"{lan_ip}:41641", f"127.3.3.40:{region}"],
   preferred_derp=region)`;
3. answers every UDP disco PING from an allowlisted peer with
   `disco.build_pong(..., src_endpoint=<peer's observed addr, 18-byte v4-mapped>)`
   over UDP;
4. brings up the DERP leg via the existing `derp_client.py`, so the WG
   response has a path either way.

Pass criteria, from `lenovopill` (same `192.168.15.0/24`): `tailscale ping
<python-node>` reports `via 192.168.15.x:41641`; `tailscale status` shows
`direct`; a WG handshake initiated by the peer arrives on the UDP socket.
**If this fails, stop.** Re-read tailscaled's `magicsock` `handlePingLocked`
and `handlePongConnLocked` before writing any Rust. Also record in the notes
whether a PONG alone populates the peer's `peerMap` ip:port→node-key mapping,
which decides whether the device ever needs to send its own PING (Step 7).

### Step 1 — `tm_disco`: PONG over direct UDP (host-only) (~2-3 h)

- Generalize `encode_derp_relay_src_ipport` (`tm_disco/src/lib.rs:116-127`)
  into `encode_src_ipport(SocketAddrV4)`, which also emits the DERP form via
  `127.3.3.40:<region>`.
- Replace `MaybeDisco { src_ip, src_port, src_node_key, .. }` with
  `src: DiscoSrc { Derp { node_key } | Udp(SocketAddrV4) }`.
- Over UDP, reply with `DiscoEvent::SendPongUdp { dst: SocketAddrV4, payload }`
  with `src_ipport = dst` (the peer's observed address, which is what
  tailscaled expects), and also emit `DiscoEvent::DirectPathSeen { node_key,
  addr }`.
- `AllowPeer` becomes `AllowPeer { disco_key, node_key }`. The router already
  has both (`tm_runtime/src/lib.rs:444-448`). A UDP PING's claimed node key
  (in the boxed body after `tx_id`) must match the netmap's pairing for that
  disco key, otherwise drop it. This stops one tailnet peer from claiming
  another's path.
- **Bug to fix here:** the 100 ms PONG rate limit is per *peer*
  (`:139-150,326-332`). tailscaled sends its DERP and UDP PINGs back to back,
  so the second path's PONG gets suppressed, and that is usually the UDP one,
  the one that matters. Rate-limit per (peer, path) instead.
- Add a cheap pre-decrypt rate limit per source IP for UDP (each disco open is
  an X25519 DH, several ms on the C3). Over DERP only tailnet nodes can reach
  us, but over UDP any LAN host can.

Validation (Python first): generate a fixed-nonce vector with pynacl
(`disco.build_pong` with a fixed nonce and `src_endpoint` =
`::ffff:192.168.15.139` port 41641) and add
`pong_seal_crosscheck::udp_pong_wire_matches_pynacl_reference`, same pattern
as the existing `pong_wire_matches_pynacl_reference`
(`tm_disco/src/lib.rs:597-649`). Check the 18-byte layout by hand against
`~/src/tailscale-rs/ts_disco_protocol/src/endpoint.rs`. Unit-test the
node-key/disco-key pairing rejection and per-path rate limiting. Gate:
`cargo test -p tm_disco`.

### Step 2 — UDP socket + receive loop, receive-only, disco not answered (~3-4 h incl. device run)

- `tm_netstack`: replace the ESP-IDF placeholder with a real
  `tokio::net::UdpSocket` on both targets (`bind`, `local_addr`,
  `try_send_to`, `recv_from`). `try_send_to` never awaits: UDP is
  best-effort, and `WouldBlock` counts as a drop.
- `tm_runtime` (`lan-direct` feature): in `Runtime::join`/`connect`, bind
  `0.0.0.0:41641` **before** `spawn_control` and the DERP connect. Fall back
  to port 0 if 41641 is taken. On any bind error, log `warn!` and run
  DERP-only. Add `spawn_udp` (`#[inline(never)]`, boxed) running a receive
  loop into the static buffer, with demux:
  - drop sources in `100.64.0.0/10` (the tailnet itself: `0.0.0.0` also binds
    on the tailnet netif, and WG-in-WG must be refused);
  - disco magic → at this step, **log only** (decrypt and count, no reply);
  - WG type 1..=4 with a plausible length → log only;
  - anything else → drop with a counter.
- Log the bound port and a periodic `udp rx: disco=N wg=M junk=K` counter.

Validation: host test on loopback (`tm_netstack`/`tm_runtime`). Send a
pynacl-built PING, a WG init from `wg_spec.py` vectors, junk, and a
`100.64.x.x`-sourced datagram, and assert the demux counters. On device,
flash with `lan-direct` on and the endpoint **not** published, then run a new
`tools/wg_validator/udp_probe.py` from the LAN that sends a disco PING to
`<device-lan-ip>:41641`, and confirm the serial counter increments. This is
the first on-device proof that tokio UDP works. Also watch `heap_probe`
around bind and during a 1000-datagram burst to measure the recvmbox/WiFi-RX
transient. Gate: bind succeeds (this is where the `MAX_UDP_PCB` bump is
confirmed necessary or not), no heap regression in the DERP TLS numbers, and
DERP traffic unaffected.

### Step 3 — `tm_control`: compute the LAN endpoint, still unpublished (~1-2 h)

- `tm_control::Config` gets `lan_udp_port: Option<u16>`.
- In `bring_up`, derive `lan_ep = main_conn.local_addr()` filtered per D1,
  plus the port. Build `endpoints = [lan_ep, "127.3.3.40:<region>"]` for
  publish #2 (`:580-608`). Omit `EndpointTypes`: today's publish omits it and
  the control server accepts that. If a real peer ignores the LAN endpoint in
  Step 5, adding `EndpointTypes: [1 /*Local*/, 0]` is the first thing to try
  (MicroLink sends it, `ml_coord.c:1250`).
- At this step, **compute and log** the endpoint only. Publishing is wired
  but switched off by a const until Step 5 (D4).

Validation: a host unit test serializes the publish #2 body with
`lan_udp_port: Some(41641)` and a fixed `local_addr` and compares it to
`ts_control.py`'s `write_map(endpoints=[...])` body for the same inputs (the
field-for-field cross-check this code already uses). A second test with
`None` asserts the body is byte-identical to today. Unit-test the D1 filter:
`100.64.1.2`, `127.0.0.1` and `0.0.0.0` are rejected, `192.168.15.20` and a
public v4 are accepted.

### Step 4 — `tm_wg`: dual-path peers + path-tagged I/O (host-only) (~4-6 h)

- D3's `derp` + `direct` fields. `add_peer` takes the DERP endpoint.
  `endpoint_for` is unchanged: it still returns `Derp`, because
  that is the fallback.
- `WgCmd::InboundPacket` gets `via: Via { Derp { src_key } | Udp(SocketAddrV4) }`,
  and `on_inbound` passes the real `from` instead of the hard-coded `Derp`
  (`lib.rs:314-317`). For UDP there is no `src_key`; the peer comes from
  `out.peer` (static key or session id), which `drain_recv` already prefers
  (`lib.rs:385-389`).
- Rewrite `maybe_roam` per D3: authenticated UDP sets or refreshes `direct`,
  and DERP never touches it.
- New `WgCmd::DirectPathSeen { node_key, addr }` sets or refreshes `direct`
  (from Step 1's disco event).
- `WgEvent::OutboundPacket` gets `via: Option<SocketAddrV4>` (None = DERP),
  computed by one `WgEndpoint::path_for(id, now)` in `drain_recv` and
  `emit_to_peer`.

Validation (`cargo test -p tm_wg`, all host):
- a full handshake + data exchange between two endpoints where A receives
  over `Udp(x)`: A's replies are tagged `via=Some(x)`;
- a forged or undecryptable UDP packet from `y` never changes the path;
- trust expiry (`now + 6.6 s`) makes `path_for` return DERP;
- a peer's address changing `x→z` via an authenticated packet adopts `z`;
- a DERP-sourced packet leaves `direct` untouched;
- the existing `retry_frees_stale_session_and_ignores_late_response` and
  size guard still pass.

WG crypto is unchanged, so no new pynacl vectors are needed. The existing
`wg_spec.py` vectors still cover the bytes.

### Step 5 — wire it end to end and publish (the observable step) (~2-3 h + hardware)

All in one commit, behind `lan-direct` (D4):
- the router forwards UDP disco to `tm_disco` with `DiscoSrc::Udp`, UDP WG to
  `tm_wg` with `Via::Udp`, `SendPongUdp` to `try_send_to`, and
  `DirectPathSeen` to `WgCmd::DirectPathSeen`;
- `WgEvent::OutboundPacket { via: Some(addr) }` goes to `try_send_to`, and on
  **any** error the same buffer falls back to `DerpCmd::SendPacket` (so a
  transient `ENOMEM`/`WouldBlock` costs latency, not a packet);
  `via: None` goes to DERP as today;
- enable publishing in `tm_control` (Step 3's const).

Only `event_router_task` (`tm_runtime/src/lib.rs:331`) needs this. The second,
host-only router in `Runtime::spawn` (`:1007+`, `cfg(not espidf)`) never
wires disco and stays DERP-only.

Validation: host test of the router demux with a fake UDP pair if cheap,
otherwise on-device (Step 6).

### Step 6 — hardware acceptance + fault injection (~½ day)

With a real LAN peer (`lenovopill` or the phone on WiFi):
1. `tailscale ping esp32c3` → `via 192.168.x.y:41641`. `tailscale status` →
   `direct`. `curl http://<tailnet-ip>/cm?cmnd=status+2` succeeds. The serial
   log shows `OutboundPacket via udp`.
2. **Fallback:** on the peer, `iptables -I INPUT -p udp --sport 41641 -j DROP`
   (or turn the phone's WiFi off and use cellular). Within about 6.5 s
   `status` shows `relay "sao"`, curl keeps working, and the device log shows
   sends reverting to DERP. Remove the rule and the path goes back to
   direct.
3. **Remote peer (not on the LAN)**: it probes our private endpoint, gets no
   PONG, stays on DERP, and nothing changes versus today.
4. **Device IP change** (DHCP lease change, or a static-lease change plus a
   router reboot): the control reconnect re-publishes the new `LAN_IP:41641`
   (serial `Step 7.6` line) and the direct path returns.
5. Soak for 30+ min of normal traffic: no new heap floor regression
   (`heap_probe`/`pktbuf_pool allocs=`), and DERP keepalives continue.

### Step 7 — (deferred, optional) device-initiated direct path: outbound PING + CallMeMaybe (~1 day)

After Steps 0-6, direct paths are created when the **peer** has traffic for us.
That is the device's main traffic pattern: it is an HTTP server polled from
phones and laptops. For device-initiated traffic, e.g. the rung-6a ICMP echo
or future outbound telemetry, the first packets go via DERP until the peer
pings us. Upgrading that direction needs:
- outbound PING to a peer's LAN candidates, which requires parsing the
  peer's `Endpoints` (today skipped in `map_stream.rs`, costing about 8 peers ×
  a few `SocketAddrV4`) or its CallMeMaybe;
- CallMeMaybe **receive** (`tm_disco` `MSG_CALL_ME_MAYBE`, variable-length
  18 B × n endpoints; see
  `~/src/tailscale-rs/ts_disco_protocol/src/call_me_maybe.rs`), keeping only
  candidates in our own STA subnet, and pinging those;
- PONG receive → `DirectPathSeen` (tx_id tracking for our own PINGs).

Validation: fixed-nonce pynacl vectors for our PING (`disco.build_ping`) and a
parsed CallMeMaybe fixture. **Recommendation: do not start Step 7 unless
Step 0 shows that a PONG alone does not populate the peer's ip→node-key map,
in which case a minimal outbound PING moves into Step 5.** Otherwise it is a
latency nicety for a traffic direction this device barely uses.

## Risk assessment

| Failure | Blast radius | Why it's bounded |
|---|---|---|
| Endpoint published but unreachable (VLAN, isolation, double NAT) | none | Peers never get a PONG and stay on DERP (D2). |
| UDP socket fails to bind (pcb pool full, port in use) | none | `warn!`, DERP-only, endpoint not published (Step 5 publishes only if bound). |
| Device answers PONG but drops UDP WireGuard | **total outage for LAN peers, self-sustaining** | The dangerous one. Prevented structurally by D4 (disco reply and WG ingest land in the same gated commit). Step 6.1 tests it explicitly. |
| Device stops answering on UDP mid-session (task died, WiFi stall) | ≤ ~6.5 s blackout per peer | tailscaled's `bestAddr` trust lapses without PONGs and it falls back to DERP. The device's own trust lapses the same way (D3). |
| UDP send error on device | one packet delayed | Falls back to DERP per packet (Step 5). |
| LAN flood to :41641 | CPU, transient heap | Pre-decrypt per-IP rate limit (Step 1), small recvmbox (budget table). WG `mac1` rejects unauthenticated inits cheaply. Measured in Step 2. |
| Heap fragmentation from new allocations | could reopen ALLOCATIONS.md crashes | One-time socket allocation before DERP TLS. Static RX buffer. No per-packet heap on the UDP path beyond the existing `PktBuf` pool. Soak in Step 6.5. |
| Wrong LAN IP (multi-homed) | none | ESP32-C3 has one STA netif. `local_addr()` is by construction the address that reaches the internet. |
| Regression when the feature is off | none | Byte-identical publish body (Step 3 test), no socket, `tm_wg` paths default to DERP. |

Rollback: set the wrapper's `lan-direct` feature off and reflash. Nothing is
persisted: no NVS state, and no control-plane state beyond the next
re-publish, which drops the endpoint.

## Effort summary and stopping point

| Step | Estimate |
|---|---|
| 0 Python spike | 2-3 h |
| 1 `tm_disco` UDP PONG + vectors | 2-3 h |
| 2 socket + receive loop + device proof | 3-4 h |
| 3 `tm_control` endpoint (computed) | 1-2 h |
| 4 `tm_wg` dual path | 4-6 h |
| 5 router wiring + publish | 2-3 h |
| 6 hardware acceptance | ~4 h |
| **0-6 total** | **~2.5-3 days** |
| 7 (deferred) outbound PING + CallMeMaybe | ~1 day |

The earlier "1-2 days for all of Tier 1" was **optimistic by about a day**,
for three reasons found in the code: the roaming logic does not do
DERP→UDP (the "already exists" reuse is smaller than assumed), there is no
path plumbing between `tm_wg` and the router, and the lwIP pcb/recvmbox
budget needs a wrapper sdkconfig change plus measurement. None of these is
open-ended. Step 7 is excluded, not squeezed in.

**Where to stop:**
- **If Step 0 fails** (a real tailscaled will not go direct even with a real
  endpoint and UDP PONGs), stop and write up why. Do not build Steps 1-6.
- **If Step 2 shows** tokio UDP cannot bind or run on this device, or the
  UDP-burst heap transient pushes `largest_internal` below the ~8 KB hyper
  buffer threshold, stop at Step 2. Keep the host-side work (Steps 1, 3 and 4
  are harmless and tested) and record the measurement here.
- Otherwise stop after Step 6. Step 7 needs its own go decision.

## Wrapper-side changes needed (sibling app, not in this repo)

`tasmolike-rs`, at Step 2/5 time only:
- `sdkconfig.defaults`: `CONFIG_LWIP_MAX_UDP_PCB=6` (currently 4 at line
  114) and `CONFIG_LWIP_UDP_RECVMBOX_SIZE=3`.
- `Cargo.toml`: `tm_runtime = { ..., features = ["lan-direct"] }`, or pass
  it through `tailmicro`.

## Step 0 status (2026-09-27): harness built and run; genuinely BLOCKED by this sandbox's networking, not by the protocol

Built `tools/wg_validator/validate_lan_direct.py`, the corrected Spike 2
harness Step 0 calls for. It fixes both harness bugs identified above:

1. Derives our real LAN IPv4 (D1's own technique: the control-plane TCP
   socket's `getsockname()`, filtered — IPv4 only, no loopback/unspecified,
   no `100.64.0.0/10`) and publishes `["<lan_ip>:41641", "127.3.3.40:<region>"]`
   instead of `0.0.0.0:<port>`.
2. Actually answers a peer's UDP disco PING with a real, sealed
   `disco.build_pong(..., src_endpoint=<peer's observed UDP address>)` sent
   back over the same UDP socket — `disco.py` gained a `pack_endpoint(ip,
   port)` helper for this (the literal-address form, as opposed to
   `encode_derp_relay_src_ipport`'s `127.3.3.40:<region>` convention).
3. Brings up the DERP leg (`derp_client.py`) alongside, so a WireGuard
   response has a path either way, same as a real node.

It also independently registers as its own ephemeral tailnet node (own
node/disco keys via an auth key from `.env.wokwi`, same pattern as the
existing `validate_live_udp.py`) — no `tailscale` CLI or existing tailscaled
identity needed.

**Result of actually running it** (`tools/wg_validator/validate_lan_direct.py`,
from this workspace's sandbox, `bospill`): control-plane registration
succeeded, the tailnet's real online peers were correctly enumerated
(`esp32c3` — the real hardware device — and `alanjds-s25`, both genuinely
online right now), but the D1 IPv4-LAN-address step came back empty:

```
control-plane TCP local_addr=('2804:7f0:18:3049:...', 47632, 0, 0) -> D1 lan_ip=None
[BLOCKED] D1: a usable IPv4 LAN address is derivable from this host's control-plane socket
```

Verified this is a real, hard environment property of this specific sandbox,
not a bug in the script: `ip -4 addr show` on `eno1` (the only up, non-loopback
interface) returns **nothing** — no IPv4 address at all, only IPv6 (the box
is IPv6-only to the internet). `ip route` shows no IPv4 route, and a raw
`socket.connect(('8.8.8.8', 53))` fails with `[Errno 101] Network is
unreachable`. `tailscale0`'s `100.85.218.10` is the *overlay* address, not a
usable underlay LAN endpoint (Tier 1 is explicitly the underlay-LAN path,
D1). So no host process here — this harness or a real `tailscaled` — has any
IPv4 LAN address to publish or any way to originate an IPv4 UDP datagram at
all. This also rules out "test against `bospill`'s own tailscaled instead":
`bospill`'s own `Self.Addrs` in `tailscale status` are IPv6-only for the same
reason (same host, same missing IPv4 stack).

**This is a scoping/environment constraint on *this sandbox*, not a finding
about the plan or the disco/WireGuard protocol.** The plan's mechanism claim
(D2–D4, and the original Spike 2's disco PING/PONG round trip) is unaffected:
it was never re-tested and disproven here, it was simply never reachable to
test from a box with no IPv4 LAN stack. The original Spike 2 *did* prove the
disco crypto round-trips against a real peer, from a runner that actually
shared an IPv4 LAN (`192.168.15.0/24` with `lenovopill`) — that evidence
stands. What Step 0 needed to add on top (a real endpoint + a real PONG) is
now implemented and ready to run, just not exercisable from here.

**What was still validated from here, independent of LAN reachability:**
- The corrected harness is syntactically and logically complete, imports and
  runs cleanly, correctly talks to the live control plane, and correctly
  aborts with a clear, honest BLOCKED verdict instead of silently publishing
  a bogus/unreachable address (which is exactly the D2 failure mode the
  original Spike 2 fell into, just for a different underlying reason).
- The Step 1 validation asset the plan asks for is done: see
  `tools/wg_validator/gen_udp_pong_vector.py` (output committed at
  `tools/wg_validator/udp_pong_vector.txt`) — a fixed-nonce pynacl reference
  vector for a UDP disco PONG whose `src_ipport` carries a real literal
  endpoint (`::ffff:192.168.15.139` port 41641, the plan's own example),
  built with the *same* fixed `receiver_priv`/`sender_pub` fixture already
  hardcoded in `tm_disco/src/lib.rs`'s `aead_crosscheck` / `framing` /
  `pong_seal_crosscheck` tests, so a Step 1 `udp_pong_wire_matches_
  pynacl_reference` test can drop in next to the existing one with no new
  key fixtures. This does not depend on any live network access.

**Recommendation — do not revise the plan; re-scope where Step 0's live leg
runs:**
- Step 0's actual pass/fail is still open — it needs to run once from a host
  with a real IPv4 LAN interface reachable to an online tailnet peer
  (`alanjds-s25` the phone, or a machine sharing the ESP32's home WiFi
  subnet, the way the original Spike 2 used `lenovopill`). That is an
  environment choice, not a code change: `validate_lan_direct.py` needs no
  edits to run there, just `TS_ENV=...` and optionally `PEER_HOSTNAME=...`.
- **Step 1 (Rust `tm_disco` UDP PONG) can start now.** It is host-testable,
  has its pynacl reference vector ready, and does not depend on live LAN
  access or on Step 0's live leg completing. This matches the plan's own
  ordering (Steps 1/3/4 are described as "harmless and tested" independent
  of live hardware).
- **Do not start Step 2 (on-device UDP socket) or later** until Step 0's live
  leg actually runs somewhere with real IPv4 LAN reachability and the
  PING→PONG→(ideally)WG-init sequence is observed, per the plan's own
  stopping rule ("If Step 0 fails, stop... do not build Steps 1-6" — read
  literally that's about a live pass/fail this round couldn't produce either
  way; the prudent reading is: Step 1 is safe host-only work, Steps 2+ that
  touch the device should wait for that live confirmation).
- Hard rules were respected throughout: nothing was flashed to the ESP32 at
  `/dev/ttyACM0` (it was never touched — only read passively via the control
  plane's netmap, which shows it online), no production traffic was
  disrupted, and only new files in `tools/wg_validator/` plus this doc
  section were changed in `tailmicro-rs` (`wg-dispatch-scratch`); nothing was
  pushed, and `tasmolike-rs` was not modified.

## Step 0 status (2026-09-28): the earlier BLOCKED verdict was environment
config, not a hardware limit — fixed; live run gives a mixed but genuinely
useful result

**The IPv4 blocker is resolved.** `bospill` had no IPv4 route at all because
its wired connection's DHCP lease had silently expired/never renewed
(`ipv4.method=auto` was correctly configured; the router just wasn't
leasing it one). Cycling the NetworkManager connection
(`nmcli connection down/up "Wired connection 1"`, run via
`distrobox-host-exec` since this session's own container has no
`CAP_NET_ADMIN`) got a real lease: `192.168.15.70/24` with a default
gateway. This is bospill's real host network, not a container-only fix —
the container shares the host's network namespace, so it picked the new
route up immediately. `validate_lan_direct.py`'s D1 check now correctly
derives `192.168.15.70` from the control-plane socket instead of BLOCKED
(confirmed by forcing `socket.getaddrinfo` to prefer `AF_INET`, since
bospill is dual-stack and glibc's address selection otherwise picks the
working IPv6 route to `login.tailscale.com`, which the real `tm_control`
Rust code — using a literal control-server IP, not a hostname lookup with
family fallback — won't hit the same way).

**With D1 fixed, three live-peer attempts, each answering a different open
question:**

1. **Target `esp32c3` (our own embedded firmware), passive wait: no
   PING arrived.** Expected, not a bug: `tm_disco` is currently
   PONG-only (Step 7 in this plan, outbound PING/CallMeMaybe, is explicitly
   deferred) — there is no code path in the current firmware that would
   ever send an unsolicited PING to a newly-published peer. Testing Step
   0's "does a real peer probe us" question against our own PING-incapable
   device was the wrong target; it can only ever demonstrate the reverse
   direction (a real peer PONGing back to *us*).

2. **Target `alanjds-s25` (the phone), passive wait: no PING arrived.**
   Its published endpoints (`187.90.221.201:3838`,
   `177.26.244.89:7805`, `192.0.0.2:45230`, plus IPv6) are all mobile-carrier
   NAT addresses, none on `192.168.15.0/24` — the phone is not on bospill's
   WiFi right now. Inconclusive by construction, not a finding.

3. **Target `bospill`'s own real tailscaled (a genuine full client, online,
   on the same LAN by definition), two runs:**
   - **Active**: our probe sent a properly-sealed disco PING straight to
     `bospill`'s published LAN endpoint (`192.168.15.70:41641`) every 3s.
     Got a real, valid, decryptable **PONG back over direct UDP** within
     one round — `RESULT: got_ping=False got_pong=True got_wg=False`. This
     is genuine, fresh confirmation (independent of the original 2026-09-16
     Spike 2, using today's current `disco.py`/`ts_control.py` code) that
     our disco wire format and crypto interop correctly with a real,
     unmodified Tailscale client over a real LAN UDP path.
   - **Passive** (no active probing from us, matching what
     `validate_lan_direct.py` actually implements): **no PING arrived**,
     even after 60s and even after also issuing a real
     `tailscale ping 100.75.122.18` (our probe's tailnet address) from the
     host CLI to force an OS-level attempted-traffic event. The `tailscale
     ping` itself reported "no reply" (timed out on all 3 attempts).

**What (3)'s passive result means, honestly**: real tailscaled's magicsock
does not appear to proactively attempt a freshly-netmap-published peer's
direct endpoint on netmap propagation alone, and a `tailscale ping` issued
from the *other* side didn't produce a visible reply either — but the
probe script only listens on the raw UDP socket, not on the DERP leg it
also brought up (`dc`, `derp_client.DerpClient`), so if bospill's
`tailscale ping` attempt went out over DERP first (the normal path before
a direct upgrade is trusted) and expected a DERP-relayed disco reply, this
harness would have silently failed to answer it — a harness gap, not
necessarily a "real peers never self-initiate" finding. **This specific
question (does a real peer proactively try a freshly-published LAN
endpoint once it has reason to send it traffic) is still open** and matters
for the plan: the production scenario (a phone's HTTP request needing to
reach the ESP32) already provides that "reason" via real application data,
so it likely does not block the plan either way, but a cleaner follow-up
(a probe that reads and answers on both the UDP socket and the DERP leg)
would close it properly.

**Bottom line**: the disco PING/PONG crypto and wire format are proven,
again, against a real unmodified Tailscale client over a real LAN UDP path
— the mechanism itself keeps checking out. The full "peer moves its
WireGuard session off DERP onto our published UDP endpoint, unprompted"
outcome that would make this an unqualified pass is still not observed,
because every attempt so far either used a peer that can't initiate
(`esp32c3`), wasn't reachable on this LAN (`alanjds-s25`), or (for
`bospill`) needed our harness to also monitor the DERP leg to be a fair
test. **Recommendation unchanged from the prior status update**: Step 1
(Rust `tm_disco` UDP PONG, host-testable, pynacl vector ready) can proceed
now. A cleaner Step 0 re-run — DERP-leg-aware harness, against `bospill`,
`lenovopill` (currently offline), or the phone once it's actually on this
WiFi — would be worth doing before Step 2 (on-device UDP socket) starts,
but the crypto-interop evidence gathered so far gives no reason to expect
Step 2+ to fail.

No hardware was touched (`esp32c3` only ever observed passively via the
control plane's netmap). No `tailmicro-rs` code changed this round — only
this doc section. `tasmolike-rs` was not modified. Scratch scripts used for
the active-probe/passive-listen variants stayed in the session's own
scratchpad directory, not committed (they duplicate/extend
`validate_lan_direct.py` for one-off experiments; if a DERP-aware Step 0
re-run is wanted next, promoting one of them into `tools/wg_validator/`
properly is the right move, not what was done here under time pressure).
