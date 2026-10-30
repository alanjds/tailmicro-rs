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

## Step 1 status (2026-09-28): done, host-tested, `tm_wg` unaffected

Implemented in `tm_disco/src/lib.rs` (host-only, no device flashing):

- `encode_derp_relay_src_ipport` generalized into `encode_src_ipport(SocketAddrV4,
  &mut [u8])`; the DERP-relay form is now a thin wrapper around it
  (`SocketAddrV4::new(127.3.3.40, region)`), so DERP-relayed PONGs keep
  byte-identical wire output -- confirmed by the existing
  `pong_wire_matches_pynacl_reference` test, still green.
- `MaybeDisco { src_ip, src_port, src_node_key }` replaced with
  `MaybeDisco { src: DiscoSrc, data }`, where
  `DiscoSrc { Derp { node_key }, Udp(SocketAddrV4) }` distinguishes which
  transport a disco datagram arrived on.
- Over UDP, `process()` now returns (up to two) `DiscoEvent`s instead of
  one: `SendPongUdp { dst, payload }` (with `src_ipport = dst`, the peer's
  own observed address, matching real tailscaled's expectation) plus
  `DirectPathSeen { node_key, addr }`.
- `AllowPeer([u8; 32])` -> `AllowPeer { disco_key, node_key }`. A UDP PING's
  claimed node key (plaintext body after `tx_id`: `tx_id(12) ||
  node_key(32)`) is checked against this pairing; a mismatch drops the
  packet silently (no PONG). DERP-sourced PINGs skip this check (DERP
  already authenticates the sender's node key via TLS+relay auth).
- Bug fix: the 100 ms PONG rate limit is now per `(peer, path)`
  (`last_pong_derp`/`last_pong_udp` on `PeerRateLimit`) instead of per
  peer, so tailscaled's back-to-back DERP+UDP probing no longer suppresses
  the UDP PONG.
- New cheap pre-decrypt rate limit per UDP source IP
  (`UDP_DECRYPT_RATE_LIMIT`, 100 ms, `MAX_UDP_RATE_IPS = 8` FIFO-evicted
  entries), gating the expensive X25519 DH before it ever runs, for UDP
  disco datagrams only.

Validation (Python-first, per this repo's habit): `tm_disco`'s
`pong_seal_crosscheck::udp_pong_wire_matches_pynacl_reference` cross-checks
`build_sealed_pong(..., PongSrc::Udp(192.168.15.139:41641), ...)`
byte-for-byte against `tools/wg_validator/udp_pong_vector.txt`'s pynacl
reference (unchanged from the prior round). New `udp_security` test module
covers the node-key/disco-key mismatch rejection and the per-(peer,path)
rate-limit fix end to end (self-sealed wire bytes via a test-local disco
keypair, not the pynacl fixture, since that fixture's `sender_pub` has no
matching private key available in Rust). `cargo test -p tm_disco`: 8/8
green (2 new `pong_seal_crosscheck` + `udp_security` groups added to the
existing `aead_crosscheck`/`framing` suites).

`tm_runtime/src/lib.rs`'s single `AllowPeer` call site (netmap peer loop)
and both `MaybeDisco` construction sites (the `espidf` event router and the
host-only `Runtime::spawn` router) were updated to the new field names/
`DiscoSrc::Derp` wrapping; `DiscoEvent::SendPongUdp` and `DirectPathSeen`
got new match arms that log and drop (Step 2 wires them to a real UDP
socket -- there isn't one yet, by design of this round's scope). This round
ran concurrently with an unrelated heap-fragmentation investigation with
live uncommitted changes in `tm_runtime`/`tm_wg` (a new `forward_or_drop`
non-blocking-send helper, `tm_wg::heapdiag`); those were read via `git
diff` first and edited around, not touched or reverted.

**Gate status**: `cargo test -p tm_disco` is 8/8 green. `cargo check -p
tm_wg` is clean (untouched by this round). `cargo check -p tm_runtime`
could **not** be run here at all, on either the pre- or post-change tree:
`tm_runtime`'s `esp-idf-sys`/`esp-idf-svc` deps are not `cfg`-gated to
`target_os = "espidf"`, and `esp-idf-sys`'s build script refuses any
non-espidf target outright (`Error: Unsupported target
'x86_64-unknown-linux-gnu'`) with no `IDF_PATH`/esp toolchain installed in
this sandbox -- confirmed pre-existing by reproducing the identical failure
via `git stash`. This is the same limitation `tm_runtime`'s own test-module
doc comment already documents. The `tm_runtime` edits were instead verified
by careful manual diff review against `tm_disco`'s new API (field names,
enum variants, `PeerInfo::{disco_key,node_key}`) and by confirming no other
crate in the workspace references the old `MaybeDisco`/`AllowPeer` shapes
(repo-wide grep). A real espidf toolchain (or a future `cfg`-gate fix) is
needed to close this gap with an actual compile.

## Step 2 status (2026-09-29): done, host-tested and verified on the ESP32-C3

Implemented:

- `tm_netstack`: `UdpSocket` is now a real `tokio::net::UdpSocket` on both
  targets (`bind`/`bind_sync`, `local_addr`, `send_to`, `writable`,
  `try_send_to`, `recv_from`). `NetError` gained `WouldBlock` and a
  `From<std::io::Error>`. The demux and receive loop live in the new
  `tm_netstack::lan_udp`, not in `tm_runtime`, because `tm_runtime` cannot
  be built on the host (its `esp-idf-sys` dependency is unconditional, see
  the Step 1 status). It covers `classify()` (a `100.64.0.0/10` source wins
  over any payload; disco magic plus at least 80 B; WireGuard type 1..=4
  with an exact or minimum length and zero reserved bytes; everything else
  is junk), `RxStats` atomics, `bind_lan()` (41641, then port 0),
  a once-only static receive buffer of `PKT_CAP` bytes, and `rx_loop()`.
  `rx_loop` logs `udp rx: disco= wg= junk= tailnet= err= (heap ...)` at most
  every 10 s and only when a counter changed, so a flood cannot saturate the
  UART (the Step 8 lesson). It backs off 50 ms after a receive error and
  gives up after 16 consecutive errors.
- `tm_runtime`, behind the new `lan-direct` feature (off by default; also
  re-exported as the root crate's `lan-direct`): the socket is bound in
  `Runtime::build` before `spawn_control`, so before both the control and
  the DERP TLS handshakes. Heap-block probes run before and after the bind.
  A boxed `udp_rx_task` runs the loop. Only the first disco and the first
  WireGuard datagram are logged at info level; the rest go to trace. With
  the feature off, `tm_runtime` compiles to what it was before.
- `tools/wg_validator/gen_udp_demux_vectors.py` writes a pynacl-built disco
  PING (124 B, fixed nonce) and a `wg_spec.build_initiation` message (148 B)
  as hex vectors. `tools/wg_validator/udp_probe.py` (`probe` mode, and
  `burst N [SIZE] [PPS]` mode) is the on-device LAN probe.

Deviations from the plan text, stated plainly:

- Disco datagrams are **counted by framing, not decrypted**. The receive
  task has no disco private key at this step, and decrypting would spend an
  X25519 DH on each unsolicited LAN datagram. That work belongs to Step 5,
  where the datagram goes to `tm_disco`, which already has the per-IP
  pre-decrypt rate limit from Step 1.
- A `100.64.x.x`-sourced datagram cannot be produced over loopback, so the
  tailnet-source drop is covered by the `classify` unit tests
  (`classify_tailnet_source_wins_over_payload`), not by the loopback
  end-to-end test.
- `CONFIG_LWIP_UDP_RECVMBOX_SIZE=3` is impossible: its Kconfig range is
  6..64, and ESP-IDF silently clamped it to 6, which the generated
  `sdkconfig` confirmed. The wrapper stays at the default of 6. Measured
  below, 6 is fine. If it ever needs tightening, `CONFIG_LWIP_SO_RCVBUF`
  plus `SO_RCVBUF` is the lever, not the mbox size.
- For Step 5, note that tokio's `try_send_to` returns `WouldBlock` until
  the reactor has seen the socket writable once. The loopback test hit
  this. The send path must `await writable()` once after bind (or poll
  `send_to` once), or the first PONGs and WireGuard replies are silently
  counted as drops.

**`MAX_UDP_PCB` bump: not needed.** The wrapper's
`CONFIG_LWIP_MAX_UDP_PCB=4` is not a real Kconfig symbol, so ESP-IDF ignores
it. The real symbol is `CONFIG_LWIP_MAX_UDP_PCBS`, which is effectively 16.
The same misspelling pattern affects the wrapper's `NUM_TCP_PCB` (real:
`LWIP_MAX_ACTIVE_TCP`, 16), `MAX_LISTENING_PCB` (real:
`LWIP_MAX_LISTENING_TCP`, 16) and `MAX_RAW_PCB` (real: `LWIP_MAX_RAW_PCBS`,
16). Those lines have never had any effect; that is worth a separate cleanup
in the wrapper. The bind on the device succeeded on 41641 on every boot.

Host validation: `cargo test -p tm_netstack` passes 5/5:
`classify_real_vectors`, `classify_tailnet_source_wins_over_payload`,
`classify_junk`, `try_send_to_never_blocks_and_reports_the_bound_port`, and
`rx_loop_demuxes_over_loopback`. The last one sends the real PING, the real
init, junk, an oversize datagram and a second PING, and asserts disco=2
wg=1 junk=2.

Device validation (ESP32-C3, wrapper built with `tm_runtime/lan-direct`,
endpoint not published, LAN IP 192.168.15.74). This is also the first real
espidf compile of `tm_runtime` since the Step 1 router edits, which closes
the gap that section left open.

- Bind: `lan-direct: UDP socket bound on 0.0.0.0:41641`, before the control
  Noise handshake. It cost 448-456 B of heap and 7 allocations, and the
  largest free block did not change (94208 before and after). This was
  identical across 3 boots.
- `udp_probe.py probe` (1 PING, 1 WG init, 1 junk): the device logged the
  first disco datagram (124 B, from 192.168.15.70) and the first WireGuard
  datagram (type 1, 148 B), then `udp rx: disco=1 wg=1 junk=1 tailnet=0
  err=0`, an exact match.
- Bursts of 1000 datagrams of 1400 B each, with the tailnet up (DERP
  connected, both peers handshook):
  - unpaced (about 93k pps from the host): 6 arrived, and the rest were
    dropped before the socket, by the WiFi or lwIP layers;
  - 200 pps: 964/1000 counted;
  - 1000 pps: 525/1000 counted.

  Across all bursts: zero `ALLOC FAILED`, zero resets, zero receive errors,
  and the loop never stopped. The `heap-watch` minimum of largest-free
  during the 1000 pps burst was 22528 B, with 36344 B total free. That is
  1 KB below the 23552 B the same boot reached during its DERP TLS
  handshake. It recovered to 27648 B right after. The `udp rx` heap sample
  after each burst was back at its baseline (27648 largest, about 43.4 KB
  total). So the recvmbox/WiFi-RX transient is real but small, and bounded
  by the mbox of 6.
- Tailnet HTTP (`curl http://<tailnet-ip>/cm?cmnd=Status` over DERP)
  returned 200 before, between and after the bursts.

A/B heap cost, lan-direct OFF against ON. The first pass (two clean boots
of each build at the Step 2 commit) looked like this:

| Checkpoint | OFF | ON | Delta |
|---|---|---|---|
| Heap after loading keys | 115248-115268 | 113600 | -1.65 KB (the static RX buffer in `.bss` shrinks the heap region) |
| Heap after device connect | 62208 | 59388-59412 | -2.8 KB |
| DERP `before tls.open`, total free | 48048-48188 | 45092-45144 | -3.0 KB |
| DERP `before tls.open`, largest free | 36864 | 34816 | -2 KB |

**Correction, from more boots during Step 4:** two samples per build were
not enough. The later checkpoints vary by about 2.5-3 KB from boot to boot
of the *same* firmware. At the Step 4 tree with lan-direct OFF, two boots
gave 59312 and 61804 after device connect, and 44448/34816 and 47804/36864
before `tls.open`. Two lan-direct ON boots at the same tree gave 58876 and
58844, and 40996/30720 and 44780/34816. Both builds land in the 30720-36864
largest-block range across boots. The first-pass "-3 KB" was mostly this
noise. What is firm and reproducible is:

- 1.6 KB of `.bss` for the RX buffer and stats, visible in `heap_init`'s
  region length and in "Heap after loading keys" on every boot;
- 448-456 B of heap for the socket, measured directly around the bind on
  every boot.

That is the plan's 2-2.5 KB estimate. The DERP TLS handshake and both peer
handshakes completed on every boot of every build. To tell a real Step 5
regression from this noise, compare several boots per build, not one.

## Step 3 status (2026-09-29): done, host-tested, computed-and-logged on the ESP32-C3

Implemented:

- `tm_control::Config` gained `lan_udp_port: Option<u16>`. The app's
  `control_config()` sets it to `None`. `tm_runtime` (under `lan-direct`)
  overwrites it with the socket's actual bound port, which covers the
  port-0 fallback.
- `tm_control::lan_endpoint(local, port)` is the D1 filter. It accepts IPv4
  only, and rejects unspecified, loopback, `100.64.0.0/10` and port 0.
- Publish #2's body builder is factored out into `publish2_body(node, disco,
  region, lan_ep)`. `lan_ep` goes first in `Endpoints` and the
  `127.3.3.40:<region>` entry second. `EndpointTypes` is still omitted, as
  the plan says.
- `bring_up` computes `lan_ep` from `main_conn.local_addr()` and logs it.
  It passes it into the body only when the private const
  `PUBLISH_LAN_ENDPOINT` is true. That const is `false`, and Step 5 flips it
  (D4).

Validation, `cargo test -p tm_control`, 15/15 green:

- `publish2_with_lan_endpoint_matches_ts_control_write_map`: the body is
  compared, as parsed JSON, with the body that `ts_control.py`'s real
  `write_map()` produces for the same inputs. That reference is captured by
  `tools/wg_validator/gen_publish2_lan_vector.py` into
  `publish2_lan_body.json`, with the transport stubbed. The comparison is on
  parsed JSON because Python orders and spaces keys differently. The one
  intended difference, `Hostinfo.OS` ("linux" in the Python probe), is
  patched explicitly in the test.
- `publish2_without_lan_endpoint_is_byte_identical_to_derp_only`: with
  `None`, the bytes equal what the old inline code built. This holds with
  the feature on (as long as the const is off) and with it off.
- `lan_endpoint_filter_per_d1`: 100.64.1.2, 100.127.255.254, 127.0.0.1,
  0.0.0.0 and an IPv6 address are rejected, as is port 0. 192.168.15.20,
  8.8.4.4, 100.63.0.1 and 100.128.0.1 are accepted.
- `lan_endpoint_publishing_is_still_off` guards the const.

On the device (lan-direct build): `lan-direct: LAN endpoint
192.168.15.74:41641 computed, not published yet`, followed by the usual
DERP-only re-publish. Both peers handshook and tailnet HTTP returned 200. A
LAN peer's `tailscale status` for the device shows no `Addrs` and relay
`sao`, which confirms nothing was advertised.

## Step 4 status (2026-09-29): done, host-tested, compiled and booted on the ESP32-C3 (inert)

Implemented in `tm_wg`:

- `Peer.endpoint` is split into `derp: Endpoint` (always present, never
  torn down) and `direct: Option<DirectPath { addr: SocketAddrV4,
  trust_until: Instant }>`. `DIRECT_TRUST` is 6.5 s. `add_peer` takes the
  DERP endpoint. `peer_endpoint` still returns it, and `endpoint_for` is
  unchanged.
- `WgEndpoint::path_for(id, now) -> Option<SocketAddrV4>` returns the
  direct address while `now < trust_until`, and `None` (DERP) otherwise.
  `drain_recv` and `emit_to_peer` both use it, so handshakes, keepalives
  and data follow one rule. In `drain_recv` it is evaluated after
  `recv_one_into`, so the reply to a packet that just proved a UDP path
  goes back over that path.
- `maybe_roam(peer, from, now)` sets or refreshes `direct` only for a UDP
  IPv4 source. DERP never touches it, and IPv6 is ignored. It runs only
  after authentication:
  - a transport packet that decrypted (including the replay window);
  - the transport packet that confirms a responder handshake;
  - (new) a handshake response that `finish()` accepted.
- **Deviation, deliberate:** a handshake *initiation* no longer roams. The
  old code did roam on an initiation. An initiation is not proof of the
  source address: it can be re-sent from anywhere, and the existing replay
  check (`hs.timestamp < last`) lets an equal timestamp through. The path
  is adopted one packet later, when the handshake completes. In practice
  tailscaled establishes trust by disco first, via `DirectPathSeen`, so
  this costs nothing.
- `WgCmd::InboundPacket { via: Via, payload }` with `Via { Derp { src_key },
  Udp(SocketAddrV4) }`. `on_inbound` passes the real transport as `from`.
  Over UDP there is no fallback key: if the packet names no known peer,
  nothing is emitted.
- `WgCmd::DirectPathSeen { node_key, addr }` becomes
  `WgEndpoint::direct_path_seen`, which does nothing for an unknown peer.
  It does not force the lazy endpoint into existence.
- `WgEvent::OutboundPacket` gained `via: Option<SocketAddrV4>`.

`tm_runtime`: both `InboundPacket` construction sites send
`Via::Derp { src_key }`. The router ignores `OutboundPacket.via`, and
everything still goes to DERP. `DiscoEvent::DirectPathSeen` is still only
logged and is **not** forwarded to `tm_wg`, on purpose. Forwarding it now
would switch sends to a path whose replies cannot be ingested yet (D4).
Step 5 does both at once.

Validation, `cargo test -p tm_wg`, 32/32 green. New tests:

- `udp_path_is_adopted_from_authenticated_packets_and_used_for_replies`:
  an init over UDP sets nothing. A response over `Udp(xb)` sets A's path,
  so A's confirmation is routed to `xb`. The confirmation over `Udp(xa)`
  sets B's path. Data keeps the path warm, and 10 s of silence lets it
  lapse.
- `forged_or_undecryptable_udp_never_changes_the_path`: from `y`, none of
  these moves the path from `x`:
  - a genuine packet replayed;
  - a packet with the right receiver id and corrupted ciphertext;
  - a re-sent initiation;
  - non-WireGuard junk.
- `trust_expires_after_6_5_s_and_sends_revert_to_derp`: the path is set at
  +6.4 s and gone at +6.6 s, and the DERP route is still present.
- `authenticated_packet_from_a_new_address_moves_the_path`: `x` to `z`, with
  trust refreshed to `t1 + 6.5 s`.
- `derp_sourced_packets_leave_the_direct_path_untouched`: DERP data is
  accepted but neither moves nor refreshes `direct`. A DERP-only handshake
  never creates one.
- `direct_path_seen_sets_and_refreshes_trust` (including an unknown peer)
  and `ipv6_udp_source_is_ignored`.
- `tests::replies_to_udp_inbound_are_tagged_with_the_udp_path` runs a real
  `WgActor`. It checks, on actual `WgEvent`s:
  - the proactive initiation from `ApplyMap` is `via: None`;
  - after a handshake response arrives as `Via::Udp(x)`, the confirmation
    is `OutboundPacket { via: Some(x) }`, and the independent `WgEndpoint`
    peer accepts it;
  - a junk UDP datagram emits nothing.
- The existing `retry_frees_stale_session_and_ignores_late_response`,
  `full_handshake...`, `send_data...` and `wgendpoint_fits_fragmented_heap`
  tests still pass.

Size: `WgEndpoint` went from 5968 B to 6224 B (+32 B per peer, `Peer` is
now 736 B on the host). That is within the 8 KB guard, and it is `.bss`,
not heap.

Device: the wrapper builds with and without `lan-direct`. Both builds were
flashed and booted. DERP connected, both peers handshook, and tailnet HTTP
returned 200. No resets and no `ALLOC FAILED`. Heap numbers are in the
Step 2 correction above. Step 4 changes nothing on the air, as intended.

**Not done, by instruction:** Step 5 (UDP PONG, UDP WireGuard ingest,
forwarding `DirectPathSeen`, routing `via` to the socket, flipping
`PUBLISH_LAN_ENDPOINT`). Notes for whoever does it:

- Prime the socket (`writable().await` once after bind) before relying on
  `try_send_to`; see Step 2.
- The UDP rx task needs a path into `tm_disco` (`DiscoSrc::Udp`) and into
  `tm_wg` (`Via::Udp`). The `tm_buf` pool is 4 buffers, so the copy out of
  the static RX buffer should use `PktBuf::from_slice`, and a WireGuard
  flood must be dropped with `forward_or_drop` rather than awaited.

## Step 5 status (2026-09-29): done, landed as one D4 commit plus two follow-ups

Commits on `wg-dispatch-scratch` (not pushed):

- `4aeb646` `tm_wg`: DERP hold-off and a strict initiation replay check.
  Both were found on hardware in Step 6. They only matter once a direct
  path exists.
- `44c5a83` Step 5 proper (D4). UDP PONG, UDP WireGuard ingest, `via`
  routing and `PUBLISH_LAN_ENDPOINT = true` land together.
- `c7afc96` disco PINGs may take the second-to-last pool buffer (Step 6
  soak finding).

What Step 5 wires (all in `event_router_task`; the host-only
`Runtime::spawn` router stays DERP-only):

- `udp_rx_task` primes the socket with `writable().await` before its first
  receive. It then copies each accepted datagram with
  `PktBuf::from_slice` and hands it on with `forward_or_drop`:
  - disco goes to `DiscoCmd::MaybeDisco { src: DiscoSrc::Udp }`;
  - WireGuard goes to `WgCmd::InboundPacket { via: Via::Udp }`.
- Pool floor. There is no fresh heap allocation per datagram.
  - A WireGuard datagram is dropped, and counted as `pool_drop`, when
    fewer than 2 of the 4 pool buffers are free.
  - A disco datagram is dropped only when none is free. It is also
    counted separately as `pool_drop (disco N)`.
  - So a LAN flood can neither force the ~1.5 KB heap fallback nor starve
    DERP.
- `OutboundPacket { via: Some(addr) }` calls `try_send_to`. On any error
  the same buffer goes to `DerpCmd::SendPacket`. The hardware runs had
  `fallback=0` throughout.
- `SendPongUdp` goes out on the socket. `via: None` goes to DERP as before.
- `tm_control` publishes `LAN_IP:41641` in the Step 7.6 re-publish. It
  only has an effect when the feature is on and the bind succeeded.
- Counters: a periodic `udp rx:` line reports `tx: wg/fallback/pong/
  pong_err` and `pool_drop`. Path changes log once per change, as
  `OutboundPacket via udp <addr>` or `via DERP again`, never per packet.

**Deviation from D3(a), deliberate.** `DiscoEvent::DirectPathSeen` (a
received PING) is logged but not forwarded to `WgCmd::DirectPathSeen`
(`DISCO_PING_SETS_SEND_PATH = false`).

- A PING is one-way evidence: it proves the peer can reach us, not that we
  can reach it. tailscaled keeps pinging our endpoint about every 3 s while
  it has traffic.
- With (a) on (build B below), a blocked return path left the device
  sending into it for the whole outage.
- The send path is now adopted only from authenticated WireGuard received
  over UDP (D3(b)). That is also how tailscaled itself behaves: it adopts
  a path only on a PONG to its own PING.

**Two `tm_wg` fixes that D3 did not anticipate** (commit `4aeb646`).
Both come from one tailscaled behaviour: once its bestAddr trust lapses,
it sends every WireGuard packet over BOTH UDP and DERP
(`addrForSendLocked`).

- *DERP hold-off* (`DERP_HOLDOFF = DIRECT_TRUST = 6.5 s`).
  - The problem: in send-both mode, UDP copies kept arriving and kept
    refreshing our direct trust while our own UDP transmits were being
    lost (build C: black hole).
  - The fix: any WireGuard message from a peer arriving over DERP now
    holds our sends to that peer on DERP for 6.5 s. It needs no decrypt,
    and replays count. A DERP arrival means the peer itself no longer
    trusts the direct path.
- *Strict initiation replay check.* `recv_init` now rejects
  `timestamp <= last`, as wireguard-go does with
  `!timestamp.After(last)`. Before this it rejected only `<`.
  - The problem: under send-both, each initiation arrives twice. Both
    copies were answered, and the second answer replaced the pending
    handshake. That forced a re-handshake, seen as a 16-45 s curl outage
    in build D.
  - The regression test is
    `duplicate_initiation_is_answered_once_and_the_handshake_completes`.
    It fails on the old `<`.
- The per-packet "replay / stale nonce rejected" log moved from `warn` to
  `debug`. Send-both makes it fire once per duplicate, and UART output
  throttled the data plane.

**Test-only feature `lan-direct-fault-test`.**

- It makes the device silently drop its own direct UDP transmits for 60 s
  of every 300 s, counted from the first direct send, while still
  receiving.
- From the peer's side this is the same as `iptables -I INPUT -p udp
  --sport 41641 -j DROP` on the peer. This host has no `sudo`, so that
  rule could not be used here.
- Never enable it in a shipped build.

Host tests: tm_wg 34/34, tm_control 15/15, tm_netstack 5/5, tm_disco 8/8.
`tm_runtime` cannot be built for the host in this checkout
(`esp-idf-sys`), so it was verified by the wrapper firmware build with the
feature on and off.

## Step 6 status (2026-09-29): all five criteria exercised on the ESP32-C3; 4 only partly

The rig:

- Device: ESP32-C3 (`esp32c3`, 192.168.15.74) running the wrapper firmware
  with `tm_runtime/lan-direct` enabled for the test builds only. The
  wrapper's `Cargo.toml` was restored afterwards.
- Real tailscaled peers on the same WiFi:
  - `bospill`, 192.168.15.70, node `b781..`: the host all measurements
    were taken from.
  - `lenovopill`, 192.168.15.139, node `0e63..`.
  - the phone `alanjds-s25`, 192.168.15.158, node `959c..`, which joined
    the WiFi late in the session.
- Observer: once per iteration (about every 2 s), bospill recorded
  `tailscale status` for esp32c3 plus `curl --max-time 3
  /cm?cmnd=status+2`.
- A rootless extra tailscaled peer, used as a fault harness, was
  considered and not used. Registering new nodes was out of bounds. Fault
  injection is device-side instead (see Step 5).

Builds, in order:

| build | what changed | result |
|---|---|---|
| A | Step 5 as planned (D3(a) on) | criterion 1 passes |
| B | fault test, D3(a) on | black hole for each whole 60 s block, curl 0/14 both times |
| C | D3(a) off | still black-holed (peer send-both keeps UDP arriving); one block recovered at 37 s, the next never |
| D | + DERP hold-off | device back on DERP in 4.7 s / 5.2 s, but 16-45 s curl outages from double-answered initiations |
| E | + strict init replay | fallback works; see criterion 2 |
| F | final code minus `c7afc96`, no fault | 13 min with curl, then 4.5 h idle |
| G | final code (`c7afc96`), no fault | 47 min soak, 3 LAN peers with traffic |
| H | feature OFF (DERP-only) | same-load baseline for G |

**1. Direct path from a real peer: PASS, from all three LAN peers.**

- bospill (build A):
  - The endpoint was published about 20 s after boot. bospill PINGed over
    UDP, got a PONG, and moved its WireGuard to UDP about 2 s later.
  - `tailscale status` showed `active; direct 192.168.15.74:41641`.
  - `tailscale ping esp32c3` returned `pong ... via 192.168.15.74:41641
    in 201ms`. `--icmp` answered in 234 ms. `--tsmp` did not answer, as
    expected: TSMP was never implemented (wg-dataplane-notes).
  - curl returned 200 three times out of three.
  - Serial showed `OutboundPacket via udp 192.168.15.70:41641`.
  - Builds F and G confirmed it again (ping via 192.168.15.74:41641 in
    292-430 ms, `direct` in status).
- lenovopill: when it had curl traffic, the device sent to
  192.168.15.139:41641. bospill's status also showed lenovopill direct at
  that LAN address. A disco-only `tailscale ping` loop from lenovopill did
  not move the device's send path, as designed, because only
  authenticated WireGuard does.
- Phone:
  - Earlier in the session it was on cellular: `tailscale ping` went via
    a carrier IPv6 address. That was the "before" field report, where the
    phone on the same WiFi still went via DERP.
  - Once it was on the WiFi and generating traffic, the device adopted
    192.168.15.158:45230 and logged `OutboundPacket via udp
    192.168.15.158:45230`.
  - The user confirmed on the phone that the Tailscale app shows esp32c3
    with its direct IP, not DERP, and that HTTP and ping work from it.

**2. Fallback when the direct path breaks: PASS, with DERP-quality service
during the outage.** Build E, two 60 s blocks:

- The device stopped sending direct 4.5 s and 1.5 s after the block
  started (hold-off triggered by the peer's DERP copies). The peer showed
  `relay "sao"` within about 3-8 s.
- The device went back to direct 7.2 s after each block was lifted.
- curl over the relay:
  - Block 1: 7 of 20 failed. 2 failed in the switch-over itself. 2
    failed around a routine 120 s rekey that completed over DERP (the
    duplicate initiation was rejected, as intended). 3 were isolated
    3 s timeouts.
  - Block 2: 1 of 22 failed.
  - Outside the blocks: 6 of 256 failed.
  - Relay median latency was 1.6 s, against 1.0 s direct.
- There was no black hole and no re-handshake storm. Compare builds B-D,
  where each block was a near-total outage.

**3. Remote peer unaffected: PASS.** While the phone was on cellular, it
handshook with the device over DERP on every boot and kept working. An
off-LAN peer has no route to 192.168.15.74, so it never gets a UDP PONG
and stays on DERP.

**4. Device IP change: re-publish shown, the IP change itself NOT
tested.** The endpoint is recomputed from the control socket's local
address on every control (re)connect, in the Step 7.6 re-publish. Two
natural control reconnects (build C at 335 s, build F at 4 h 28 min)
each logged `publishing LAN endpoint 192.168.15.74:41641` again. Peer
PINGs and PONGs resumed afterwards. Forcing a DHCP change needs router
access this session did not have. The expected path is that lwIP aborts
TCP connections on an address change, control reconnects, and the new IP
is published. That path is reasoned, not observed.

**5. Soak: PASS on heap. Throughput under heavy multi-client load is
limited by the device, not by this feature.**

Build F: 4.5 h, the first 13 min with bospill curl, then idle apart from
peer keepalives.

| window | largest_free (median) | total_free (median) |
|---|---|---|
| each 30 min slice to 4 h | 28672 | 42656 |

- The heap was flat for 4 h.
- After the control reconnect at 4 h 28 min, largest_free settled at
  20480 (a transient low of 15872 during the Noise handshake). That is
  the control path, not UDP.
- DERP stayed up and there were no resets.

Build G: 47 min. bospill curl ran throughout. From about 15 min on,
lenovopill also ran curl every 5 s and the phone ran ping every 2 s plus
HTTP every 5 s.

- Heap: each 10 min slice had a largest_free median of 24576 (minimum
  21504) and a total_free median of about 38.5K. The heap-watch floor was
  17408, set once at 14 min. There was no downward trend, no ALLOC
  FAILED, and no reset.
- Counters at 47 min:
  - rx: disco 2678, wg 6967.
  - pool_drop 925, of which disco 78.
  - tx: wg 5622, pong 2599, fallback 0, pong_err 0.
- WireGuard pool drops were about 13% under three concurrent clients.
  TCP recovers them, but they cost latency.
- Spontaneous direct-to-DERP flaps for bospill:
  - Build F (before `c7afc96`): 3 in 13 min. Each lined up with a 10 s
    window where PINGs arrived and no PONG left, while `pool_drop`
    climbed.
  - Build G: 2 in 47 min, and those under three times the load.
- lenovopill and the phone logged more `via DERP again` lines. Their
  5-second request cadence lets the 6.5 s trust window lapse between
  requests. That is the designed behaviour.

Same-load comparison, bospill curl with a 3 s timeout while all three
peers' loops ran:

| build | path | curl failed | 200 median / p90 |
|---|---|---|---|
| G, lan-direct | direct | 322 / 638 (50%) | 1.55 s / 2.59 s |
| H, feature off | relay "sao" | 113 / 167 (68%) | 1.89 s / 2.94 s |

The high failure rate in both is the device's HTTP server being saturated
by three clients, not the path. With bospill alone (G's first 15 min,
F), failures were about 1-2%. lan-direct did better than DERP-only under
the same load. Build H's heap was comparable: largest_free median 25600,
total_free median 42616.

**Bottom line.**

- The direct path works with real tailscaled peers (desktop, laptop and
  Android).
- Fallback is bounded by the 6.5 s trust window, and DERP remains the
  floor.
- Heap is flat over 4.5 h.
- DERP-only behaviour is unchanged with the feature off.

Remaining caveats before calling it shipped:

- The IP-change case (criterion 4) is only reasoned.
- WireGuard `pool_drop` is about 13% under heavy concurrent load. It
  could be tuned by revisiting the 2-buffer floor or `POOL_N`.
- A few extra 3 s curl timeouts happen during a real path break.
