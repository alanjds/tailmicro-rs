# Plan (a): expose the local HTTP port on the tailnet via an lwIP netif

## Goal

Make the device's existing HTTP server reachable over its tailnet IP
(`100.x.y.z:80`), exactly as it is already reachable over its WiFi DHCP IP.
The success test is: from any tailnet peer (e.g. `bospill`),
`curl http://<node-tailnet-ip>/` returns the same response that
`curl http://<node-wifi-ip>/` returns today.

## Why nothing in the HTTP server needs to change

The app binds the server to `0.0.0.0:80` with a `tokio` `TcpListener`
(`tasmolike-rs/src/main.rs:162-168`). On ESP-IDF `tokio::net` is backed by
lwIP BSD sockets, and a `0.0.0.0` bind accepts connections on **every** IP
that lwIP has a netif for. lwIP has a netif for the WiFi IP (created by
esp-netif from DHCP), which is why the WiFi IP already works.

lwIP has **no** netif for the tailnet IP. The tailnet IP lives only inside
`tm_wg` (userspace WireGuard) and is never presented to lwIP. So the fix is
entirely below the socket layer: give lwIP a netif that owns the tailnet IP
and is plumbed to `tm_wg`. The moment that netif exists and is `up`, the
existing `0.0.0.0:80` listener starts accepting tailnet connections with zero
application changes.

## Current state (the seam we are replacing)

Inbound decrypted packets are handled by hand in the event router
(`tm_runtime/src/lib.rs:451-473`): a decrypted IP packet is inspected and, if
it is an ICMP echo request to `our_ip`, an echo reply is hand-built
(`build_icmp_echo_reply`, `tm_runtime/src/lib.rs:215`) and sent back via
`WgCmd::SendData`. Everything else (a TCP SYN to port 80, DNS, anything) is
logged and dropped. The code comment states the intent directly:

> tm_netstack has no on-device lwIP injection path yet (it is a stub), so we
> surface it here; this is the seam where a transport round-trip becomes
> observable.

`tm_netstack/src/lib.rs` confirms the chosen architecture: **do not** add
smoltcp; reuse ESP-IDF's lwIP and inject decrypted packets into it. That
injection path was never built. This plan builds it.

## Architecture: a point-to-point (tun-style) lwIP netif

Add one virtual lwIP netif that:

- owns the node's tailnet IPv4 address (`our_ip`, a `100.64.0.0/10` CGNAT
  address assigned by the control plane),
- has **no** L2 / Ethernet / ARP (it is a raw IP interface,
  `NETIF_FLAG_POINTTOPOINT`, like a `tun` device),
- delivers received IP packets up into lwIP via `tcpip_input()`,
- emits transmitted IP packets down to `tm_wg` for encryption via its
  `output` callback.

```
                 tailnet peer (bospill)
                        |  encrypted WG-over-DERP
                        v
 tm_derp  --RecvPacket--> tm_wg (decrypt) --WgEvent::InboundDecrypted-->
     ^                                                            |
     |                                                    tcpip_input(pbuf)
     |                                                            v
     |                                                     +--------------+
     |                                                     |    lwIP      |
 WgCmd::SendData <-- dst-IP->peer-key lookup <-- output()--|  TCP/IP +    |
     |                                                     |  socket API  |
     |                                                     +--------------+
     |                                                            ^
     |                                                            | 0.0.0.0:80
     |                                                     existing tokio HTTP server
```

Inbound: `InboundDecrypted` -> `tcpip_input()` -> lwIP routes to the `:80`
listener. lwIP also answers ICMP itself, so `build_icmp_echo_reply` and the
whole hand-rolled ICMP path can be deleted once this works.

Outbound: lwIP routes the reply to the tailnet netif and calls its `output`
callback with a raw IP packet. The callback looks up the destination tailnet
IP -> peer node key and sends `WgCmd::SendData { dst_key, payload }`, which
`tm_wg` encrypts and `tm_derp` relays.

## Concrete work items

### 1. Build the netif (new code, `tm_netstack` on-device path)

- Register a netif with the lwIP raw API: `netif_add(&netif, &ipaddr,
  &netmask, &gw, state, init_cb, ip_input_cb)`. Prefer the raw lwIP netif
  over `esp_netif` for a tun-style interface (esp_netif is Ethernet/PPP
  oriented; a raw netif is simpler and lighter here). Verify the required
  symbols (`netif_add`, `netif_set_up`, `netif_set_link_up`, `tcpip_input`,
  `pbuf_alloc`, `pbuf_take`, `pbuf_free`, `netif_ip4_addr`) are exposed
  through `esp-idf-sys` bindings; add them to the bindgen allowlist if not.
- Flags: `NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_UP | NETIF_FLAG_LINK_UP`, no
  `NETIF_FLAG_ETHARP`, no `NETIF_FLAG_BROADCAST`.
- Address: assign `our_ip/32`. Add a route so `100.64.0.0/10` egresses this
  netif (with a single point-to-point netif and a /10 on-link, lwIP's
  longest-prefix routing sends tailnet-destined traffic here; confirm on
  device that replies to a peer are routed to this netif and not the WiFi
  default route).
- MTU: set ~1380 (1500 - WireGuard overhead - DERP framing headroom) so
  lwIP advertises a TCP MSS that never forces IP fragmentation across the
  tunnel. Tune against the real `MAX_DERP_PAYLOAD` in `tm_runtime`.

### 2. Inbound injection

- On `WgEvent::InboundDecrypted { payload }` (currently
  `tm_runtime/src/lib.rs:451`): allocate a `pbuf` (`pbuf_alloc(PBUF_RAW,
  len, PBUF_POOL)`), `pbuf_take` the decrypted bytes, and submit via
  `tcpip_input(pbuf, &netif)`.
- **Thread-safety is mandatory here.** The event router runs in the tokio
  task; lwIP's core runs in its own tcpip thread. Never call `netif->input`
  or touch lwIP PCBs directly from the tokio task. Use `tcpip_input()` (it
  hands off to the tcpip thread) or wrap work in `tcpip_callback()`. Free the
  pbuf correctly on every error path.

### 3. Outbound callback -> WireGuard

- The netif `output` callback (`err_t (*output)(netif, pbuf, ip4_addr)`)
  runs on the tcpip thread. It must not block on a tokio channel. Copy the
  pbuf into a plain buffer and push it onto a bounded, non-blocking
  `async_channel` sender (`try_send`; drop on full with a counter, same
  backpressure philosophy as the other channels — see the capacity-2 note at
  `tm_runtime/src/lib.rs:24`). The event router drains this channel.
- For each outbound IP packet: parse the destination IPv4 (bytes 16-19 of
  the IP header), look up the peer node key. `peer_ips` already maps
  `node_key -> tailnet_ip` (built at `tm_runtime/src/lib.rs:327-330`); add
  the reverse lookup `tailnet_ip -> node_key`. Then
  `wg_tx2.send(WgCmd::SendData { dst_key, payload })`.
- Packets to an unknown destination (no matching peer) are dropped; log once
  per distinct destination to avoid log spam.

### 4. Lifecycle

- Create/assign the netif when `our_ip` becomes known
  (`ControlEvent::OurIpAssigned`, `tm_runtime/src/lib.rs:333`, and/or the
  `MapUpdate` `our_ip` capture at `:326`). Handle `our_ip` changing across
  reconnects (bring the netif down, reassign, bring up) — this couples to
  plan (b): a stable IP makes this a one-time setup.
- On teardown / control loss, decide whether to keep the netif up (so the
  `:80` listener stays bound) or tear it down. Keeping it up is simpler and
  fine; inbound just stops until the tunnel is back.

### 5. Retire the hand-rolled ICMP path

Once injection works, lwIP answers pings itself. Delete
`build_icmp_echo_reply` / `build_icmp_echo_request` usage from the inbound
handler (keep the functions only if still wanted for the rung-6a self-test,
or move them behind a cfg). The `PeerHandshook` ICMP-elicitor
(`tm_runtime/src/lib.rs:475-495`) can stay as a liveness probe or be removed.

## Risks and things to verify on device

- **Heap.** The device has ~57 KB free after connect with the DERP TLS
  session resident (this is the same fragmentation constraint that caused the
  `WgEndpoint` OOM — see the `QUEUE_DEPTH = 0` fix in
  `tm_wg/src/endpoint.rs`). Each TCP connection costs a PCB plus send/recv
  buffers (several KB). Measure with `log_heap` around netif creation and
  during a live `curl`. Cap concurrent tailnet connections (small `listen`
  backlog, short keep-alive) if needed. This is the single most likely
  failure mode.
- **lwIP config.** Confirm `CONFIG_LWIP_...` sysconfig has enough TCP PCBs
  (`MEMP_NUM_TCP_PCB`), pbuf pool (`PBUF_POOL_SIZE`), and that the tcpip
  thread stack is adequate. Custom-netif support must be present in the
  build.
- **Routing correctness.** Verify a reply actually egresses the tailnet
  netif and not the WiFi default route. A `100.64.0.0/10` on-link route on a
  point-to-point netif should do it; test explicitly.
- **`0.0.0.0` bind reaches the new netif.** Default lwIP behavior accepts on
  all netifs; confirm no `SO_BINDTODEVICE` or source-address restriction is
  in play.
- **MTU / MSS.** If large responses stall, suspect fragmentation or an MSS
  that ignores tunnel overhead; lower the netif MTU.
- **pbuf lifetime / threading.** The most likely source of crashes. Keep all
  lwIP calls on the tcpip thread; copy at the tokio boundary.

## Test plan

1. Host build stays green (`tm_netstack` host path unchanged; guard the new
   code with `#[cfg(target_os = "espidf")]`).
2. Device build + flash.
3. From a tailnet peer: `ping <node-tailnet-ip>` still works (now answered by
   lwIP, not the hand-rolled reflector).
4. From a tailnet peer: `curl -v http://<node-tailnet-ip>/` returns the same
   body as the WiFi IP. Watch `log_heap` and the serial for crashes.
5. Two concurrent `curl`s to check connection-count headroom.

## Scope / non-goals

- IPv6 tailnet addressing is out of scope (IPv4 `100.64.0.0/10` only).
- Outbound-initiated TCP from the device over the tailnet is not required for
  this goal (serving is inbound-initiated); the same netif enables it later.
- Depends on plan (b) for a *stable* tailnet IP; functionally this works with
  a changing IP, but the endpoint URL would move each boot until (b) lands.
