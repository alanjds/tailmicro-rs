# tailmicro-rs

Tailscale client optimised for the **ESP32-C3** (400 KB SRAM, no PSRAM).

Fork of [`tailscale-rs`](https://github.com/tailscale/tailscale-rs) with the
same public API but with internals redesigned around embedded constraints,
incorporating the best strategies from
[MicroLink](https://github.com/CamM2325/microlink).

---

## Design goals

| Goal | Approach |
|---|---|
| No OOM on MapResponse | H/2 frame-by-frame streaming parse into a bounded roster |
| No heap fragmentation | Pooled packet buffers (`tm_buf`), bounded channels, persistent scratch (see `ALLOCATIONS.md`) |
| Source-compat with tailscale-rs | Same `Device`, `Config`, `netstack::*` names where practical |
| No extra OS tasks | One `Driver` future folding every actor into a single `tokio::join!`, run on a `current_thread` runtime |
| No CA bundle | Control key pinned via a signed blob; DERP TLS leg skips certificate checks (traffic is already end-to-end encrypted) |
| No C dependencies for WireGuard | Pure-Rust data plane, crypto core vendored from `ts_tunnel` |

---

## What changed vs tailscale-rs

Most of the official Tailscale lib API is kept (`Device`, `Config`, `netstack`),
but `Device::connect()` also returns a `Driver` future that you must include
in your async loop (e.g. `tokio::join!`): it is the data plane, not a task.
Inside, `h2` and smoltcp give way to `tm_h2` and lwIP, with bounded peer tables and pooled packet buffers.
Control uses a pinned key instead of a CA bundle, with DERP/DISCO ideas borrowed from MicroLink.

---

## Crates

| Crate | Role |
|---|---|
| `tailmicro` (root) | Public API: `Device`, `Config`, `Error`, `netstack`, `keys` |
| `tm_runtime` | Wires the actors and event router together; returns `Runtime` + `Driver`; optional LAN-only direct UDP path (`lan-direct`, on by default) |
| `tm_control` | Control client: pinned-key Noise IK, registration, interactive login, streaming netmap parse, node-key expiry |
| `tm_h2` | Minimal single-stream HTTP/2 frame reader/writer |
| `tm_derp` | DERP relay transport (optional on-device TLS 1.3 via the `etls` feature) |
| `tm_disco` | Passive DISCO responder (PING -> PONG, peer allowlist, rate limit) |
| `tm_wg` | WireGuard actor and bounded `WgEndpoint` (vendored `ts_tunnel` crypto, no FFI) |
| `tm_netstack` | Sockets over lwIP/`tokio::net`, tailnet netif, MagicDNS name table and lwIP resolver hook |
| `tm_keys` | Key types, pin verification, and node identity (seed-derived keys, rotation counters) |
| `tm_buf` | Shared packet buffer pool, channel helpers, network-link hint |
| `tm_time` | Runtime-agnostic clock |

---

## Features

- **Control-key pinning**: `Config::with_control_pin_hex` verifies an
  Ed25519-signed blob made by `tools/gen_fingerprint.py` (see `tools/README.md`;
  `tools/pin_signer.html` signs in the browser). Without a pin, `Device::connect`
  cannot reach control. `with_control_key` supplies a raw key instead.
- **Login**: auth key, or interactive login when none is given; read the URL
  with `tailmicro::login_url()`. `with_login_allowed(false)` makes it fail with
  `LoginRequired` instead. An expired node key yields `NodeKeyExpired`;
  renew it with `with_node_rotation` / `with_previous_node_rotation`.
- **Stable identity**: `with_identity_seed` derives node and disco keys from an
  app-held secret instead of the public MAC.
- **MagicDNS**: `Device::resolve`, `Config::with_magicdns`, `with_dns_resolver`;
  on ESP32 lwIP's `getaddrinfo` consults the same table.
- **Netmap refresh**: periodic re-poll (`with_refresh_interval`) and streamed deltas.
- **Services**: `with_services` advertises services to the tailnet.
- **Link awareness**: `with_link_check` defers reconnects while WiFi is down.
- **Direct LAN path**: peers on the same LAN talk UDP directly, with DERP as fallback.
  STUN, hole punching and port mapping are out of scope.

---

## Measured footprint (ESP32-C3)

Measured on a real ESP32-C3 with the `tasmolike-rs` firmware (ESP-IDF 5.5, debug
build, WiFi up, a small HTTP server and mDNS running), comparing the same image
with and without `tailmicro-rs` linked in. `tailmicro-rs` currently sits at
~ 32 KB `.bss` and ~ 63 KB of heap while connected to a tailnet, plus ~ 390 KB
of flash code.

The rest of the SRAM is left for ESP-IDF, the WiFi stack and the application.

---

## Usage

```rust
// ESP32-C3: use a current_thread runtime!
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all().build().unwrap();

rt.block_on(async {
    let config = tailmicro::Config::new("tskey-auth-...")
        .with_control_pin_hex("<hex blob from tools/gen_fingerprint.py>")?;

    let (dev, driver) = tailmicro::Device::connect(
        &config,
        Some("tskey-auth-...".to_owned()),
    ).await?;
    println!("tailnet address: {}", dev.ipv4_addr());

    // `driver` IS the data plane. Keep polling it alongside your own work;
    // never await it alone and never drop it (that takes the node offline).
    tokio::join!(driver, async { /* your application */ });
    Ok::<_, tailmicro::Error>(())
});
```

`Device::connect` returns once control assigns a tailnet IP, bounded by
`Config::with_connect_timeout`. Sockets live in `tailmicro::netstack`
(`UdpSocket`, `TcpStream`, `TcpListener`). On ESP32 the tailnet also appears as
an lwIP netif, so an existing server bound to `0.0.0.0` is reachable on the
tailnet IP unchanged.

---

## Implementation status

The control plane, DERP, DISCO responder, WireGuard data plane, MagicDNS and
the LAN direct path are implemented and run on hardware. Remaining:

| Item | Status |
|---|---|
| STUN / NAT traversal / port mapping | Not planned (see `docs/lan-direct-path-plan.md`) |
| DERP certificate verification | Deliberately off (see `tm_derp/src/tls.rs`) |
| `etls` DERP TLS feature | Off by default; enable per build |
| Active DISCO probing (`CallMeMaybe`) | Deferred |
| `Device::shutdown` | Currently a no-op |

Design notes and investigations are in `docs/`; heap-allocation work is in
`ALLOCATIONS.md`.

---

## License

BSD-3-Clause (same as tailscale-rs)
