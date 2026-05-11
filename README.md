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
| No OOM on MapResponse | H/2 frame-by-frame streaming JSON parse — max 4 KB buffer |
| No heap surprises | `ArrayVec` / `heapless::Vec` peer tables, bounded channels |
| Source-compat with tailscale-rs | Same `Device`, `Config`, `netstack::*` types |
| No extra OS tasks | Tokio `current_thread` + `tokio::join!` — one FreeRTOS task |
| No CA bundle (saves 30 KB) | TLS fingerprint verification (from MicroLink) |
| WireGuard without reimplementation | FFI to `wireguard-lwip` ESP-IDF component |

---

## What changed vs tailscale-rs

### `tm_h2` replaces the `h2` crate
- ~200 lines, single-file, zero heap allocation
- Handles exactly one stream (stream 1) — the MapResponse long-poll
- Negotiates `SETTINGS_MAX_FRAME_SIZE = 4096` so the server sends in 4 KB chunks
- Sends proactive `WINDOW_UPDATE` (MicroLink technique) to prevent stalls

### `tm_control` — streaming MapResponse parser
- Receives H/2 DATA frames one at a time
- Feeds each 4 KB chunk to an incremental JSON state machine
- **Total heap for MapResponse: one 4 KB frame buffer + ~512 B parser state**
- MapState uses `ArrayVec<PeerInfo, 8>` — no `Vec<>` heap growth

### `tm_netstack` replaces `ts_netstack_smoltcp`
- No smoltcp — lwIP is already present in ESP-IDF
- `wireguard-lwip` injects decrypted packets directly into lwIP
- On host: delegates to `tokio::net` for tests

### `tm_wg` — WireGuard via FFI
- Wraps `wireguard-lwip` C library (ESP-IDF component)
- Peer table: `ArrayVec<WgPeerState, 8>` — static, no heap
- LRU eviction with optional priority peer (from MicroLink)

### `tm_disco` — passive DISCO responder
- Responds to PING with PONG (mandatory for peers to reach us)
- Peer allowlist — only process DISCO from known WG peers
- PONG rate-limit: 1 per peer per 100 ms (from dj-oyu / MicroLink)

### Actor model (from tailscale-rs)
- All subsystems are actors with `mpsc::channel(4)` mailboxes
- `tokio::select!` instead of separate TX/RX FreeRTOS tasks
- Channel capacity of 4 = bounded memory, natural backpressure

---

## Memory budget (ESP32-C3)

```
ESP-IDF + WiFi stack:          ~180 KB
Tokio current_thread executor:   ~8 KB
Actor stacks (Tokio tasks):     ~16 KB
mbedTLS (TLS 1.2, no bundle):   ~40 KB
H/2 frame buffer (stack):        ~4 KB
JSON parser state (stack):       ~1 KB
WireGuard state (8 peers):       ~2 KB
DERP connection:                  ~6 KB
Channels (4 × 4 × ~1.5 KB):    ~24 KB
Application + misc:             ~20 KB
──────────────────────────────────────
Total:                         ~301 KB
Free:                           ~99 KB  ← comfortable margin
```

---

## Usage (identical to tailscale-rs)

```rust
// ESP32-C3: use current_thread runtime!
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all().build().unwrap();

rt.block_on(async {
    let dev = tailmicro::Device::new(
        &tailmicro::Config::new("tskey-auth-..."),
        Some("tskey-auth-...".to_owned()),
    ).await?;

    let sock = dev.udp_bind((dev.ipv4_addr().await?, 9000).into()).await?;

    loop {
        let mut buf = [0u8; 1500];
        let (n, from) = sock.recv_from(&mut buf).await?;
        sock.send_to(from, &buf[..n]).await?;
    }
    Ok::<_, tailmicro::Error>(())
});
```

---

## Implementation status

| Component | Status |
|---|---|
| `tm_h2` frame parser | ✅ Complete |
| `tm_keys` key types  | ✅ Complete |
| `tm_disco` PING responder | ✅ Skeleton complete |
| `tm_wg` FFI wrapper  | ✅ Skeleton complete |
| `tm_control` Noise IK + registration | 🔧 Stub — Phase 1 |
| `tm_control` MapResponse streaming parse | 🔧 Skeleton — Phase 1 |
| `tm_derp` relay transport | 🔧 Stub — Phase 2 |
| `tm_netstack` ESP-IDF socket | 🔧 Stub — Phase 2 |
| NVS key persistence | 🔧 Phase 3 |
| TLS fingerprint verification | 🔧 Phase 3 |
| STUN / direct paths | ⏳ Phase 4 |

---

## License

BSD-3-Clause (same as tailscale-rs)
