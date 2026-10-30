# Plan (b): stable per-chip node identity and tailnet IP

## Goal

A given physical ESP32-C3 should keep the **same** Tailscale node identity
(and therefore the same tailnet IP) across reboots and reflashes, instead of
registering as a brand-new node every boot. Success test: reboot and reflash
the device several times and confirm the Tailscale dashboard/API shows the
same node with the same `100.x.y.z` address each time, with no growing pile of
ghost `esp32c3-N` entries.

This should land **before** plan (a): a moving tailnet IP makes
`http://<node>/` point at a different address every boot, so a stable IP is
what makes exposing the HTTP port actually useful. This change is also lower
risk than (a).

## Observed problem (from live serial logs)

The firmware already has a persist-or-generate path
(`tasmolike-rs/src/tailscale_rust.rs:54` `load_or_generate_keys`, reading and
writing `NodeState` in NVS via `postcard`). Yet across six flashed boots the
serial log printed:

```
esp32_tokio_demo::tailscale_rust: Loaded existing Tailscale node keys
```

immediately followed by a **different** `nodekey:` on every boot
(`685e9ffb…`, `8c3a515f…`, `6268d3c9…`, `40a72838…`, `5172ca9a…`,
`b994aba0…`). The tailnet IP moved accordingly (`100.127.196.55` ->
`100.80.251.18` in two of those boots), and the dashboard accumulated ghost
nodes that only disappear via Tailscale's ephemeral GC.

So "persist to NVS" is *already coded* but the identity still changes. The
first job of this plan is to find out **why**, not to re-add persistence.

## Investigation checklist (do this first)

1. **Does the flashed firmware actually use the NVS-loaded key?**
   `tailscale_rust.rs` is the legacy path. Confirm whether the currently
   flashed data-plane firmware constructs its `NodeState` from
   `load_or_generate_keys()` or calls `NodeState::generate()`
   (`tm_keys/src/lib.rs:153`) somewhere in the `tm_runtime` bring-up. Trace
   the key that reaches `tm_control` registration. If the runtime generates
   its own key and ignores the NVS one, that alone explains the churn and the
   "Loaded existing" log is misleading (it loads a key nothing uses).

2. **Does flashing erase NVS?** `espflash flash -M` writes a merged
   bootloader+partition-table+app image. Determine whether that erases the
   NVS partition (offset from `partitions.csv`). If each flash wipes NVS,
   the key will change on every *reflash* even if it is stable across plain
   reboots. Distinguish the two cases with a clean power-cycle-without-reflash
   test (reboot only; check the `nodekey:` stays the same). Dev reflashes
   churning the key is tolerable; plain reboots must not.

3. **Does NVS read-back actually round-trip?** Verify
   `postcard::from_bytes::<NodeState>` returns the same bytes that were
   written (namespace `TAILSCALE_NAMESPACE`, key blob, RW-vs-RO open order,
   the several early-return `NodeState::generate()` fallbacks at
   `tailscale_rust.rs:66/92/101`). A silent deserialize failure would fall
   through to generate while still having logged "Loaded existing" earlier.

4. **Is the registration ephemeral?** All boots used the same auth key
   `tskey-auth-kev9MGSSN3…`. If that key has the **ephemeral** flag, Tailscale
   deletes the node shortly after it disconnects and may hand out a new IP on
   re-registration even for the same node key. A stable *key* is necessary but
   may not be sufficient for a stable *IP* if the node is ephemeral. Check the
   key's flags in the Tailscale admin console.

## Design options (choose after the investigation)

### Key stability

- **Option K1 — fix/persist NVS (smallest change).** Ensure the runtime uses
  `load_or_generate_keys()` output, that read-back round-trips, and that plain
  reboots keep the key. Stable across reboots; still lost if a reflash erases
  NVS.

- **Option K2 — derive the key deterministically from the chip.** Seed
  `NodePrivateKey` from the ESP32-C3 factory eFuse (unique 6-byte MAC via
  `esp_efuse_mac_get_default`, or the eFuse chip ID) through a KDF
  (HKDF-SHA256 with a fixed domain-separation label). Same physical chip ->
  same key **even across NVS erase / reflash**, with nothing to persist. This
  is the most robust for a fleet of devices. Note: eFuse MAC is not secret, so
  the KDF gives a stable-but-not-high-entropy key; acceptable for device
  identity, and it can be combined with a persisted random salt (K1+K2) if
  more entropy is wanted while keeping cross-reflash stability via a fallback
  to the deterministic key.

- **Recommendation:** K2 (optionally K1+K2). It removes the entire class of
  "NVS got wiped / didn't round-trip" failures and needs no successful write
  to work.

### IP / registration stability

- If registration is ephemeral and that reassigns IPs: switch to a
  **non-ephemeral** (persistent) auth key, or reserve the node's IP. A
  persistent node keeps its IP as long as the same node key re-registers.
  Trade-off: non-ephemeral nodes are **not** auto-GC'd, so a stable key is a
  prerequisite (otherwise every boot leaves a permanent ghost). K2 + a
  persistent registration together give: one dashboard entry per chip, stable
  IP, no ghosts.
- Keep the ephemeral-registration timeout cooperative and internal to
  tailmicro (per the standing constraint: the timeout must be internal, the
  wrapper cooperates, no imposed 32 KB thread).

## Concrete work items (once options are chosen)

1. In `tm_keys`: add a deterministic constructor, e.g.
   `NodePrivateKey::derive_from_seed(&[u8], label)` using HKDF, plus a
   `NodeState::derive_from_chip()` that pulls the eFuse MAC/chip-id on espidf
   (behind `#[cfg(target_os = "espidf")]`) and uses a fixed test seed on host.
   Keep `generate()` for the random path.
2. In the runtime/app bring-up: replace the identity source so the registered
   key is the stable one. If keeping NVS (K1), make the runtime consume
   `load_or_generate_keys()` and fix the read-back; if K2, derive at boot and
   drop the NVS dependency for the node key (or keep NVS only as a salt
   store).
3. Fix the misleading log: only print "Loaded existing…" when a key was
   actually loaded *and adopted*; print the key fingerprint being registered
   so future logs make churn obvious at a glance.
4. Auth key: document/switch to a reusable non-ephemeral key if a permanent
   stable IP is required; otherwise document that the IP is stable only while
   the ephemeral node has not been GC'd.
5. Ghost cleanup (optional, nice-to-have): on successful registration with a
   stable key, the old ghosts stop being created; existing ones GC on their
   own. A one-off admin-API cleanup script (using `~/.ts-api-key`, never
   printing it) can remove the accumulated `esp32c3-N` ghosts.

## Test plan

1. Host: `cargo test -p tm_keys` — deterministic derivation is reproducible
   (same seed -> same key), and differs per seed.
2. Device: flash, note the registered `nodekey:` and tailnet IP.
3. Plain reboot (no reflash): same key, same IP.
4. Reflash: with K2, same key, same IP; with K1-only, expected to change if
   flashing wipes NVS (document the limitation).
5. Dashboard/API: one node entry per chip, IP stable, ghost count not
   growing.

## Risks

- eFuse-derived keys are stable but low-entropy relative to random; fine for
  device identity, not for anything requiring secrecy of the derivation
  input. Use a fixed domain-separation label and, if desired, mix in a
  persisted random salt.
- Switching to non-ephemeral registration means ghosts (if any are still
  created) are permanent until manually removed — only safe once the key is
  truly stable.
- Never log or commit the auth key or any private key material (standing
  constraint). Log only public-key fingerprints.

## Relationship to plan (a)

Land (b) first. With a stable `our_ip`, plan (a)'s netif setup becomes a
one-time bring-up (no address-change handling), and the exposed
`http://<node>/` endpoint has a durable address.

## Update: app-held secret seed (MAC alone is not enough)

K2 derived the keys from the factory eFuse MAC alone. The MAC is public (it
is visible on the LAN), so anyone could recompute the node private key and
impersonate the node on the tailnet.

Current scheme: the app generates a random 32-byte secret on first boot and
keeps it in its own NVS (tailmicro never stores it), plus a `u32` generation
counter (0 by default). `Config::with_identity_seed(secret, generation)`
makes `NodeState::derive_from_secret` run HKDF-SHA256 with ikm = secret,
salt = chip MAC (per-device pepper), info = the per-key label followed by the
generation as 4 big-endian bytes. Bumping the generation yields entirely new
node, machine and disco keys, which is the hook for node-key rotation.

Without `with_identity_seed`, the old MAC-only derivation is used as an
insecure fallback and a warning is logged.

Consequence: an NVS wipe loses the secret, so the device gets a new identity.
The old node stays listed (offline) in the admin console until it is deleted.
