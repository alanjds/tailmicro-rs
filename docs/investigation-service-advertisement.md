# Investigation: advertising "HTTP on TCP/80" on the tailnet

Read-only investigation, 2026-10-01. No source changes. Sources were pinned at tailscale/tailscale `main@d33279d7` (`CurrentCapabilityVersion = 148`), juanfont/headscale `main@eeaac680` and tailscale/tailscale-rs `main`. Line numbers refer to those revisions.

## Summary and recommendation

Tailscale's mechanism is `Hostinfo.Services []tailcfg.Service{Proto,Port,Description}`. For TCP/UDP entries it is **informational only**: no ACL, DNS, serve or Funnel behaviour depends on it. It shows up in the admin console's Services → Discovered page, but only when the tailnet has turned on endpoint collection, which is off by default and off on this tailnet today. headscale passes it through to peers' netmaps. Access to port 80 is decided entirely by ACL/grants plus the MagicDNS name. The newer Tailscale Services feature (`svc:` VIPs) is overkill: it needs a tagged node, admin approval, the c2n protocol and listening on extra VIP addresses.

**Recommendation:** add a static `&'static [Service]` to `Config`, serialized into **every** Hostinfo (register, both publishes and the streaming poll). The cost is about 70 B of request body per service, 8 B of config and 0 B of heap. Effort is **S**. Do not parse peers' services. Before relying on it, get the maintainer to decide on endpoint collection (see Open questions).

## What Tailscale does

**Schema (verified, `tailcfg/tailcfg.go`).**
- `ServiceProto` (L801-812) has the values `"tcp"`, `"udp"`, `"peerapi4"`, `"peerapi6"` and `"peerapi-dns-proxy"`.
- `Service{Proto, Port uint16, Description string ,omitempty}` is at L825-855. `Description` is "usually the process name". For `peerapi-dns-proxy`, `Port` must be 1.
- `Hostinfo.Services []Service ,omitempty` is at L957.
- `Hostinfo.ShieldsUp` (L922) and `Hostinfo.ServicesHash` (L964, used for VIP services) sit next to it.
- `MapResponse.CollectServices opt.Bool` (L2094-2098): "whether this node's Tailnet has requested that info about services be included in HostInfo".

**What tailscaled sends (verified).**
- `ipn/ipnlocal/local.go` `hostInfoWithServicesLocked` (L5790-5820) blanks `Services` unless the `ShouldUploadServices` hook returns true, then always appends the peerapi pseudo-services from `peerAPIServicesLocked` (L5716).
- The hook comes from `feature/portlist/portlist.go` L76 and L99-100: `!shieldsUp && CollectServices`. The portlist poller fills `Proto`, `Port` and `Description = process name` (L160-170).
- So stock clients only report real TCP/UDP ports when the tailnet opts in.
- Live check on this tailnet (local API `whois`, read-only): all 11 tailscaled peers advertise only peerapi entries. The `esp32c3` peer advertises `{"OS":"embedded","Hostname":"esp32c3"}` with no `Services`.

**Who reads it.**
- *Peers' tailscaled (verified).* Only the pseudo-services are functional.
  - `peerAPIPorts` (local.go L7764-7778) finds a peer's peerapi from `peerapi4`/`peerapi6`, which drives Taildrop and DoH via exit nodes.
  - The `peerapi-dns-proxy` fallback is at L8035-8041.
  - No code path in `ipnlocal` reads `tcp`/`udp` entries for behaviour.
  - `tailscale status --json` does **not** expose them: `ipnstate.PeerStatus` has `PeerAPIURL` but no `Services`, and the live status JSON has no such key. They are visible through `localapi/v0/whois` → `Node.Hostinfo.Services`, and in the raw netmap.
- *SaaS control and admin console (docs, [kb/1100](https://tailscale.com/kb/1100/services)).*
  - "Endpoint collection … disabled by default … never collected or shared between your devices unless you … enable" it.
  - The toggle is under Services → Discovered.
  - Endpoints are "not stored in our database" (live view only).
  - Nothing is shared from shields-up machines.
  - For shared nodes, viewers only see endpoints their ACL grants them.
  - Inference: control filters the services each peer sees by ACL, and probably drops TCP/UDP entries when collection is off.
  - Observed: SaaS trims peer Hostinfo to `Hostname`, `OS` and `Services`.
- *headscale (verified).* `hscontrol/state/maprequest.go` `peerHostinfo` (L162-176) keeps `Services` among the peer-visible fields and fans it out unfiltered. There is no CollectServices gating and no admin UI.

**Functional effect.** None for `tcp`/`udp`:
- ACL/grant enforcement uses the packet filter, which is evaluated on the receiving node.
- MagicDNS names come from `Hostname`/GivenName.
- `tailscale serve`/Funnel use `ServeConfig` plus `Hostinfo.IngressEnabled`/`WireIngress`, not `Services`.

**Tailscale Services (`svc:` VIPs).** These are a different system:
- The host sets `Hostinfo.ServicesHash` (serve.go L1708-1715).
- Control then fetches the list via c2n `GET /vip-services` (serve.go L70), which returns `VIPService{Name, Ports, Active}` (tailcfg L1067-1082).
- Control answers with `ServiceIPMappings` in the `service-host` node capability (tailcfg L3111-3127) and adds the VIP addresses to AllowedIPs.
- Requirements ([kb/1552](https://tailscale.com/kb/1552/tailscale-services)): a tag-based host identity, admin approval or auto-approval, grants that target the service, and clients ≥ 1.86.
- Tailmicro would need: c2n handling (PingRequest-driven HTTP over Noise), CapMap parsing, the lwIP netif accepting VIP destination addresses, and tags. This is **L** effort, and it only buys a stable `svc:` name and multi-host failover. Not relevant for one device.

## Wire mechanics

- **Where Hostinfo travels.** It is in `RegisterRequest.Hostinfo` (tailcfg L1338; direct.go L764) and in `MapRequest.Hostinfo` (L1473).
- **Streaming requests ignore it on SaaS.** For `Stream=true` with Version ≥ 68 the server "should treat this as a read-only request and ignore any Hostinfo" (L1460-1468). `ReadOnly` has been deprecated since v68 (L1505-1511).
- **How tailscaled pushes a change.**
  1. `Auto.SetHostinfo` (auto.go L681) calls `Direct.SetHostinfo` (direct.go L441-457), which **dedupes client-side** with `hi.Equal`.
  2. If anything changed, `updateControl()` (auto.go L259) runs `SendUpdate` = `sendMapRequest(stream=false, nu=nil)`. That is a "lite" request with `OmitPeers=true` (direct.go L974, L1093-1104).
  3. Per tailcfg L1513-1527, `OmitPeers && !Stream && !ReadOnly` lets the client "update their endpoints without breaking existing long-polling" connections, and the response may be empty (headscale `poll.go` L128-147 just writes 200).
- **Server-side dedupe (headscale, verified).**
  - `UpdateNodeFromMapRequest` (state.go L3275) is called for non-streaming requests (poll.go L124) **and for the streaming request too** (poll.go L244). This is a difference from SaaS.
  - It **replaces the whole stored Hostinfo** when `hostinfoEqual` fails, and re-broadcasts the node to peers only when `peerHostinfoEqual` fails (maprequest.go L138-181).
  - Consequence: if any request carries a Hostinfo *without* `Services`, headscale erases them and pushes the change to every peer, and the next request flips them back. **Services must be identical in all four Hostinfos we send.** SaaS behaviour is not verified; we assume it stores the last non-streaming value.
- **Reconnects.** Every Tailmicro reconnect re-runs register, publish #1 and publish #2 (lib.rs L521). Those requests re-send the full Hostinfo anyway, so nothing extra is needed. Do not add a separate lite request.

**Current Tailmicro Hostinfo.**
- `HostInfo{OS, Hostname, NetInfo?}` (lib.rs L348-366) is built by hand in four places:
  - register (L583)
  - publish #1 (L634)
  - publish #2 via `publish2_body` (L330)
  - streaming poll (L500)
- Each is hard-coded `os:"embedded", hostname:"esp32c3"`.
- Bodies are serialized by `to_json_buf` into `heapless::Vec<u8, REQUEST_BODY_CAP=768>` (L41, L56). `build_h2_post` boxes `ArrayVec<u8, MAX_REQUEST_SIZE=4352>` (L36, L946).

**Minimum JSON to add**, inside `Hostinfo`:

```json
"Services":[{"Proto":"tcp","Port":80,"Description":"tasmolike HTTP"}]
```

**Body size budget.** Measured with Python using real key lengths, compact JSON:
- Publish #2 today, worst case: 370 B.
- Plus one service: 440 B. Each further service adds about 57 B plus the description length.
- Register with a 128-char auth key and one service: about 370 B.
- So there is room for about 5 services with 32 B descriptions under 768 B. A cap of `MAX_SERVICES = 4` and descriptions of 32 B or less keeps a margin of about 100 B. Overflow already fails fast with `JsonError::ParseError`.

**Peer parsing collision.**
- `map_stream.rs` `enter()` (L294-317) maps `(PeerHostinfo, "Services", array)` to `Ctx::Skip`, so the new array is skipped at the cost of a few stack-depth pushes. No collision.
- Reading peers' services would need about `ArrayVec<(u8,u16),4>`, roughly 14-16 B per `PeerInfo`, which is about 128 B in the boxed `MapState` at `MAX_PEERS=8`, plus parser states.
- Tailmicro has no consumer for that data, and on SaaS it would only contain peerapi pseudo-services. **Don't.**

## Proposed Tailmicro change (effort: S)

`tm_control/src/lib.rs`:

```rust
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProto { Tcp, Udp }           // never emit peerapi* (we have no peerapi)

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub proto: ServiceProto,
    pub port: u16,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub description: &'static str,           // checked <= 32 B at config time
}
pub const MAX_SERVICES: usize = 4;

pub struct Config { /* … */ pub hostname: &'static str, pub services: &'static [Service] }

struct HostInfo<'a> {
    #[serde(rename = "OS")] os: &'a str,
    hostname: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    services: &'a [Service],                  // Go field order irrelevant; JSON keyed
    #[serde(rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    net_info: Option<NetInfo>,
}
impl ControlActor {
    fn hostinfo(&self, net_info: Option<NetInfo>) -> HostInfo<'_> {
        HostInfo { os: "embedded", hostname: self.config.hostname,
                   services: self.config.services, net_info }
    }
}
```

- Replace the four literal `HostInfo { … }` sites with `self.hostinfo(None)` or `self.hostinfo(Some(NetInfo{…}))`.
- Pass `services` into `publish2_body`.
- Root `src/config.rs`: add `services: &'static [Service]` (default `&[]`), map it in `control_config()`, and re-export `Service`/`ServiceProto`. `tm_runtime` is unchanged because `RuntimeConfig.control` already carries `tm_control::Config`.
- Tests:
  - Extend the existing `publish2_body` golden test (L1216 area) to assert `Hostinfo.Services`.
  - Add one test asserting that an empty slice leaves today's bodies byte-identical.
  - Add one test that 4 services with 32 B descriptions still fit in 768 B.

**Cost.**
- Heap: 0 (static slice, serialized straight into the existing stack buffer).
- RAM: 8 B fat pointer in `Config` (twice: root and tm_control) and 8 B in `HostInfo`.
- Stack: no new buffers.
- Flash: a few hundred bytes of serde code.
- Wire: about 70 B per request, four requests per (re)connect.
- No ALLOCATIONS.md item is touched.

**Not in scope.** Changing services at runtime would need `ControlCmd::SetServices` plus a lite `OmitPeers` MapRequest on a fresh stream ID. That has to be issued while `stream_map_response` is blocked reading `MAP_STREAM_ID`, which means `select!`-ing the command channel inside the frame loop and handling a second stream's response (M). Not worth it for a fixed port 80.

## API sketch

```rust
static SERVICES: &[tailmicro::Service] =
    &[tailmicro::Service::tcp(80, "tasmolike HTTP")];   // const fn ctor

let config = Config::new(..)
    .with_control_pin_hex(PIN)?
    .with_hostname("tasmolike-kitchen")?   // optional, see Risks: MagicDNS name
    .with_services(SERVICES)?;             // Err if > MAX_SERVICES or desc > 32 B
```

- A slice is used rather than a builder that pushes items, so the data stays in `.rodata`.
- The services are sent at register and on every publish and poll. A change takes effect at the next (re)connect or reboot.

## Verification plan

1. **Baseline (done, read-only).** On bospill, `curl --unix-socket /run/tailscale/tailscaled.sock http://local-tailscaled.sock/localapi/v0/whois?addr=100.75.48.69` returns `Hostinfo {"OS":"embedded","Hostname":"esp32c3"}`.
2. **Flash the change, then repeat the whois.** Expect `"Services":[{"Proto":"tcp","Port":80,"Description":"tasmolike HTTP"}]`. If SaaS drops TCP entries because endpoint collection is off, the field will be absent. That is the key unknown, and the test resolves it.
3. **Debug log.** The firmware's existing `debug!` on the register body (lib.rs L587) shows what was sent. Add the same log for the publish bodies, at debug level only.
4. **Admin console.** Services → Discovered requires the tailnet owner to **enable endpoint collection**. That is a tailnet-wide setting change (it also starts collecting every tailscaled host's listening ports), so it is the user's decision. I did not change it.
5. **Admin API.** Optional, and needs a read-only API access token from the user. `GET /api/v2/device/{id}?fields=all` exists, but whether it includes services is not verified.
6. **headscale (optional).** Run a local headscale and check `headscale nodes list -o json` and a peer's whois, to confirm the "identical Hostinfo in every request" invariant (no peer churn on reconnect).
7. **Reachability is independent of all this.** `curl http://esp32c3.polecat-fort.ts.net/` from bospill works or fails based on ACLs alone.

## Risks

- **Informational only.** Advertising is not exposure control. Who can reach :80 is decided by ACLs/grants. **Tailmicro does not enforce the packet filter**: `map_stream` skips `PacketFilter`, and nothing filters inbound. Any peer that control lets see the node can hit every port. Port-scoped grants are therefore not enforced on-device. This is pre-existing, but it is worth stating next to an "HTTP on 80" advert.
- **Collection gating.** Stock clients honour `CollectServices`/ShieldsUp. We would advertise unconditionally. SaaS may silently drop the entries (UX surprise) or show them while the tailnet has collection disabled (policy surprise). Optionally parse `CollectServices` and gate on it, though that needs a parser state.
- **headscale flapping.** If any of the four Hostinfos diverge, headscale overwrites Hostinfo and broadcasts to all peers on each reconnect. Using a single `hostinfo()` helper prevents that.
- **Privacy.** `Description` reaches every allowed peer (headscale: all peers). Keep it generic: no firmware version or location.
- **Hostname.** It is hard-coded `"esp32c3"`. Several devices become `esp32c3-1`, `esp32c3-2`, …, and that name is what users actually type. A configurable hostname matters more for discoverability than `Services`.
- **No peerapi.** Never advertise `peerapi*`. Peers would try Taildrop or DoH to us and fail.
- **`tailscale serve` interplay.** None. Serve and Funnel are host-local tailscaled features, and Tailmicro serves directly.

## Open questions for the maintainer

1. Turn on endpoint collection for this tailnet, accepting that it collects every host's ports, or accept that the advert may be invisible on SaaS?
2. Gate on `CollectServices` like tailscaled, or always send?
3. Add `with_hostname` in the same change?
4. Is static-at-boot acceptable, so that runtime changes are not needed?
5. Should inbound packet-filter enforcement be tracked as its own card?

## Not verified

- Whether Tailscale SaaS stores and forwards `tcp`/`udp` entries from a client when endpoint collection is off. Step 2 of the verification plan resolves this.
- That SaaS filters services per viewer by ACL (that comes from the docs, not from code).
- That SaaS dedupes Hostinfo server-side.
- Whether the admin REST API exposes services.
- That no tailscaled code outside `ipnlocal/local.go` consumes `tcp`/`udp` service entries. I grepped only `local.go`, `peerapi.go`, `serve.go` and `portlist.go`.
- The exact body sizes on device. The figures are a Python model using real key and prefix lengths.
- That tailscale-rs has an API to set services. It has only the serde types `ts_control_serde/src/service.rs` and `HostInfo.services`, and its `Description` lacks `omitempty`.
