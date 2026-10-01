# Investigation: MagicDNS name resolution on the ESP32-C3

Goal: firmware calls `connect("bospill:8080")` (or `bospill.tailnet-xyz.ts.net`) and it reaches the tailnet peer, with no change to tailmicro's own control/DERP resolution over WiFi DNS.

Status: read-only investigation. Nothing here was built or flashed. Each claim is tagged **[V]** verified against source (path:line given) or **[I]** inference, not verified.

## Recommendation (short)

Do not build a DNS responder first. Build a **fixed-capacity name table fed from the netmap**, exposed two ways:

1. a pure, host-testable lookup (`resolve(name) -> Option<[u8;4]>`) plus a `Device::resolve`/`peer_by_name` API, and
2. a thin ESP-IDF adapter: Kconfig `CONFIG_LWIP_HOOK_NETCONN_EXT_RESOLVE_CUSTOM=y` and a Rust `#[no_mangle] extern "C" fn lwip_hook_netconn_external_resolve`, which makes tokio's `spawn_blocking(getaddrinfo)` path resolve tailnet names unchanged. Anything not an exact peer match returns 0 and falls through to WiFi DNS.

A 100.100.100.100 responder (option b) is deferred. It is the faithful tailscaled design, but costs a DNS codec, a UDP path through the router, and lwIP server-list side effects, none of which the minimum goal needs.

## Q1. What tailscaled MagicDNS does, and the minimum subset

Verified from tailscale/tailscale and headscale sources on GitHub (fetched with `gh api`, current main):

- **[V]** Service address is 100.100.100.100 (`net/tsaddr/tsaddr.go:52-53`, `TailscaleServiceIPString`). The resolver also answers the symbolic name for that IP (`net/dns/resolver/tsdns.go:732-740`).
- **[V]** Host records come from the netmap: `dnsConfigForNetmap` (`ipn/ipnlocal/node_backend.go:1435`) fills `Hosts` and `Routes`; newer code serves them on demand via `magicDNSHostAddrs` (`node_backend.go:~1195`) keyed by lowercased FQDN, trailing dot trimmed (`nodeByFQDNLocked`, `node_backend.go:~1264-1283`).
- **[V]** Short names: `nodeByFQDNLocked` returns a bare name (no dot) only if `DNS.Proxied` is true. So `Proxied` is the MagicDNS on/off switch for short names. Search-domain expansion itself happens in the OS resolver (via `DNSConfig.Domains`), not in tsdns.go.
- **[V]** Authority: for names under a local domain that are not in the host map, tsdns answers NXDOMAIN; for names it is not authoritative for it returns REFUSED so the caller forwards (`tsdns.go:725-790`).
- **[V]** A query for an existing name but an absent record type returns success with empty answer, not NXDOMAIN (`tsdns.go:~790-800`).
- **[V]** IPv4 answers: peers' IPv6 is withheld when the peer has IPv4, unless the `MagicDNSPeerAAAA` capability is set (`magicDNSAddrs`, `node_backend.go:~1300`). tailmicro is IPv4-only, so A records are sufficient.
- **[V]** Split DNS: `DNSConfig.Routes` maps suffix to resolvers; an entry with empty resolvers means "answer from Hosts/ExtraRecords" (`net/dns/config.go:38-44`; capability version 23 note in `tailcfg/tailcfg.go:75`).
- **[V]** `DNSConfig.Proxied`, `Domains` (search domains), `CertDomains` (`tailcfg/tailcfg.go:1809-1829`).
- **[V]** headscale: `Proxied = dns.magic_dns` (default true); `Domains = [base_domain] + search_domains` (`hscontrol/types/config.go:1106-1122`). The node `Name` is `GivenName.<base_domain>.`, and **with an empty base_domain it is just `GivenName`, with no dot and no suffix** (`hscontrol/types/node.go:512-525`). SaaS sends `Name` as `host.tailnet.ts.net.` **[I]** (consistent with upstream tailscale-rs tests, not checked against live SaaS).
- **[V]** `Name` can differ from `Hostinfo.Hostname`: headscale uses `GivenName`, and Tailscale applies collision suffixes (`-1`) **[I for the SaaS suffix detail]**.

**Minimum on-device subset (recommended):**

1. Exact peer match on the short label or `label.<suffix>`, case-insensitive, trailing dot allowed. The suffix is whatever follows the first label of the self node's `Name`.
2. Resolve our own name too.
3. A records only (IPv4).
4. Short names only when `Proxied` is true (matches tailscaled).
5. Everything else falls through untouched.

Not worth on-device: forwarding to `Resolvers`/`Routes`, ExtraRecords, PTR, AAAA, subdomain resolve, 4via6, DoH/DoT upstreams.

## Q2. Candidate designs

Context facts **[V]**:

- The tailnet is a no-L2 lwIP netif, netmask 100.64.0.0/10, so 100.100.100.100 would be routed through it. `tailnet_output_cb` (`tm_netstack/src/tailnet/device.rs:192`) queues `OutboundPacket`s; the router's `netif_out_rx` branch (`tm_runtime/src/lib.rs:1199`) looks up `ip_to_key` (`lib.rs:780`, `heapless::Vec<_, 8>`) and on a miss calls `log_unknown_netif_dest` (`lib.rs:579`) and drops. Inbound goes back via `inject_inbound` (`device.rs:79`).
- Firmware hostname resolution: tokio `TcpStream::connect((host, port))` runs `getaddrinfo` in `spawn_blocking` on a pthread (`CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT=3072`). IP literals skip it. tm_control's `open_tcp` (`tm_control/src/lib.rs:1017`) and tm_derp use the same path.
- lwIP DNS servers are global (3 slots, `LWIP_DNS_SETSERVER_WITH_NETIF` off) and DHCP overwrites them.
- lwIP hooks (ESP-IDF v5.5, `components/lwip`): `Kconfig:1361` `LWIP_HOOK_NETCONN_EXT_RESOLVE_{NONE,DEFAULT,CUSTOM}`, `Kconfig:1389` `LWIP_HOOK_DNS_EXT_RESOLVE_{NONE,CUSTOM}`; both are NONE in the generated sdkconfig today. Prototypes at `port/include/lwip_default_hooks.h:53-64`. The netconn hook is called in `netconn_gethostbyname_addrtype` (`lwip/src/api/api_lib.c:1295-1303`) in the **caller** thread, before any message to tcpip; reached from `lwip_getaddrinfo` (`api/netdb.c:495`). The DNS hook (`lwip/src/core/dns.c:1749-1756`) runs on the tcpip thread and must not block. Return 0 means not consumed (normal DNS proceeds); non-zero means consumed with `*err` as result.
- `DNS_LOCAL_HOSTLIST` has no Kconfig and is not in `lwipopts.h` (`opt.h:1202`), so `dns_local_addhost` needs an lwIP fork or an `ESP_IDF_LWIP_HOOK_FILENAME` header trick. The Kconfig hooks are the no-fork route.

| | (a) name table via lwIP hook | (b) responder at 100.100.100.100 | (c) `Device::resolve(name)` API |
|---|---|---|---|
| RAM | ~0.6 KB static table; no thread, no sockets | DNS codec buffers, UDP PCB (`LWIP_MAX_UDP_PCB=4`), likely extra tcpip stack (`LWIP_TCPIP_TASK_STACK_SIZE=3072` is tight) **[I]** | same table as (a) |
| Flash | tiny | codec plus parser for queries and replies | tiny |
| spawn_blocking | works unchanged: hook runs in the getaddrinfo thread, short mutex | works, but adds a network round trip per lookup | bypasses it; async caller gets an answer with no thread |
| 8-peer limit | names beyond the 8 online peers unresolvable (same as `ip_to_key`) | same | same |
| Fall-through | return 0, normal WiFi DNS | needs NXDOMAIN failover between servers: `dns.c:1385-1400` retries the next server on error rcode, which leaks tailnet names to the LAN resolver and is defeated by NXDOMAIN-hijacking ISPs; server list is overwritten by DHCP **[V for dns.c, I for hijack impact]** | not applicable, caller chooses |
| Failure modes | stale snapshot (below); hook symbol missing at link time if Kconfig is CUSTOM | lost UDP packets over DERP, timeouts, lwIP retry/failover quirks | callers must opt in; `connect("name:port")` stays broken for third-party code |
| Host testable | table and matcher fully; hook glue only on device | codec yes, end-to-end needs the netif | fully |
| Runtime-agnostic fit | table is pure core; hook is a Tokio/espidf adapter | wants a UDP socket abstraction in the `Net` trait | exactly `Net::resolve` in `docs/plan-runtime-backends.md` |

How this fits `docs/plan-runtime-backends.md`: it plans `Net::resolve`/`connect_host` with TokioNet keeping spawn_blocking DNS and Embassy using `DnsSocket` (Decision 8 asks whether to drop spawn_blocking DNS later). A pure name table plus codec-free lookup sits under both backends; the lwIP hook is only the Tokio/espidf adapter and an Embassy backend calls the same core from `resolve`. This avoids the DNS divergence the plan lists under Risks.

Verdict: **(a)+(c) share one core; (b) is a later, optional layer.** Upstream also leans this way: it has the routing plumbing for (b) but not the responder (Q4).

## Q3. What tm_control keeps today and what it must keep

Verified current state:

- `PeerInfo` (`tm_control/src/lib.rs:81`) holds key, disco, ip, derp region, and `hostname: heapless::String<64>` from `Hostinfo.Hostname` (`map_stream.rs:344-349`), **not** from `Name`.
- `Name` is ignored in the Peer context; root `DNSConfig` hits `Ctx::Skip` (`map_stream.rs:293-316`).
- `commit_peer` keeps online peers with key and ip only (`map_stream.rs:373-393`); caps are 8 peers, 4 DERP regions.
- The netmap is a **one-shot snapshot**: the publish MapRequest is non-streaming; the keepalive poll sets `omit_peers: true` (`lib.rs:590`) with `discarding = streaming` (`lib.rs:860`), so its body is drained. The router rebuilds `ip_to_key` only on `ControlEvent::MapUpdate` (`lib.rs:973` emits, `tm_runtime/src/lib.rs:814` consumes), i.e. on (re)connect.

Needed additions:

| Field | Source | Why | Size |
|---|---|---|---|
| peer `Name` | `Peer.Name` | exact match target; differs from Hostname | `String<64>` x8 = 512 B |
| self `Name` | `Node.Name` | own name, and the tailnet suffix (everything after the first label) | 64 B; suffix is a slice, no extra storage |
| `DNSConfig.Proxied` | root `DNSConfig` | gate short-name resolution | 1 B |
| `DNSConfig.Domains` | optional | alternate suffixes; phase 4 only | skip initially |

Total about 0.6 KB in the boxed `MapState` event (transient), plus a ~0.6 KB static table in the runtime (copy of label and ip). Names longer than 64 are dropped for that peer (it stays routable; it is simply not resolvable by name). Handle the empty-suffix headscale case: a `Name` with no dot is both label and FQDN.

Streaming parser spike: **none expected [I, from reading the code]**. Capture is one arm per field in `scalar_str` (`name_is("Name")` in the Peer branch near `map_stream.rs:335-343`, in the self-node branch, and a new `Ctx::DnsConfig` in `enter()` for `Proxied`). `ValueString` is already a fixed `String<128>`, `PeerScratch` grows 64 B, the `ArrayVec<Ctx,16>` stack has room (DNSConfig depth 2). Whether `Proxied` (a JSON bool) flows through a bool callback that the parser currently ignores needs checking **[unverified]**. Add a fixture with `Name`, `DNSConfig` to the tests at `map_stream.rs:423-516`, which currently have neither.

## Q4. Upstream tailscale-rs (HEAD 0b8d819)

- **[V]** `ts_control_serde/src/dns.rs` models the full `DnsConfig` (resolvers, routes, fallback_resolvers, `Domains`, `Proxied`, extra_records, cert_domains); `netmap.rs:327-331` carries `dns_config`. `Node.name` is the FQDN (`node.rs:53`), split into hostname and tailnet in `ts_control/src/node.rs:~117`.
- **[V]** `Node::matches_name` (`ts_control/src/node.rs:74-92`) accepts the bare hostname or the FQDN, with an optional trailing dot, without allocating. `Device::peer_by_name` (`src/lib.rs:249`) goes through the `PeerTracker` actor (`ts_runtime/src/peer_tracker.rs:33`, linear scan).
- **[V]** There is **no resolver**: README lists MagicDNS and Split DNS as Unsupported and peer lookups as Coming Soon; `ts_python/src/udp.rs` says DNS is unsupported.
- **[V]** Plumbing exists: `RouteAction::Loopback(OverlayTransportId)` "used for things like DNS serving", with a test routing 100.100.100.100 to loopback (`ts_overlay_router/src/outbound.rs:25,107-136`).

Implication: mirror `peer_by_name` naming and its matching semantics (short or FQDN, trailing dot optional) in tailmicro's `Device` API, so source-compat with upstream holds. Note upstream matches the Hostinfo-derived label; tailmicro should match `Name`'s label (what DNS actually serves).

## Q5. Plan, tests, risks

**Phase 0 (tm_control, host-only).** Capture `Name` (peer, self) and `DNSConfig.Proxied` in `map_stream.rs`; add to `PeerInfo`/`MapState`; fixtures for SaaS-style (`bospill.tailnet-xyz.ts.net.`) and headscale-empty-suffix names; test oversized names.

**Phase 1 (pure core).** A `names` module (no_std, `heapless`): `NameTable<8>::set(from MapState)`, `lookup(&str) -> Option<[u8;4]>` with the matching rules in Q1. Property-style tests: case, trailing dot, wrong suffix, `Proxied=false`, ordinary hostnames (`example.com`, `login.tailscale.com`) never match.

**Phase 2 (API).** Router stores the table on `MapUpdate`; `Device::resolve(name)` and `peer_by_name` using it. Matches `Net::resolve` in the backends plan.

**Phase 3 (ESP-IDF adapter).** Add `CONFIG_LWIP_HOOK_NETCONN_EXT_RESOLVE_CUSTOM=y` to `/home/alanjds/src/tasmolike-rs/sdkconfig.defaults` (then `rm -rf target/riscv32imc-esp-espidf/debug/build/esp-idf-sys-*` to regenerate). In tm_netstack (espidf-only) export `#[no_mangle] extern "C" fn lwip_hook_netconn_external_resolve(name, addr, addrtype, err) -> c_int`: return 0 unless the lookup hits and `addrtype` allows IPv4. Export the symbol unconditionally so a CUSTOM Kconfig never fails to link.

**Phase 4 (optional, later).** Refresh without reconnect (stream peer deltas or periodic poll), `Domains`/ExtraRecords, then the 100.100.100.100 responder hooked at the `netif_out_rx` branch.

**Test plan.** Host: Phases 0-2 unit tests, no hardware. Device (user flashes): `connect("bospill:8080")` and FQDN form succeed; `connect("example.com:80")` and the control/DERP reconnect still resolve through WiFi; unknown short name fails the same way as today. Heap: record min-free and largest-block before and after per `ALLOCATIONS.md`, since the table is `.bss` and counts against it.

**Risks.**

- Stale snapshot: peers joining after boot are unresolvable until the next control reconnect **[V]** (follows from the drained keepalive poll). The user-visible failure is a plain DNS error, which is confusing; log it.
- Hook behaviour untested: `addrtype` handling for `AF_UNSPEC`, Rust symbol linkage from esp-idf-sys, and the mutex flavour on ESP-IDF std are **unverified [I]**. Prototype early; use a plain `static` with a short critical section.
- Name collisions: a LAN host with the same short name as a peer is shadowed (tailscaled behaves the same when Proxied). tm_control/DERP names contain dots with a foreign suffix, so exact matching leaves them alone.
- Names of peers beyond the 8-peer cap, and offline peers, do not resolve.
- Hook is global to all `getaddrinfo` callers on the device (including mDNS-adjacent users); exact matching keeps leakage and surprise minimal. No hostname is ever sent to the tailnet in this design.

## Decisions for the user

1. Accept the hook-based table (a)+(c) now and defer the 100.100.100.100 responder?
2. Is a boot-time snapshot (refresh only on control reconnect) acceptable, or should phase 4 refresh be scheduled soon?
3. Match semantics: follow tailscaled (short names only when `Proxied`, tailnet wins over WiFi DNS), or require the FQDN only?
4. Name storage: `String<64>` per peer (+0.6 KB) or tighter `String<32>` (+0.3 KB, longer names unresolvable)?
5. Put the Kconfig change in tasmolike-rs only, or make tm_netstack document it as a required consumer setting?
