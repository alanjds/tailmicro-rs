/*
 * Extra lwIP bindgen coverage for the tailnet point-to-point netif
 * (tm_netstack::tailnet, espidf target only).
 *
 * esp-idf-sys's default bindings.h pulls in lwip/sockets.h, lwip/dns.h etc
 * (see ESP_IDF_COMP_LWIP_ENABLED in its bindings.h), which transitively drag
 * in lwip/netif.h and lwip/pbuf.h -- so netif_add/pbuf_alloc/etc are already
 * bound. lwip/tcpip.h is NOT pulled in transitively by any of those, so
 * tcpip_input()/tcpip_callback() (the two functions that hand a packet or a
 * closure off to the lwIP tcpip thread -- the only thread-safe way to touch
 * lwIP from the tokio task) are missing from the default bindings.
 *
 * This file is wired into the build via tm_netstack/Cargo.toml's
 * `[[package.metadata.esp-idf-sys.extra_components]] bindings_header`
 * (no `bindings_module`, so it merges into the normal esp_idf_sys:: root
 * bindings instead of a separate module) -- the same mechanism
 * tasmolike-rs's own Cargo.toml already uses for the `mdns` remote
 * component, just for header-only coverage instead of an extra C component.
 * See docs/tailnet-http-lwip-netif-plan.md and docs/wg-dataplane-notes.md.
 */
#include "lwip/tcpip.h"
