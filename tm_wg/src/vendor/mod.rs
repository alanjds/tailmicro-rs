//! Vendored WireGuard crypto core.
//!
//! These modules are copied (not depended-upon) from the official
//! `tailscale-rs` `ts_tunnel` crate, BSD-3-Clause, Copyright Tailscale Inc &
//! contributors. The license and patent grant are carried forward verbatim as
//! `VENDOR-LICENSE` and `VENDOR-PATENTS` in this directory.
//!
//! **Exact upstream commit vendored:
//! `0b8d819b99c6463e4f0b6ae64d244909b866bfe0`** (from
//! `ts_tunnel/src/{messages,macs,session,handshake,config,time}.rs`).
//!
//! Upstream is pre-1.0 and actively developed; there is no automatic re-sync.
//! The deliberate mechanical/structural edits made during the port (key-type
//! shim, `Packet` replacing `PacketMut`, OsRng route, dropped scheduler
//! handle, TAI64N synced-clock feed, RFC 6479 replay window, message-count
//! rekey) are documented in `docs/wg-dataplane-notes.md`.

pub mod config;
pub mod handshake;
pub mod keys;
pub mod macs;
pub mod messages;
pub mod packet;
pub mod session;
pub mod tai64n;
