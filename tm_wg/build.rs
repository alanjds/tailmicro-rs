//! Build script for tm_wg.
//!
//! The old `wireguard-lwip` C FFI path (and its `wireguard_stub` cfg) is gone:
//! the WireGuard data plane is now pure Rust (vendored ts_tunnel crypto core +
//! a bounded-memory endpoint). This build script intentionally does nothing.

fn main() {}
