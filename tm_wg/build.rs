//! Build script for tm_wg
//!
//! This script detects whether wireguard-lwip is available and sets a cfg flag
//! accordingly. If wireguard-lwip is not available, the crate will use stubbed
//! functions that do nothing.

fn main() {
    // Check if wireguard-lwip component is available
    // This is done by checking if the wireguard-lwip component directory exists
    // in ESP-IDF components
    
    // For now, we always set the stub flag because wireguard-lwip is not
    // available in ESP-IDF 5.5
    println!("cargo:rustc-cfg=wireguard_stub");
}