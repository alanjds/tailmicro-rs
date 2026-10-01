//! Host-native Noise handshake test — no Wokwi, no ESP-IDF.
//!
//! `tm_control` has zero ESP dependency (only the top-level `tailmicro`
//! crate does, for WiFi/NVS, unrelated to this path), so the real control
//! connection logic can be exercised directly against the real network from
//! a dev machine. Drives `ControlActor` through the same channel-based
//! `run()`/`ControlCmd`/`ControlEvent` API the firmware uses, so this is the
//! real code path, not a reimplementation.
//!
//! Usage:
//!   TAILMICRO_CONTROL_PIN=<hex> TS_AUTHKEY=<key> [TAILMICRO_CONTROL_HOST=host] \
//!     cargo run -p tm_control --example host_handshake

use tm_control::{Config, ControlActor, ControlCmd, ControlEvent};
use tm_keys::NodeState;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
    let pin_hex = std::env::var("TAILMICRO_CONTROL_PIN")
        .expect("set TAILMICRO_CONTROL_PIN (hex blob from tools/gen_fingerprint.py)");
    let auth_key = std::env::var("TS_AUTHKEY").unwrap_or_default();
    let host = std::env::var("TAILMICRO_CONTROL_HOST")
        .unwrap_or_else(|_| "login.tailscale.com".to_string());
    let host: &'static str = Box::leak(host.into_boxed_str());

    let control_pin = tm_control::pin::verify_pin_hex(&pin_hex, &tm_control::pin::PIN_VERIFY_KEY, None)
        .expect("pin verification failed");
    println!("Pin verified OK. Connecting to {host}:80 with that pinned Noise key.");

    let config = Config { control_host: host, control_port: 80, control_pin, connect_timeout: None, lan_udp_port: None, hostname: "esp32c3", services: &[] };
    let node_state = NodeState::generate();
    let actor = ControlActor::new(config, node_state);

    let (cmd_tx, cmd_rx) = async_channel::unbounded::<ControlCmd>();
    let (ev_tx, ev_rx) = async_channel::unbounded::<ControlEvent>();

    let run_task = tokio::spawn(actor.run(cmd_rx, ev_tx));

    let auth_key_heapless: heapless::String<128> = auth_key.as_str().try_into().unwrap_or_default();
    cmd_tx.send(ControlCmd::Start { auth_key: auth_key_heapless }).await.unwrap();

    // Drain events for a few seconds; a real registration will keep streaming,
    // so this is just enough to observe handshake success/failure.
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(10));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            ev = ev_rx.recv() => {
                match ev {
                    Ok(ControlEvent::Error(e)) => { println!("ControlEvent::Error: {:?}", e); break; }
                    Ok(ControlEvent::OurIpAssigned(ip)) => println!("ControlEvent::OurIpAssigned: {:?}", ip.0),
                    Ok(ControlEvent::MapUpdate(_)) => { println!("ControlEvent::MapUpdate received - handshake and registration succeeded!"); break; }
                    Ok(ControlEvent::KeyExpiry) => println!("ControlEvent::KeyExpiry"),
                    Err(_) => { println!("event channel closed"); break; }
                }
            }
            _ = &mut timeout => { println!("timed out waiting for a terminal event"); break; }
        }
    }

    let _ = cmd_tx.send(ControlCmd::Shutdown).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), run_task).await;
}
