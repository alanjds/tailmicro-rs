//! On-device lwIP glue for the tailnet netif. See `super` for the threading
//! rules this file is built against.

use super::{OutboundPacket, OutboundSender, TailnetError, MTU, TAILNET_NETMASK};

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;
use std::sync::OnceLock;

use esp_idf_sys::*;

/// Whether `NETIF` has been registered with lwIP yet. Only ever flipped by
/// `do_bring_up`, which always runs on the tcpip thread (see
/// `run_on_tcpip_thread`) -- so this is the one piece of state genuinely
/// shared across threads, and it is only ever read/written as a plain
/// atomic flag (no data behind it needs synchronizing beyond this bit).
static NETIF_UP: AtomicBool = AtomicBool::new(false);

/// The lwIP netif struct. Must live at a fixed address for as long as it is
/// registered (lwIP stores this pointer in its global netif list), hence a
/// `static mut` rather than a stack/heap value tm_netstack could otherwise
/// own and move. All reads/writes happen on the tcpip thread only, via
/// `run_on_tcpip_thread` / the `input`/`output` callbacks lwIP invokes
/// directly on that thread -- never from the tokio task.
static mut NETIF: MaybeUninit<netif> = MaybeUninit::uninit();

/// Sender the `output` callback uses to hand outbound packets back to
/// `tm_runtime`'s event router. Set once by the first `bring_up` call.
/// `OnceLock` (not a `Mutex`) because it is written exactly once per boot
/// and read from the tcpip thread on every outbound packet after that --
/// no per-packet lock contention.
static OUTBOUND_TX: OnceLock<OutboundSender> = OnceLock::new();

/// Bring the tailnet netif up with `our_ip`, registering `outbound_tx` as
/// the sink for packets lwIP wants to send out this interface. Idempotent
/// across repeated `OurIpAssigned`/`MapUpdate` events carrying the same IP
/// (checked by the caller in practice, but also safe to call again here --
/// see `set_address`).
pub fn bring_up(our_ip: [u8; 4], outbound_tx: OutboundSender) -> Result<(), TailnetError> {
    // OnceLock: only the first call's sender wins. There is only ever one
    // Runtime/event-router per boot, so this is set exactly once.
    let _ = OUTBOUND_TX.set(outbound_tx);

    if NETIF_UP.load(Ordering::SeqCst) {
        return set_address(our_ip);
    }

    run_on_tcpip_thread(move || do_bring_up(our_ip))?
}

/// Reassign the netif's address. Used when `our_ip` changes across a
/// control-plane reconnect (a stable IP is plan (b)'s follow-up; this just
/// needs to be correct, not optimal, per the plan's lifecycle item).
/// Brings the netif down, reassigns, and brings it back up -- all inside a
/// single `tcpip_callback` job so no half-applied state is ever observed by
/// lwIP's other users (e.g. an in-flight `ip4_route` lookup).
pub fn set_address(new_ip: [u8; 4]) -> Result<(), TailnetError> {
    if !NETIF_UP.load(Ordering::SeqCst) {
        return run_on_tcpip_thread(move || do_bring_up(new_ip))?;
    }
    run_on_tcpip_thread(move || unsafe {
        let netif_ptr = netif_ptr();
        netif_set_down(netif_ptr);
        let ip = ip4_addr_from_bytes(new_ip)?;
        let mask = ip4_addr_from_bytes(TAILNET_NETMASK)?;
        netif_set_addr(netif_ptr, &ip, &mask, &ip);
        netif_set_up(netif_ptr);
        netif_set_link_up(netif_ptr);
        Ok(())
    })?
}

/// Inject a decrypted inbound IP packet into lwIP. Called from the tokio
/// task (the event router, on `WgEvent::InboundDecrypted`) -- safe to call
/// directly because `tcpip_input()` itself does the hand-off to the tcpip
/// thread; we must NOT call `netif->input`/`ip_input` directly from here.
pub fn inject_inbound(payload: &[u8]) -> Result<(), TailnetError> {
    if !NETIF_UP.load(Ordering::SeqCst) {
        return Err(TailnetError::NotUp);
    }
    if payload.len() > u16::MAX as usize {
        return Err(TailnetError::Lwip(-1));
    }
    let len = payload.len() as u16;
    unsafe {
        let p = pbuf_alloc(pbuf_layer_PBUF_RAW, len, pbuf_type_PBUF_POOL);
        if p.is_null() {
            return Err(TailnetError::Lwip(err_enum_t_ERR_MEM as i8));
        }
        let rc = pbuf_take(p, payload.as_ptr() as *const c_void, len);
        if rc as i32 != err_enum_t_ERR_OK {
            pbuf_free(p);
            return Err(TailnetError::Lwip(rc));
        }
        // tcpip_input takes ownership of `p` on success (ERR_OK): it posts
        // the pointer into the tcpip task's mailbox and that task frees it
        // after `ip_input` is done with it. On failure ownership stays with
        // us, so we must free it here -- freeing after a successful post
        // would be a use-after-free/double-free on the tcpip thread.
        let rc = tcpip_input(p, netif_ptr());
        if rc as i32 != err_enum_t_ERR_OK {
            pbuf_free(p);
            return Err(TailnetError::Lwip(rc));
        }
    }
    Ok(())
}

/// Raw pointer to the static netif. `&raw mut` avoids creating an
/// intermediate `&mut` reference to the `static mut` (which would be UB if
/// aliased); every caller of this function is required by this module's
/// contract to only ever be running on the tcpip thread.
unsafe fn netif_ptr() -> *mut netif {
    (&raw mut NETIF).cast::<netif>()
}

/// The actual `netif_add` + bring-up sequence. MUST run on the tcpip thread
/// (see `run_on_tcpip_thread`).
fn do_bring_up(our_ip: [u8; 4]) -> Result<(), TailnetError> {
    unsafe {
        let ip = ip4_addr_from_bytes(our_ip)?;
        let mask = ip4_addr_from_bytes(TAILNET_NETMASK)?;
        let netif_ptr = netif_ptr();
        // Defensive zero of the whole struct before netif_add. netif_add
        // itself resets every field it depends on (ip_addr/netmask/gw,
        // output(_ip6), mtu, flags, igmp/mld filters, acd_list, ip6 address
        // table, ...; see netif_add() in esp-idf's lwip/src/core/netif.c),
        // but `hostname`/`hwaddr`/`client_data` are not among them and this
        // static starts as `MaybeUninit` -- zeroing removes any dependence
        // on that not mattering across lwIP versions/configs.
        core::ptr::write_bytes(netif_ptr, 0, 1);
        let ret = netif_add(
            netif_ptr,
            &ip,
            &mask,
            &ip, // gw: irrelevant once the /10 netmask makes the network-match
                 // route hit (see TAILNET_NETMASK's doc comment); set to our
                 // own address rather than 0.0.0.0 so ip4_route's secondary
                 // "gateway matches on a non-broadcast interface" branch also
                 // has a sane, well-defined value if ever exercised.
            core::ptr::null_mut(),
            Some(tailnet_init_cb),
            Some(ip_input),
        );
        if ret.is_null() {
            return Err(TailnetError::Lwip(-1));
        }
        netif_set_up(netif_ptr);
        netif_set_link_up(netif_ptr);
    }
    NETIF_UP.store(true, Ordering::SeqCst);
    Ok(())
}

/// netif `init` callback, invoked synchronously by `netif_add` (on the
/// tcpip thread, since `netif_add` itself is only ever called from
/// `do_bring_up` via `run_on_tcpip_thread`). Configures this as a raw-IP,
/// no-L2 ("tun"-style) interface: no `NETIF_FLAG_ETHARP`/`ETHERNET` (no ARP,
/// no Ethernet framing) and no `NETIF_FLAG_BROADCAST`.
///
/// Note on the plan's original `NETIF_FLAG_POINTTOPOINT`: this lwIP version
/// (esp-idf release-v5.5's vendored lwIP) has no such flag --
/// `components/lwip/lwip/src/include/lwip/netif.h` only defines
/// `UP`/`BROADCAST`/`LINK_UP`/`ETHARP`/`ETHERNET`/`IGMP`/`MLD6`. The
/// point-to-point/no-L2 behavior the plan wants is achieved simply by
/// leaving `ETHARP`/`ETHERNET`/`BROADCAST` unset, matching how lwIP's own
/// raw netifs (PPP, loopif) are configured.
unsafe extern "C" fn tailnet_init_cb(netif: *mut netif) -> err_t {
    unsafe {
        (*netif).name[0] = b'w' as core::ffi::c_char;
        (*netif).name[1] = b'g' as core::ffi::c_char;
        (*netif).output = Some(tailnet_output_cb);
        (*netif).mtu = MTU;
        (*netif).flags = (NETIF_FLAG_UP | NETIF_FLAG_LINK_UP) as u8;
    }
    err_enum_t_ERR_OK as err_t
}

/// netif `output` callback: lwIP calls this (ON THE TCPIP THREAD) whenever
/// it wants to send an IPv4 packet out this interface. Must not block --
/// copies the packet and hands it off via a non-blocking channel `try_send`
/// for the tokio-side event router to pick up (it looks up the destination
/// tailnet IP -> peer node key and relays via `WgCmd::SendData`).
///
/// Per lwIP convention (matches every stock netif driver, e.g.
/// `ethernetif_output`/PPP's `output`), this function does NOT free `p`:
/// ownership stays with the caller (`ip4_output_if`), which frees it (or
/// leaves it to whichever pbuf owner queued it, e.g. TCP retransmission)
/// after this call returns.
unsafe extern "C" fn tailnet_output_cb(
    _netif: *mut netif,
    p: *mut pbuf,
    _ipaddr: *const ip4_addr_t,
) -> err_t {
    // This callback runs on the tcpip task, whose stack is small
    // (CONFIG_LWIP_TCPIP_TASK_STACK_SIZE, 3072 bytes in this project's
    // sdkconfig -- see the deployment note this module's doc points at).
    // Building a full ~1500-byte `heapless::Vec` as a plain local here
    // (then `Box::new`-ing it) would reserve a stack slot close to half
    // that budget on top of lwIP's own call depth to reach this callback --
    // the exact class of bug documented at length in
    // docs/wg-dataplane-notes.md for the (much larger) main task stack.
    // `tm_buf::PktBuf::acquire` hands back a pooled heap buffer, or, if
    // the pool is empty, allocates one via `Box::write(Box::new_uninit(),
    // ..)`, which constructs the empty `Vec` directly on the heap. Either
    // way the only per-packet stack cost here is the loop locals, not the
    // packet buffer itself; every subsequent `extend_from_slice` below
    // writes straight into that heap memory. The pool's Mutex is held only
    // for one pop, so taking it from this (tcpip) thread is fine.
    let mut buf: tm_buf::PktBuf = tm_buf::PktBuf::acquire();
    unsafe {
        let mut cur = p;
        while !cur.is_null() {
            let seg_len = (*cur).len as usize;
            let seg = core::slice::from_raw_parts((*cur).payload as *const u8, seg_len);
            // Silently truncates past MAX_PACKET; this matches every other
            // packet buffer in this workspace (see tm_wg/tm_runtime), and a
            // legitimate IP packet destined for us never exceeds MTU (1380)
            // + headers, well under MAX_PACKET (1532).
            let _ = buf.extend_from_slice(seg);
            cur = (*cur).next;
        }
    }
    if buf.len() < 20 {
        // Too short to carry a valid IPv4 header; nothing sane to route.
        return err_enum_t_ERR_VAL as err_t;
    }
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&buf[16..20]);
    if tm_buf::lat::ENABLED && tm_buf::lat::is_icmp_echo(&buf, 0) {
        tm_buf::lat::stamp(tm_buf::lat::Hop::NetifOut);
    }
    if let Some(tx) = OUTBOUND_TX.get() {
        // try_send: synchronous, non-blocking, thread-safe without an
        // executor (async_channel's queue is a plain concurrent structure).
        // Drop-on-full is the same backpressure philosophy as every other
        // inter-actor channel in this workspace (CHAN_CAP = 2 in
        // tm_runtime) -- a full channel means the event router is behind,
        // and dropping here is strictly better than blocking the tcpip
        // thread.
        let _ = tx.try_send(OutboundPacket { dst_ip, data: buf });
    }
    err_enum_t_ERR_OK as err_t
}

/// Parse a dotted-quad byte array into an `ip4_addr_t` via lwIP's own
/// parser (`ipaddr_addr`), rather than hand-rolling the network-byte-order
/// packing of `ip4_addr_t.addr` (a real risk of a silent, hard-to-spot
/// routing bug if gotten backwards on a little-endian target). This runs
/// only at netif bring-up/address-change time (not per packet), so the
/// string round-trip cost is irrelevant.
fn ip4_addr_from_bytes(b: [u8; 4]) -> Result<ip4_addr_t, TailnetError> {
    let s = CString::new(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        .map_err(|_| TailnetError::Lwip(-1))?;
    let addr = unsafe { ipaddr_addr(s.as_ptr()) };
    if addr == u32::MAX {
        // ipaddr_addr returns IPADDR_NONE (0xffffffff) on parse failure.
        // A real 255.255.255.255 would also hit this, but that value never
        // appears as our_ip/netmask/gw in this module's callers.
        return Err(TailnetError::Lwip(-1));
    }
    Ok(ip4_addr_t { addr })
}

/// Run `f` on the lwIP tcpip thread and block (via a `std::sync::mpsc`
/// rendezvous) until it has finished, returning whatever `f` returns.
///
/// This is the one place in this module that blocks the calling task. It is
/// only ever called from `bring_up`/`set_address` -- rare, one-shot
/// lifecycle events (boot, and reconnect-time IP changes), not a per-packet
/// path -- so blocking the single OS thread backing the tokio
/// `current_thread` runtime for the (sub-millisecond) time it takes the
/// tcpip task to drain its callback mailbox is an acceptable trade. Do NOT
/// reuse this helper for anything per-packet; `inject_inbound` deliberately
/// uses `tcpip_input()` instead, which hands off without blocking.
fn run_on_tcpip_thread<R, F>(f: F) -> Result<R, TailnetError>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel::<R>(1);
    let job: Box<dyn FnOnce() + Send> = Box::new(move || {
        let r = f();
        let _ = tx.send(r);
    });
    let ctx = Box::into_raw(Box::new(job)) as *mut c_void;
    let rc = unsafe { tcpip_callback(Some(tcpip_trampoline), ctx) };
    if rc as i32 != err_enum_t_ERR_OK {
        // tcpip_callback failed to enqueue the job -- the trampoline will
        // never run, so we must reclaim (and drop) the box ourselves here
        // instead of leaking it.
        unsafe {
            drop(Box::from_raw(ctx as *mut Box<dyn FnOnce() + Send>));
        }
        return Err(TailnetError::Lwip(rc));
    }
    rx.recv().map_err(|_| TailnetError::Lwip(-1))
}

/// Trampoline lwIP's `tcpip_callback` invokes on the tcpip thread. Unpacks
/// and runs the boxed closure `run_on_tcpip_thread` queued.
unsafe extern "C" fn tcpip_trampoline(ctx: *mut c_void) {
    let job: Box<Box<dyn FnOnce() + Send>> =
        unsafe { Box::from_raw(ctx as *mut Box<dyn FnOnce() + Send>) };
    job();
}
