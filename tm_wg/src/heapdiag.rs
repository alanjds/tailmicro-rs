//! TEMPORARY heap diagnostics (ALLOCATIONS.md Step 7). Device-only; every
//! function is a no-op on host builds.
//!
//! - `snap(tag)`: `heap_caps_get_info` block-count probe (same numbers as the
//!   older per-crate `heap_probe_blocks` helpers), returned so callers can
//!   diff two snapshots.
//! - `trace_begin`/`trace_end`: an ESP-IDF standalone heap trace window
//!   (`HEAP_TRACE_LEAKS`), so every allocation made anywhere in the system
//!   (any FreeRTOS task) inside the window that is still live at its end is
//!   printed with its size and caller PCs. Needs
//!   `CONFIG_HEAP_TRACING_STANDALONE=y` + `CONFIG_HEAP_TRACING_STACK_DEPTH=6`
//!   in the app's sdkconfig AND this crate's `heap-trace` feature (without
//!   it the window only diffs two `snap`s, and nothing links against
//!   `heap_trace_*`); windows do not nest (a nested begin is logged
//!   and ignored, which is itself a signal that the outer window yielded).
//! - `install_alloc_failed_dump()`: on any failed heap allocation, print the
//!   whole internal-heap block map (address-ordered `U<size>`/`F<size>`) so
//!   the fragmentation at the moment of the crash is visible.

#[derive(Clone, Copy, Default)]
pub struct Snap {
    pub total_free: usize,
    pub largest_free: usize,
    pub allocated_blocks: usize,
    pub free_blocks: usize,
}

#[inline(never)]
pub fn snap(tag: &str) -> Snap {
    #[cfg(target_os = "espidf")]
    unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        let s = Snap {
            total_free: info.total_free_bytes,
            largest_free: info.largest_free_block,
            allocated_blocks: info.allocated_blocks,
            free_blocks: info.free_blocks,
        };
        let hwm = esp_idf_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut());
        let stk = esp_idf_sys::pxTaskGetStackStart(core::ptr::null_mut());
        tracing::info!(
            "heapdiag [{}]: total_free={} largest_free={} free_blocks={} allocated_blocks={} task_stack_min_free={} stack_start={:p}",
            tag, s.total_free, s.largest_free, s.free_blocks, s.allocated_blocks, hwm, stk,
        );
        s
    }
    #[cfg(not(target_os = "espidf"))]
    {
        let _ = tag;
        Snap::default()
    }
}

#[cfg(all(target_os = "espidf", feature = "heap-trace"))]
mod dev {
    use core::sync::atomic::{AtomicBool, Ordering};

    // heap_trace_record_t with CONFIG_HEAP_TRACING_STACK_DEPTH=6, standalone,
    // no hash map: ccount, address, size, freed(bool, padded), 6+6 callers,
    // TAILQ_ENTRY (2 ptrs) = 4 * (4 + 12 + 2) = 72 bytes.
    const REC_WORDS: usize = 18;
    const N_RECORDS: usize = 64;
    static mut RECORDS: [u32; REC_WORDS * N_RECORDS] = [0; REC_WORDS * N_RECORDS];
    static INIT: AtomicBool = AtomicBool::new(false);
    pub static ACTIVE: AtomicBool = AtomicBool::new(false);

    const HEAP_TRACE_LEAKS: u32 = 1;
    unsafe extern "C" {
        fn heap_trace_init_standalone(buf: *mut core::ffi::c_void, n: usize) -> i32;
        fn heap_trace_start(mode: u32) -> i32;
        fn heap_trace_stop() -> i32;
        fn heap_trace_dump();
    }

    pub fn ensure_init() -> bool {
        if INIT.load(Ordering::SeqCst) {
            return true;
        }
        let rc = unsafe { heap_trace_init_standalone((&raw mut RECORDS).cast(), N_RECORDS) };
        if rc != 0 {
            tracing::warn!("heapdiag: heap_trace_init_standalone failed rc={}", rc);
            return false;
        }
        INIT.store(true, Ordering::SeqCst);
        true
    }
    pub fn start() -> bool {
        unsafe { heap_trace_start(HEAP_TRACE_LEAKS) == 0 }
    }
    pub fn stop() {
        unsafe {
            heap_trace_stop();
        }
    }
    pub fn dump() {
        unsafe { heap_trace_dump() }
    }
}

pub struct Window {
    tag: &'static str,
    owns: bool,
    before: Snap,
}

/// Open a trace window. If another window is already open (i.e. the code
/// that opened it yielded to the executor and we are running inside its
/// gap), log that and return a non-owning window.
pub fn trace_begin(tag: &'static str) -> Window {
    let before = snap(tag);
    #[cfg(all(target_os = "espidf", feature = "heap-trace"))]
    {
        use core::sync::atomic::Ordering;
        if dev::ACTIVE.swap(true, Ordering::SeqCst) {
            tracing::info!("heapdiag [{}]: NESTED inside another open trace window", tag);
            return Window { tag, owns: false, before };
        }
        if !dev::ensure_init() || !dev::start() {
            dev::ACTIVE.store(false, Ordering::SeqCst);
            return Window { tag, owns: false, before };
        }
        Window { tag, owns: true, before }
    }
    #[cfg(not(all(target_os = "espidf", feature = "heap-trace")))]
    Window { tag, owns: false, before }
}

/// Close a window: dump the still-live allocations made inside it if the
/// window cost at least one block or 1 KB of `largest_free`.
pub fn trace_end(w: Window, end_tag: &str) {
    #[cfg(all(target_os = "espidf", feature = "heap-trace"))]
    if w.owns {
        dev::stop();
    }
    let after = snap(end_tag);
    let d_blocks = after.allocated_blocks as isize - w.before.allocated_blocks as isize;
    let d_largest = after.largest_free as isize - w.before.largest_free as isize;
    let d_total = after.total_free as isize - w.before.total_free as isize;
    tracing::info!(
        "heapdiag window [{}] -> [{}]: d_allocated_blocks={} d_total_free={} d_largest_free={} owned_trace={}",
        w.tag, end_tag, d_blocks, d_total, d_largest, w.owns
    );
    #[cfg(all(target_os = "espidf", feature = "heap-trace"))]
    if w.owns {
        if d_blocks > 0 || d_largest <= -1024 {
            dev::dump();
        }
        dev::ACTIVE.store(false, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Register a failed-allocation hook that prints the internal heap's block
/// map. Uses only `esp_rom_printf` (no allocation) from inside the hook.
pub fn install_alloc_failed_dump() {
    #[cfg(target_os = "espidf")]
    unsafe {
        unsafe extern "C" fn on_fail(size: usize, caps: u32, func: *const core::ffi::c_char) {
            // Small failures are routine and recoverable: the WiFi driver's
            // dynamic RX buffers (1700 B, allocated from the wifi task) just
            // drop the frame. Dumping ~700 blocks at 115200 baud from inside
            // the wifi task on every one of them was measured to livelock the
            // device (hundreds of back-to-back dumps), so only the large,
            // fatal-in-practice failures get the map.
            if size < 4000 {
                return;
            }
            unsafe {
                esp_idf_sys::esp_rom_printf(
                    c"\nheapdiag: ALLOC FAILED size=%u caps=0x%x in %s; heap map (U=used F=free, address order):\n".as_ptr(),
                    size as u32, caps, func,
                );
                let mut n: u32 = 0;
                esp_idf_sys::heap_caps_walk(
                    esp_idf_sys::MALLOC_CAP_INTERNAL,
                    Some(walk),
                    (&raw mut n).cast(),
                );
                esp_idf_sys::esp_rom_printf(c"\nheapdiag: end heap map (%u blocks)\n".as_ptr(), n);
            }
        }
        unsafe extern "C" fn walk(
            _h: esp_idf_sys::walker_heap_into_t,
            b: esp_idf_sys::walker_block_info_t,
            user: *mut core::ffi::c_void,
        ) -> bool {
            unsafe {
                let n = &mut *(user as *mut u32);
                if b.used && b.size >= 3000 {
                    esp_idf_sys::esp_rom_printf(c"U%u@%p ".as_ptr(), b.size as u32, b.ptr);
                } else if b.used {
                    esp_idf_sys::esp_rom_printf(c"U%u ".as_ptr(), b.size as u32);
                } else {
                    esp_idf_sys::esp_rom_printf(c"[F%u@%p] ".as_ptr(), b.size as u32, b.ptr);
                }
                *n += 1;
                if *n % 16 == 0 {
                    esp_idf_sys::esp_rom_printf(c"\n".as_ptr());
                }
            }
            true
        }
        esp_idf_sys::heap_caps_register_failed_alloc_callback(Some(on_fail));
        tracing::info!("heapdiag: alloc-failed heap-map dump installed");
    }
}

