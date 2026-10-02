//! Own process: `set_clock` is global state.
use core::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};
use tm_time::Instant;

static FAKE: AtomicU64 = AtomicU64::new(10);

fn fake_now() -> u64 {
    FAKE.load(Ordering::SeqCst)
}
fn fake_unix() -> Option<u64> {
    Some(1_700_000_000)
}

#[test]
fn installed_clock_drives_now_and_unix_secs() {
    tm_time::set_clock(fake_now, fake_unix);
    let t0 = Instant::now();
    assert_eq!(t0.as_micros(), 10);
    FAKE.store(2_500_010, Ordering::SeqCst);
    assert_eq!(t0.elapsed(), Duration::from_millis(2500));
    assert_eq!(tm_time::unix_secs(), Some(1_700_000_000));
}
