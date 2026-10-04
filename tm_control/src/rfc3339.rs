//! Minimal RFC 3339 timestamp parsing, for the node `KeyExpiry` field.
//!
//! A tiny hand-written parser instead of a time crate: the one timestamp we
//! read is a fixed-shape string from control, and no_std targets pay flash for
//! every dependency. No allocation.

/// The text was not an RFC 3339 timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadTime;

/// Unix seconds of Go's zero `time.Time` (`0001-01-01T00:00:00Z`), which
/// control sends for a key that never expires.
const ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// Parse a `KeyExpiry` value: unix seconds, or `None` for the zero time (the
/// key never expires). Anything that is not a valid timestamp is an error, so
/// the caller can keep what it had instead of showing a wrong expiry.
pub fn parse_key_expiry(s: &str) -> Result<Option<i64>, BadTime> {
    let t = parse_unix(s)?;
    Ok(if t <= ZERO_TIME_UNIX { None } else { Some(t) })
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)` to unix seconds.
/// Fractional seconds are dropped. The date and fields are range checked.
pub fn parse_unix(s: &str) -> Result<i64, BadTime> {
    let b = s.as_bytes();
    // "YYYY-MM-DDTHH:MM:SS" is 19 bytes, and a zone follows at the least.
    if b.len() < 20 {
        return Err(BadTime);
    }
    let sep = |i: usize, c: u8| if b[i] == c { Ok(()) } else { Err(BadTime) };
    sep(4, b'-')?;
    sep(7, b'-')?;
    if b[10] != b'T' && b[10] != b't' {
        return Err(BadTime);
    }
    sep(13, b':')?;
    sep(16, b':')?;
    let year = digits(&b[0..4])?;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let min = digits(&b[14..16])?;
    let sec = digits(&b[17..19])?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || min > 59 || sec > 59 {
        return Err(BadTime);
    }

    let mut i = 19;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(BadTime);
        }
    }

    let offset = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(&sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let oh = digits(&b[i + 1..i + 3])?;
            let om = digits(&b[i + 4..i + 6])?;
            if oh > 23 || om > 59 {
                return Err(BadTime);
            }
            let secs = oh * 3600 + om * 60;
            if sign == b'+' { secs } else { -secs }
        }
        _ => return Err(BadTime),
    };

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3600 + min * 60 + sec - offset)
}

fn digits(b: &[u8]) -> Result<i64, BadTime> {
    let mut v = 0i64;
    for &c in b {
        if !c.is_ascii_digit() {
            return Err(BadTime);
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Ok(v)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(parse_unix("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(parse_unix("2000-03-01T00:00:00Z"), Ok(951_868_800));
        assert_eq!(parse_unix("2024-02-29T12:34:56Z"), Ok(1_709_210_096));
        assert_eq!(parse_unix("2038-01-19T03:14:08Z"), Ok(2_147_483_648));
        assert_eq!(parse_unix("0001-01-01T00:00:00Z"), Ok(ZERO_TIME_UNIX));
    }

    #[test]
    fn fraction_and_offsets() {
        assert_eq!(parse_unix("2026-12-01T00:00:00.123456789Z"), parse_unix("2026-12-01T00:00:00Z"));
        assert_eq!(parse_unix("2026-12-01T02:00:00+02:00"), parse_unix("2026-12-01T00:00:00Z"));
        assert_eq!(parse_unix("2026-11-30T19:30:00-04:30"), parse_unix("2026-12-01T00:00:00Z"));
        assert_eq!(parse_unix("2026-12-01t00:00:00z"), parse_unix("2026-12-01T00:00:00Z"));
    }

    #[test]
    fn zero_time_means_never_expires() {
        assert_eq!(parse_key_expiry("0001-01-01T00:00:00Z"), Ok(None));
        assert_eq!(parse_key_expiry("0001-01-01T00:00:00.000Z"), Ok(None));
        assert_eq!(parse_key_expiry("2026-12-01T00:00:00Z"), Ok(Some(1_796_083_200)));
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "", "x", "never", "2026-12-01", "2026-12-01T00:00:00", "2026-12-01 00:00:00Z",
            "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z", "2026-12-01T24:00:00Z", "2026-12-01T00:60:00Z",
            "2026-12-01T00:00:60Z", "2026-12-01T00:00:00.Z", "2026-12-01T00:00:00Zjunk",
            "2026-12-01T00:00:00+0200", "2026-12-01T00:00:00+24:00", "20x6-12-01T00:00:00Z",
            "+026-12-01T00:00:00Z", "2026-12-01T00:00:00.5", "\u{e9}026-12-01T00:00:00Z",
        ] {
            assert_eq!(parse_unix(s), Err(BadTime), "{s:?}");
        }
        assert_eq!(parse_key_expiry("garbage"), Err(BadTime));
    }
}
