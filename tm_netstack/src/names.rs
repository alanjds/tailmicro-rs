//! MagicDNS name table: an `/etc/hosts` for the tailnet.
//!
//! Fed from the netmap, it maps a peer's name to its tailnet IPv4. Names are
//! stored as bare lowercase labels packed in one small arena, and the tailnet
//! suffix (`tailnet-xyz.ts.net`) is stored once, since every node of a tailnet
//! shares it. The table is about 330 bytes of `.bss`.
//!
//! On the device it is consulted by lwIP's `getaddrinfo` path through
//! `lwip_hook_netconn_external_resolve` (needs
//! `CONFIG_LWIP_HOOK_NETCONN_EXT_RESOLVE_CUSTOM=y`, see [`install`]), before any
//! DNS request leaves the device: a hit never touches the WiFi DNS server, a
//! miss falls through to it untouched, and no name is ever sent to the tailnet.
//! An app resolver ([`set_resolver`]) sits between the two: it can answer a name
//! MagicDNS did not know, claim it as not found, or pass it on.

use core::net::Ipv4Addr;
use std::sync::Mutex;

/// Peers plus ourselves.
pub const MAX_NAMES: usize = 9;
/// Total bytes of label text across all entries.
pub const ARENA_BYTES: usize = 192;
/// Longest tailnet suffix kept.
pub const MAX_SUFFIX: usize = 48;

/// Which names the table answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MagicDns {
    /// Never answer; every lookup goes to the normal resolver.
    Off,
    /// Only `label.<tailnet suffix>`.
    FqdnOnly,
    /// tailscaled's rules: the FQDN, plus bare `label` when control reports
    /// MagicDNS on (`DNSConfig.Proxied`). A hit always wins over WiFi DNS.
    #[default]
    Full,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    off: u8,
    len: u8,
    ip: [u8; 4],
}

#[derive(Debug)]
pub struct NameTable {
    suffix: heapless::String<MAX_SUFFIX>,
    proxied: bool,
    arena: heapless::Vec<u8, ARENA_BYTES>,
    entries: heapless::Vec<Entry, MAX_NAMES>,
}

impl NameTable {
    pub const fn new() -> Self {
        Self {
            suffix: heapless::String::new(),
            proxied: false,
            arena: heapless::Vec::new(),
            entries: heapless::Vec::new(),
        }
    }

    /// Set the tailnet suffix (no leading or trailing dot; empty when control
    /// names nodes with a bare label) and whether MagicDNS is on. An over-long
    /// suffix is dropped, which disables FQDN matching rather than mismatching.
    pub fn set_domain(&mut self, suffix: &str, proxied: bool) {
        self.suffix.clear();
        if self.suffix.push_str(suffix).is_err() {
            self.suffix.clear();
        }
        self.proxied = proxied;
    }

    /// The tailnet suffix set by [`set_domain`](Self::set_domain); empty when
    /// none, or when it was too long to keep.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// Add `label` (stored lowercased). False if it is empty, a duplicate, or
    /// the table or arena is full; the first entry for a label wins.
    pub fn insert(&mut self, label: &str, ip: [u8; 4]) -> bool {
        if label.is_empty()
            || label.contains('.')
            || self.entries.is_full()
            || self.find(label).is_some()
            || ARENA_BYTES - self.arena.len() < label.len()
        {
            return false;
        }
        let off = self.arena.len() as u8;
        for b in label.bytes() {
            let _ = self.arena.push(b.to_ascii_lowercase());
        }
        let _ = self.entries.push(Entry { off, len: label.len() as u8, ip });
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn find(&self, label: &str) -> Option<[u8; 4]> {
        self.entries.iter().find_map(|e| {
            let text = &self.arena[e.off as usize..e.off as usize + e.len as usize];
            text.eq_ignore_ascii_case(label.as_bytes()).then_some(e.ip)
        })
    }

    /// Resolve `name` under `mode`. A trailing dot and letter case are ignored.
    pub fn lookup(&self, name: &str, mode: MagicDns) -> Option<[u8; 4]> {
        if mode == MagicDns::Off {
            return None;
        }
        let name = name.strip_suffix('.').unwrap_or(name);
        match name.split_once('.') {
            None => {
                // With no suffix the bare label is the FQDN itself (headscale
                // with an empty base_domain), so it is always allowed.
                let short_ok = self.suffix.is_empty() || (mode == MagicDns::Full && self.proxied);
                if short_ok { self.find(name) } else { None }
            }
            Some((label, rest)) => {
                if self.suffix.is_empty() || !rest.eq_ignore_ascii_case(&self.suffix) {
                    return None;
                }
                self.find(label)
            }
        }
    }
}

impl Default for NameTable {
    fn default() -> Self {
        Self::new()
    }
}

/// What an app resolver ([`Resolver`]) decides about a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The name resolves to this address.
    Found(Ipv4Addr),
    /// The resolver owns the name but has no answer (for example a `.local`
    /// name nobody replied to). The lookup fails at once and the name is never
    /// sent to the WiFi DNS server.
    NotFound,
    /// Not the resolver's name; carry on with the normal DNS server.
    Pass,
}

/// An app-supplied resolver. Called from the lookup path after MagicDNS and
/// before lwIP's DNS client, in the thread that called `getaddrinfo`, so it
/// may block (bound it with a timeout) but must not `.await`.
pub type Resolver = fn(&str) -> Resolution;

struct Shared {
    mode: MagicDns,
    table: NameTable,
    resolver: Option<Resolver>,
}

static SHARED: Mutex<Shared> = Mutex::new(Shared { mode: MagicDns::Full, table: NameTable::new(), resolver: None });

fn shared() -> std::sync::MutexGuard<'static, Shared> {
    SHARED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Choose which names the process-wide table answers. Call before the first
/// netmap arrives.
pub fn set_mode(mode: MagicDns) {
    shared().mode = mode;
}

/// Set (or clear) the app resolver consulted after MagicDNS misses.
pub fn set_resolver(resolver: Option<Resolver>) {
    shared().resolver = resolver;
}

/// Replace the process-wide table, typically on every netmap.
pub fn install(table: NameTable) {
    #[cfg(target_os = "espidf")]
    {
        // The lwIP hook is only referenced from C; keep its object linked.
        core::hint::black_box(lwip_hook_netconn_external_resolve as usize);
    }
    shared().table = table;
}

/// Copy of the process-wide table's tailnet suffix (see [`NameTable::suffix`]).
pub fn suffix() -> heapless::String<MAX_SUFFIX> {
    shared().table.suffix.clone()
}

/// Resolve a tailnet name with the process-wide table. `None` means "not a
/// tailnet name here": the caller should use its normal resolver.
pub fn resolve(name: &str) -> Option<Ipv4Addr> {
    let s = shared();
    s.table.lookup(name, s.mode).map(Ipv4Addr::from)
}

/// The full lookup chain: MagicDNS first, then the app resolver, else
/// [`Resolution::Pass`] to the normal DNS server.
pub fn answer(name: &str) -> Resolution {
    let (found, resolver) = {
        let s = shared();
        (s.table.lookup(name, s.mode), s.resolver)
    };
    if let Some(ip) = found {
        return Resolution::Found(Ipv4Addr::from(ip));
    }
    // The lock is released: the resolver may block.
    resolver.map_or(Resolution::Pass, |resolve| resolve(name))
}

/// lwIP `LWIP_HOOK_NETCONN_EXTERNAL_RESOLVE`. Runs in the thread that called
/// `getaddrinfo` (tokio's `spawn_blocking` pool on the device), before any DNS
/// message. Returns 1 when it answered, 0 to let normal DNS proceed.
///
/// # Safety
/// Called by lwIP with valid, non-null pointers.
#[cfg(target_os = "espidf")]
#[no_mangle]
pub unsafe extern "C" fn lwip_hook_netconn_external_resolve(
    name: *const core::ffi::c_char,
    addr: *mut esp_idf_sys::ip_addr_t,
    addrtype: u8,
    err: *mut esp_idf_sys::err_t,
) -> core::ffi::c_int {
    // NETCONN_DNS_IPV6 (1): the caller wants an IPv6 address only.
    if name.is_null() || addr.is_null() || err.is_null() || addrtype == 1 {
        return 0;
    }
    let Ok(name) = core::ffi::CStr::from_ptr(name).to_str() else {
        return 0;
    };
    match answer(name) {
        Resolution::Found(ip) => {
            // `ip4_addr_t::addr` is in network byte order.
            (*addr).u_addr.ip4.addr = u32::from_ne_bytes(ip.octets());
            (*addr).type_ = 0; // IPADDR_TYPE_V4
            *err = esp_idf_sys::err_enum_t_ERR_OK as esp_idf_sys::err_t;
            1
        }
        Resolution::NotFound => {
            *err = esp_idf_sys::err_enum_t_ERR_VAL as esp_idf_sys::err_t;
            1
        }
        Resolution::Pass => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_chains_magicdns_then_the_app_resolver_then_passes() {
        fn app(name: &str) -> Resolution {
            match name {
                "printer.local" => Resolution::Found(Ipv4Addr::new(192, 168, 1, 9)),
                n if n.ends_with(".local") => Resolution::NotFound,
                _ => Resolution::Pass,
            }
        }
        set_resolver(None);
        assert_eq!(answer("printer.local"), Resolution::Pass, "no resolver: normal DNS");
        assert_eq!(suffix().as_str(), "", "nothing installed yet");
        install(table("tailnet-xyz.ts.net", true));
        assert_eq!(suffix().as_str(), "tailnet-xyz.ts.net", "the installed table's suffix, as given");
        set_resolver(Some(app));
        let tail = Ipv4Addr::new(100, 85, 218, 10);
        assert_eq!(answer("bospill"), Resolution::Found(tail), "MagicDNS wins");
        assert_eq!(answer("printer.local"), Resolution::Found(Ipv4Addr::new(192, 168, 1, 9)));
        assert_eq!(answer("ghost.local"), Resolution::NotFound);
        assert_eq!(answer("example.com"), Resolution::Pass);
        set_resolver(None);
        install(NameTable::new());
    }

    fn table(suffix: &str, proxied: bool) -> NameTable {
        let mut t = NameTable::new();
        t.set_domain(suffix, proxied);
        assert!(t.insert("bospill", [100, 85, 218, 10]));
        assert!(t.insert("Me", [100, 75, 48, 69]));
        t
    }

    #[test]
    fn full_resolves_fqdn_and_short_names_ignoring_case_and_dot() {
        let t = table("tailnet-xyz.ts.net", true);
        let want = Some([100, 85, 218, 10]);
        for n in ["bospill", "BosPill", "bospill.", "bospill.tailnet-xyz.ts.net", "BOSPILL.Tailnet-XYZ.ts.net."] {
            assert_eq!(t.lookup(n, MagicDns::Full), want, "{n}");
        }
        assert_eq!(t.lookup("me", MagicDns::Full), Some([100, 75, 48, 69]));
    }

    #[test]
    fn ordinary_names_never_match() {
        let t = table("tailnet-xyz.ts.net", true);
        for n in [
            "example.com",
            "login.tailscale.com",
            "bospill.other.ts.net",
            "bospill.tailnet-xyz.ts.net.evil.com",
            "x.bospill.tailnet-xyz.ts.net",
            "unknown",
            "",
            ".",
        ] {
            assert_eq!(t.lookup(n, MagicDns::Full), None, "{n:?}");
        }
    }

    #[test]
    fn short_names_need_proxied_and_full() {
        let on = table("t.ts.net", true);
        let off = table("t.ts.net", false);
        assert!(on.lookup("bospill", MagicDns::Full).is_some());
        assert!(on.lookup("bospill", MagicDns::FqdnOnly).is_none());
        assert!(on.lookup("bospill.t.ts.net", MagicDns::FqdnOnly).is_some());
        assert!(off.lookup("bospill", MagicDns::Full).is_none());
        assert!(off.lookup("bospill.t.ts.net", MagicDns::Full).is_some());
        assert!(on.lookup("bospill.t.ts.net", MagicDns::Off).is_none());
    }

    #[test]
    fn bare_label_control_servers_resolve_bare_names_only() {
        let t = table("", false);
        assert!(t.lookup("bospill", MagicDns::FqdnOnly).is_some());
        assert!(t.lookup("bospill", MagicDns::Full).is_some());
        assert!(t.lookup("bospill.anything", MagicDns::Full).is_none());
    }

    #[test]
    fn insert_rejects_duplicates_empty_dotted_and_overflow() {
        let mut t = NameTable::new();
        assert!(t.insert("a", [1, 1, 1, 1]));
        assert!(!t.insert("A", [2, 2, 2, 2]), "first entry wins");
        assert!(!t.insert("", [2, 2, 2, 2]));
        assert!(!t.insert("a.b", [2, 2, 2, 2]));
        assert_eq!(t.lookup("a", MagicDns::FqdnOnly), Some([1, 1, 1, 1]));

        let mut t = NameTable::new();
        for i in 0..MAX_NAMES {
            assert!(t.insert(&format!("n{i}"), [i as u8; 4]));
        }
        assert!(!t.insert("one-too-many", [0; 4]));

        let mut t = NameTable::new();
        let long = "x".repeat(32);
        let fits = ARENA_BYTES / 32;
        for i in 0..fits {
            assert!(t.insert(&format!("{}{i}", &long[..31]), [0; 4]), "{i}");
        }
        assert!(!t.insert(&long, [0; 4]), "arena exhausted");
    }

    #[test]
    fn oversized_suffix_disables_fqdn_matching() {
        let mut t = NameTable::new();
        t.set_domain(&"a".repeat(MAX_SUFFIX + 1), true);
        t.insert("p", [1; 4]);
        assert!(t.lookup(&format!("p.{}", "a".repeat(MAX_SUFFIX + 1)), MagicDns::Full).is_none());
    }

    #[test]
    fn suffix_is_kept_as_given_and_empty_when_too_long() {
        let mut t = NameTable::new();
        assert_eq!(t.suffix(), "");
        t.set_domain("Tailnet-XYZ.ts.net", true);
        assert_eq!(t.suffix(), "Tailnet-XYZ.ts.net");
        t.set_domain(&"a".repeat(MAX_SUFFIX), true);
        assert_eq!(t.suffix().len(), MAX_SUFFIX);
        t.set_domain(&"a".repeat(MAX_SUFFIX + 1), true);
        assert_eq!(t.suffix(), "", "dropped whole, never truncated");
    }

    #[test]
    fn table_stays_small() {
        assert!(core::mem::size_of::<NameTable>() <= 336, "{}", core::mem::size_of::<NameTable>());
    }
}
