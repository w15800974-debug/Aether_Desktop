//! Tunnel interface management (Windows Wintun / Linux TUN).
//!
//! On Windows: Wintun adapter -> Wintun session -> system proxy (TCP) + leak guard (UDP).
//! On Linux (Ubuntu 26.x): `/dev/net/tun` (`aether0`) via `ip tuntap` when running
//! with CAP_NET_ADMIN/root, gracefully falling back to GNOME/system proxy mode
//! when running as a regular desktop user.

use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, SplitMode};
#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);
pub const TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
pub const TUN_DNS_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
pub const TUN_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

#[cfg(windows)]
const ADAPTER_NAME: &str = "Aether";
#[cfg(windows)]
const ADAPTER_TYPE: &str = "Aether Tunnel";
#[cfg(windows)]
const ADAPTER_GUID: u128 = 0x7f1e_3c22_9a54_4d61_b0f3_9c2e_1a8d_47b5;

#[cfg(not(windows))]
const LINUX_TUN_NAME: &str = "aether0";

#[cfg(windows)]
pub struct Tunnel {
    adapter: Arc<wintun::Adapter>,
    session: Option<Arc<wintun::Session>>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

#[cfg(not(windows))]
pub struct Tunnel {
    created_dev: bool,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

#[cfg(windows)]
impl Tunnel {
    pub fn establish(profile: &ConnectionProfile, wintun_dll: &std::path::Path) -> Result<Self> {
        if !wintun_dll.is_file() {
            anyhow::bail!("wintun.dll not found at {}", wintun_dll.display());
        }
        let lib = unsafe { wintun::load_from_path(wintun_dll) }
            .with_context(|| format!("could not load {}", wintun_dll.display()))?;

        let adapter = match wintun::Adapter::open(&lib, ADAPTER_NAME) {
            Ok(a) => {
                DiagnosticsLog::i("tun", "Re-using the existing Aether Wintun adapter");
                a
            }
            Err(_) => {
                let mut last: Option<wintun::Error> = None;
                let mut made = None;
                for attempt in 0..3u32 {
                    match wintun::Adapter::create(&lib, ADAPTER_NAME, ADAPTER_TYPE, Some(ADAPTER_GUID))
                    {
                        Ok(a) => {
                            made = Some(a);
                            break;
                        }
                        Err(e) => {
                            DiagnosticsLog::w(
                                "tun",
                                &format!("Wintun create attempt {} failed: {e}", attempt + 1),
                            );
                            last = Some(e);
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            if let Ok(a) = wintun::Adapter::open(&lib, ADAPTER_NAME) {
                                made = Some(a);
                                break;
                            }
                        }
                    }
                }
                match made {
                    Some(a) => a,
                    None => {
                        let e = last.map(|e| e.to_string()).unwrap_or_default();
                        let code = os_code_of(&e);
                        return Err(anyhow::anyhow!(
                            "{}",
                            describe_create_failure(&e, code, crate::diagnostics::is_elevated())
                        ));
                    }
                }
            }
        };

        let session = adapter
            .start_session(wintun::MIN_RING_CAPACITY)
            .context("could not start the Wintun session")?;

        DiagnosticsLog::i(
            "tun",
            &format!(
                "Wintun adapter up, mtu={} (default {})",
                profile.mtu,
                crate::profile::DEFAULT_MTU
            ),
        );

        let me = Self {
            adapter,
            session: Some(Arc::new(session)),
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
        };
        me.configure_routes(profile)?;
        Ok(me)
    }

    fn configure_routes(&self, profile: &ConnectionProfile) -> Result<()> {
        let addr_ok = netsh(&[
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            &format!("address={TUN_IPV4}"),
            "mask=255.255.255.0",
        ]);
        let dns_ok = netsh(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            &format!("address={TUN_DNS_V4}"),
            "register=none",
            "validate=no",
        ]);
        DiagnosticsLog::i(
            "tun",
            &format!(
                "Adapter address {}: {} · in-tunnel DNS {}: {}",
                TUN_IPV4,
                if addr_ok { "applied" } else { "not applied (needs administrator)" },
                TUN_DNS_V4,
                if dns_ok { "applied" } else { "not applied (needs administrator)" },
            ),
        );
        log_route_summary(profile);
        Ok(())
    }

    pub fn session(&self) -> Option<Arc<wintun::Session>> {
        self.session.clone()
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    pub fn close(&mut self) {
        let had_session = self.session.take().is_some();
        let _ = self.adapter.get_luid();
        if had_session {
            DiagnosticsLog::i("tun", "Wintun adapter torn down");
        }
    }
}

#[cfg(not(windows))]
impl Tunnel {
    pub fn establish(profile: &ConnectionProfile, _wintun_dll: &std::path::Path) -> Result<Self> {
        let tun_dev = std::path::Path::new("/dev/net/tun").exists();
        let mut created_dev = false;

        if tun_dev && crate::diagnostics::is_elevated() {
            let _ = ip_cmd(&["link", "delete", LINUX_TUN_NAME]);
            let added = ip_cmd(&["tuntap", "add", "dev", LINUX_TUN_NAME, "mode", "tun"]);
            if added {
                let addr = format!("{TUN_IPV4}/24");
                let mtu_s = profile.mtu.to_string();
                let addr_ok = ip_cmd(&["addr", "replace", &addr, "dev", LINUX_TUN_NAME]);
                let up_ok = ip_cmd(&["link", "set", "dev", LINUX_TUN_NAME, "mtu", &mtu_s, "up"]);
                created_dev = addr_ok && up_ok;
                if created_dev {
                    DiagnosticsLog::i(
                        "tun",
                        &format!(
                            "Linux TUN interface {LINUX_TUN_NAME} up ({addr}, mtu={} / default {})",
                            profile.mtu,
                            crate::profile::DEFAULT_MTU
                        ),
                    );
                }
            }
        } else if tun_dev {
            DiagnosticsLog::i(
                "tun",
                "Linux /dev/net/tun present; running unprivileged — using GNOME/system proxy data path.",
            );
        } else {
            DiagnosticsLog::w(
                "tun",
                "/dev/net/tun not available — using Linux system proxy data path.",
            );
        }

        log_route_summary(profile);
        Ok(Self {
            created_dev,
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    pub fn close(&mut self) {
        if self.created_dev {
            self.created_dev = false;
            let _ = ip_cmd(&["link", "delete", LINUX_TUN_NAME]);
            DiagnosticsLog::i("tun", &format!("Linux TUN interface {LINUX_TUN_NAME} torn down"));
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
    }
}

fn log_route_summary(profile: &ConnectionProfile) {
    DiagnosticsLog::i(
        "tun",
        "Default routes NOT captured — data path is the system proxy (TCP). UDP containment is handled by the leak guard.",
    );
    if profile.ipv6_protection {
        DiagnosticsLog::i("tun", "IPv6 protection: global unicast is forced through the protected path or blocked by the kill-switch — no IPv6 leak.");
    } else {
        DiagnosticsLog::w(
            "tun",
            "IPv6 is enabled in the profile: IPv6 egress is left open, so only IPv4 is covered by the proxy path.",
        );
    }

    match profile.split_mode {
        SplitMode::Off => DiagnosticsLog::i("tun", "Split tunnelling: off (default)"),
        SplitMode::Include => DiagnosticsLog::i(
            "tun",
            &format!(
                "Split tunnelling: only {} go through the tunnel",
                profile.split_apps.len()
            ),
        ),
        SplitMode::Exclude => DiagnosticsLog::i(
            "tun",
            &format!(
                "Split tunnelling: {} bypass the tunnel",
                profile.split_apps.len()
            ),
        ),
    }
}

#[cfg(not(windows))]
fn ip_cmd(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn os_code_of(text: &str) -> i32 {
    text.rsplit("(os error ")
        .next()
        .filter(|_| text.contains("(os error "))
        .and_then(|t| t.split(')').next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

pub fn describe_create_failure(err: &str, os_code: i32, elevated: bool) -> String {
    let hint = if !elevated {
        "the process is NOT elevated - run Aether as administrator"
    } else if os_code == 183 || err.contains("already exists") {
        "an adapter with this name is still registered - it will be reused on the next attempt; if it persists, remove the stale 'Aether' adapter in Device Manager"
    } else if os_code == 5 || err.to_lowercase().contains("access is denied") {
        "access denied although elevated - security software or a driver policy is blocking the Wintun driver install"
    } else {
        "the Wintun driver could not be installed/started (check antivirus, Core Isolation, and that wintun.dll matches the app architecture)"
    };
    format!("could not create the Wintun adapter: {err} (os error {os_code}, elevated={elevated}) - {hint}")
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("netsh.exe"),
    );
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(test)]
mod failure_text_tests {
    use super::describe_create_failure;
    #[test]
    fn not_elevated_is_the_only_case_that_blames_admin() {
        assert!(describe_create_failure("x", 5, false).contains("NOT elevated"));
        assert!(!describe_create_failure("x", 5, true).contains("NOT elevated"));
    }
    #[test]
    fn parses_os_code() {
        assert_eq!(super::os_code_of("Access is denied. (os error 5)"), 5);
        assert_eq!(super::os_code_of("nothing"), 0);
    }
    #[test]
    fn already_exists_and_denied_are_distinguished() {
        assert!(describe_create_failure("x", 183, true).contains("still registered"));
        assert!(describe_create_failure("x", 5, true).contains("access denied although elevated"));
        assert!(describe_create_failure("boom", 1, true).contains("os error 1"));
    }
}
