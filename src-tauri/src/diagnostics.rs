//! پورت از `core/Diagnostics.kt`.
//!
//! همان خودآزمای ۴ مرحله‌ای اندروید که اعلام «Connected» را دروازه‌بانی می‌کند:
//!   ۱. پورت SOCKS5 باز است؟
//!   ۲. دست‌دادن SOCKS5 جواب می‌دهد؟
//!   ۳. TCP از دل پروکسی به IP خام (1.1.1.1:80) برقرار می‌شود؟
//!   ۴. DNS + HTTP واقعی از دل تونل (همراه با IP خروجی و کد کشور)؟
//!
//! مثل اندروید، مراحل ۳ و ۴ در یک پنجرهٔ گریس با تلاش مجدد هر ۷۵۰ms اجرا
//! می‌شوند (شروع سرد warp-in-warp چند ثانیه طول می‌کشد تا مسیر خروجی
//! واقعاً باز شود). نتیجهٔ هر مرحله زنده در `DiagnosticsLog::checks` منتشر
//! می‌شود تا پنل عیب‌یابی دقیقاً مثل موبایل رنگ عوض کند.

use crate::engine;
use crate::leakguard;
use crate::log::DiagnosticsLog;
use crate::probe;
use crate::profile::ConnectionProfile;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const TAG: &str = "diag";

static SELF_TEST_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn cancel_self_test() {
    SELF_TEST_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn self_test_cancelled(generation: u64) -> bool {
    SELF_TEST_GEN.load(std::sync::atomic::Ordering::SeqCst) != generation
}

pub const C_PORT: &str = "socks_port";
pub const C_HANDSHAKE: &str = "socks_handshake";
pub const C_TCP: &str = "tcp_via_proxy";
pub const C_DNS: &str = "dns_http_via_tunnel";
pub const C_LEAK: &str = "webrtc_udp_leak";

const RETRY_DELAY_MS: u64 = 750;
pub const EXTERNAL_GRACE_MS: u64 = 150_000;
const HANDSHAKE_RETRY_DELAY_MS: u64 = 1_500;

pub const TOR_BOOTSTRAP_BUDGET_MS: u64 = 300_000;
pub const TOR_BRIDGE_BUDGET_MS: u64 = 600_000;
pub const TOR_STALL_DIRECT_MS: u64 = 45_000;
pub const TOR_STALL_BRIDGED_MS: u64 = 420_000;

pub fn await_socks_handshake(
    port: u16,
    grace_ms: u64,
    alive: &dyn Fn() -> bool,
    abort: &dyn Fn() -> bool,
) -> bool {
    if probe::socks_handshake_ok_on(port) {
        return true;
    }
    if grace_ms == 0 {
        return false;
    }
    DiagnosticsLog::i(
        TAG,
        &format!(
            "stage 1: 127.0.0.1:{port} is listening but not answering yet — waiting up to {}s \
             for it ({}).",
            grace_ms / 1_000,
            crate::tor_bootstrap::describe()
        ),
    );
    let deadline = Instant::now() + Duration::from_millis(grace_ms);
    while Instant::now() < deadline {
        if !alive() {
            DiagnosticsLog::e(
                TAG,
                "stage 1: the engine exited while its proxy was still coming up.",
            );
            return false;
        }
        if abort() {
            DiagnosticsLog::e(
                TAG,
                &format!(
                    "stage 1: giving up early — {}.",
                    crate::tor_bootstrap::describe()
                ),
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(HANDSHAKE_RETRY_DELAY_MS));
        if probe::socks_handshake_ok_on(port) {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "stage 1: proxy answered ({}).",
                    crate::tor_bootstrap::describe()
                ),
            );
            return true;
        }
    }
    DiagnosticsLog::e(
        TAG,
        &format!(
            "stage 1: 127.0.0.1:{port} never answered within {}s ({}).",
            grace_ms / 1_000,
            crate::tor_bootstrap::describe()
        ),
    );
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorShape {
    FacingNetwork {
        bridges_allowed: bool,
        transport_installed: bool,
    },
    ThroughTunnel,
}

pub fn stage_failure_message(tor: Option<TorShape>) -> String {
    let Some(shape) = tor else {
        return "The tunnel started but the self-test failed.".to_string();
    };
    if shape == TorShape::ThroughTunnel {
        let snap = crate::tor_bootstrap::snapshot();
        return match snap.percent {
            None => "The tunnel is up, but Tor never reported any progress from inside it. \
                     Try Tor on its own, which lets Tor pick its own way to the network."
                .to_string(),
            Some(p) => format!(
                "The tunnel is up, but Tor stopped at {p}% inside it and did not reach the Tor \
                 network. Try another protocol for the tunnel, or Tor on its own with bridges."
            ),
        };
    }
    let snap = crate::tor_bootstrap::snapshot();
    let no_transport = matches!(
        shape,
        TorShape::FacingNetwork {
            transport_installed: false,
            ..
        }
    );
    if no_transport {
        return match snap.percent {
            Some(p) if !snap.done => format!(
                "Tor stopped at {p}% and could not reach the Tor network. No pluggable transport \
                 is installed, so only plain bridges can be tried — and a network that filters \
                 Tor usually blocks those too. Use the Aether \u{2192} Tor mode: Tor is then \
                 dialled through the tunnel, where the operator cannot see or block it."
            ),
            _ => "The engine started but Tor never reported any progress towards the Tor \
                  network, and no pluggable transport is installed. Use the Aether \u{2192} Tor \
                  mode, which builds Tor inside the tunnel."
                .to_string(),
        };
    }
    match snap.percent {
        None => "The engine started but Tor never reported any progress towards the Tor \
                 network. Check that the connection is up, then try the Aether \u{2192} Tor \
                 mode, which builds Tor inside the tunnel."
            .to_string(),
        Some(p) if !snap.done => format!(
            "Tor stopped at {p}% and could not reach the Tor network. This is what a network \
             that filters Tor looks like. Turn bridges on under Tor settings, or use the \
             Aether \u{2192} Tor mode: Tor is then dialled through the tunnel, where the \
             operator cannot see or block it."
        ),
        _ => "Tor reached the network but no stream would open through it. Try again, or pick \
              another exit country."
            .to_string(),
    }
}

const STAGE_ONE_TARGETS: [(&str, u16); 2] = [("cloudflare.com", 80), ("www.gstatic.com", 80)];

pub fn run_proxy_stage(port: u16) -> bool {
    run_proxy_stage_with_grace(port, 0, &|| true, &|| false)
}

pub fn run_proxy_stage_with_grace(
    port: u16,
    grace_ms: u64,
    alive: &dyn Fn() -> bool,
    abort: &dyn Fn() -> bool,
) -> bool {
    DiagnosticsLog::i(
        TAG,
        &format!("Stage 1 check: is 127.0.0.1:{port} a working SOCKS5 proxy?"),
    );
    if !probe::socks_ready(port) {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: nothing listening on 127.0.0.1:{port}"),
        );
        return false;
    }
    if !await_socks_handshake(port, grace_ms, alive, abort) {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: 127.0.0.1:{port} is open but does not speak SOCKS5"),
        );
        return false;
    }
    let tor_targets: [(&str, u16); 3] = [
        ("cloudflare.com", 443),
        ("www.gstatic.com", 443),
        ("cloudflare.com", 80),
    ];
    let targets: &[(&str, u16)] = if grace_ms > 0 {
        &tor_targets
    } else {
        &STAGE_ONE_TARGETS
    };
    let stream_deadline = Instant::now() + Duration::from_secs(25);
    let mut working = false;
    loop {
        for (host, dest) in targets {
            if !alive() || abort() {
                break;
            }
            if probe::tcp_via_proxy_on(port, host, *dest) {
                working = true;
                break;
            }
            if grace_ms > 0 && Instant::now() >= stream_deadline {
                break;
            }
        }
        if working || grace_ms == 0 || !alive() || abort() || Instant::now() >= stream_deadline {
            break;
        }
        DiagnosticsLog::w(
            TAG,
            "Tor has a circuit but its exit did not open a stream yet; retrying a fresh stream.",
        );
        std::thread::sleep(Duration::from_millis(750));
    }
    if !working {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: 127.0.0.1:{port} speaks SOCKS5 but cannot reach the internet"),
        );
        return false;
    }
    DiagnosticsLog::i(TAG, "Stage 1 is a working SOCKS5 proxy — starting stage 2.");
    true
}

pub fn reset_checks() {
    DiagnosticsLog::set_checks(vec![
        (
            C_PORT,
            format!("SOCKS5 port 127.0.0.1:{}", engine::exit_socks_port()),
        ),
        (C_HANDSHAKE, "SOCKS5 handshake".to_string()),
        (C_TCP, "TCP via proxy (1.1.1.1:80)".to_string()),
        (C_DNS, "DNS + HTTP via tunnel".to_string()),
        (C_LEAK, "WebRTC / UDP leak".to_string()),
    ]);
}

#[derive(Debug, Clone)]
pub struct SelfTestOutcome {
    pub ok: bool,
    pub exit: Option<probe::IpInfo>,
    pub latency_ms: Option<u64>,
    pub leak: Option<LeakReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakReport {
    pub leaking: bool,
    pub ip: Option<String>,
    pub server: Option<String>,
    pub detail: String,
}

const STUN_TIMEOUT_MS: u64 = 2_500;

pub fn webrtc_leak_check(exit_ip: Option<&str>) -> LeakReport {
    let guard = leakguard::status();
    match probe::stun_reflexive_ip(Duration::from_millis(STUN_TIMEOUT_MS)) {
        None => LeakReport {
            leaking: false,
            ip: None,
            server: None,
            detail: if guard.firewall_rules > 0 {
                if cfg!(windows) {
                    "no reply — Windows firewall kill-switch blocked direct UDP".to_string()
                } else {
                    "no reply — Linux nftables kill-switch blocked direct UDP".to_string()
                }
            } else if guard.browser_policies > 0 {
                "no reply — browser policy blocked direct UDP".to_string()
            } else {
                "no reply — direct UDP is blocked".to_string()
            },
        },
        Some(r) => {
            let via_tunnel = exit_ip.map(|e| e == r.reflexive_ip).unwrap_or(false);
            let browser_policy_only = guard.firewall_rules == 0 && guard.browser_policies > 0;
            let udp_open_by_design = guard.udp_browser_scoped && guard.browser_policies > 0;
            let leaking = !via_tunnel && !browser_policy_only && !udp_open_by_design;
            LeakReport {
                leaking,
                ip: Some(r.reflexive_ip.clone()),
                server: Some(r.server.clone()),
                detail: if via_tunnel {
                    format!("STUN answered with the tunnel exit ({})", r.reflexive_ip)
                } else if browser_policy_only {
                    "browser WebRTC policy is active; restart the browser to reload it".to_string()
                } else if udp_open_by_design {
                    format!(
                        "UDP is open for this app's own transports by design (Tor pipeline); the \
                         browser WebRTC policy is what covers the browser. {} answered from {}; \
                         restart the browser if it was already running.",
                        r.server, r.reflexive_ip
                    )
                } else {
                    format!("real IP {} reachable via {}", r.reflexive_ip, r.server)
                },
            }
        }
    }
}

pub fn self_test(grace_ms: u64) -> SelfTestOutcome {
    let generation = SELF_TEST_GEN.load(std::sync::atomic::Ordering::SeqCst);
    reset_checks();
    DiagnosticsLog::i(TAG, "Starting connectivity self-test…");

    DiagnosticsLog::update_check(C_PORT, "RUNNING", None);
    let port_open = probe::socks_ready(engine::exit_socks_port());
    if port_open {
        DiagnosticsLog::update_check(C_PORT, "PASS", Some("listening"));
        DiagnosticsLog::i(TAG, "SOCKS5 port check: open");
    } else {
        DiagnosticsLog::update_check(C_PORT, "FAIL", Some("no listener"));
        DiagnosticsLog::e(
            TAG,
            "SOCKS5 port check: nothing is listening — the engine is not up.",
        );
        DiagnosticsLog::update_check(C_HANDSHAKE, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_TCP, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_DNS, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_LEAK, "FAIL", Some("skipped"));
        return SelfTestOutcome {
            ok: false,
            exit: None,
            latency_ms: None,
            leak: None,
        };
    }

    DiagnosticsLog::update_check(C_HANDSHAKE, "RUNNING", None);
    let hs = probe::socks_handshake_ok();
    if hs {
        DiagnosticsLog::update_check(C_HANDSHAKE, "PASS", Some("method accepted"));
        DiagnosticsLog::i(TAG, "SOCKS5 handshake: OK");
    } else {
        DiagnosticsLog::update_check(C_HANDSHAKE, "FAIL", Some("no SOCKS5 reply"));
        DiagnosticsLog::e(
            TAG,
            "SOCKS5 handshake failed — the port is open but it is not a SOCKS5 server.",
        );
    }

    DiagnosticsLog::update_check(C_TCP, "RUNNING", None);
    DiagnosticsLog::update_check(C_DNS, "RUNNING", None);
    let deadline = Instant::now() + Duration::from_millis(grace_ms);
    let mut tcp_ok = false;
    let mut dns: Option<(probe::IpInfo, u64)> = None;
    loop {
        if !tcp_ok {
            tcp_ok = if grace_ms >= EXTERNAL_GRACE_MS {
                probe::tcp_via_proxy_within("1.1.1.1", 80, Duration::from_secs(12))
            } else {
                probe::tcp_via_proxy("1.1.1.1", 80)
            };
            if tcp_ok {
                DiagnosticsLog::update_check(C_TCP, "PASS", Some("connected"));
                DiagnosticsLog::i(TAG, "TCP via proxy: OK");
            }
        }
        if dns.is_none() {
            let started = Instant::now();
            let geo_timeout_ms = if grace_ms >= EXTERNAL_GRACE_MS {
                15_000
            } else {
                6_000
            };
            if let Some(info) = probe::fetch_ip_via_socks(geo_timeout_ms) {
                let ms = started.elapsed().as_millis() as u64;
                let cc = info
                    .country_code
                    .clone()
                    .unwrap_or_else(|| "??".to_string());
                DiagnosticsLog::update_check(
                    C_DNS,
                    "PASS",
                    Some(&format!("exit {} {}", info.ip, cc)),
                );
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "DNS+HTTP via tunnel: OK — exit {} {} ({} ms)",
                        mask_ip(&info.ip),
                        cc,
                        ms
                    ),
                );
                dns = Some((info, ms));
            }
        }
        if tcp_ok && dns.is_some() {
            break;
        }
        if Instant::now() >= deadline || self_test_cancelled(generation) {
            break;
        }
        std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    if !tcp_ok {
        DiagnosticsLog::update_check(
            C_TCP,
            "FAIL",
            Some("could not reach 1.1.1.1:80 through the proxy"),
        );
        DiagnosticsLog::e(
            TAG,
            "TCP via proxy failed — the engine accepted the connection but no upstream is flowing.",
        );
    }
    let ok = dns.is_some();
    if !ok {
        DiagnosticsLog::update_check(C_DNS, "FAIL", Some("no HTTP response through the tunnel"));
        if tcp_ok {
            DiagnosticsLog::w(
                TAG,
                "Raw TCP works, but the HTTPS exit-IP probe failed (DNS, TLS, HTTP or remote service); cause not yet known.",
            );
        } else {
            DiagnosticsLog::w(
                TAG,
                "No outbound path at all — the tunnel has no upstream yet.",
            );
        }
    }

    let (exit, latency_ms) = match dns {
        Some((info, ms)) => (Some(info), Some(ms)),
        None => (None, None),
    };

    DiagnosticsLog::update_check(C_LEAK, "RUNNING", None);
    let leak = webrtc_leak_check(exit.as_ref().map(|e| e.ip.as_str()));
    if leak.leaking {
        let masked = leak.ip.as_deref().map(mask_ip).unwrap_or_default();
        DiagnosticsLog::update_check(C_LEAK, "FAIL", Some("real IP still reachable over UDP"));
        DiagnosticsLog::e(
            TAG,
            &format!(
                "WebRTC leak: a STUN server answered with {masked} over direct UDP. Enable the leak guard, or restart the browser so the new policy is picked up."
            ),
        );
    } else if leakguard::status().udp_browser_scoped && leak.ip.is_some() {
        DiagnosticsLog::update_check(C_LEAK, "PASS", Some(&leak.detail));
        DiagnosticsLog::w(TAG, &format!("WebRTC / UDP leak check: {}", leak.detail));
    } else {
        DiagnosticsLog::update_check(C_LEAK, "PASS", Some(&leak.detail));
        DiagnosticsLog::i(
            TAG,
            &format!("WebRTC / UDP leak check: clean — {}", leak.detail),
        );
    }

    let ok = ok && !leak.leaking;
    SelfTestOutcome {
        ok,
        exit,
        latency_ms,
        leak: Some(leak),
    }
}

fn mask_ip(ip: &str) -> String {
    if let Some((head, _)) = ip.rsplit_once('.') {
        return format!("{head}.xxx");
    }
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').take(3).collect();
        return format!("{}::xxxx", parts.join(":"));
    }
    ip.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub name: String,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub checks: Vec<Check>,
    pub summary: String,
}

fn check(name: &str, verdict: Verdict, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        verdict,
        detail: detail.into(),
    }
}

pub fn run(profile: &ConnectionProfile) -> Report {
    let mut checks = Vec::new();

    let engine_exe = crate::engine::resolve_install_dir()
        .map(|d| d.join("engine").join(crate::engine::ENGINE_EXE));
    checks.push(match &engine_exe {
        Some(p) if p.exists() => check("Engine binary", Verdict::Pass, p.display().to_string()),
        Some(p) => check(
            "Engine binary",
            Verdict::Fail,
            format!("Missing: {}", p.display()),
        ),
        None => check(
            "Engine binary",
            Verdict::Fail,
            "Could not resolve the install directory",
        ),
    });

    #[cfg(windows)]
    {
        let wintun = crate::engine::resolve_install_dir()
            .map(|d| d.join("engine").join("wintun.dll"));
        checks.push(match &wintun {
            Some(p) if p.exists() => check("Wintun driver", Verdict::Pass, "Present"),
            _ => check(
                "Wintun driver",
                Verdict::Warn,
                "wintun.dll missing — system-proxy mode still works",
            ),
        });
        checks.push(if is_elevated() {
            check("Administrator rights", Verdict::Pass, "Running elevated")
        } else {
            check(
                "Administrator rights",
                Verdict::Warn,
                "Not elevated — connection uses the Windows system proxy instead of a TUN adapter",
            )
        });
    }
    #[cfg(not(windows))]
    {
        let tun_dev = std::path::Path::new("/dev/net/tun").exists();
        checks.push(if tun_dev {
            check("TUN device", Verdict::Pass, "/dev/net/tun present")
        } else {
            check(
                "TUN device",
                Verdict::Warn,
                "/dev/net/tun missing — system-proxy mode still works",
            )
        });
        checks.push(if is_elevated() {
            check("Network privileges", Verdict::Pass, "Running as root (TUN & nftables ready)")
        } else {
            check(
                "Network privileges",
                Verdict::Warn,
                "Running as standard user — connection uses the Linux system proxy",
            )
        });
    }

    checks.push(if probe::socks_ready(engine::exit_socks_port()) {
        check(
            "Local SOCKS5",
            Verdict::Pass,
            format!("127.0.0.1:{}", engine::exit_socks_port()),
        )
    } else {
        check(
            "Local SOCKS5",
            Verdict::Warn,
            "Not listening (expected while disconnected)",
        )
    });

    checks.push(match probe::verify_egress() {
        Some(r) => check(
            "Tunnel egress",
            Verdict::Pass,
            format!("{} in {} ms", r.endpoint, r.latency_ms),
        ),
        None => check("Tunnel egress", Verdict::Warn, "No verified egress yet"),
    });

    checks.push(if profile.mtu >= 576 && profile.mtu <= 9000 {
        check("Profile", Verdict::Pass, format!("MTU {}", profile.mtu))
    } else {
        check(
            "Profile",
            Verdict::Warn,
            format!("Unusual MTU: {}", profile.mtu),
        )
    });

    checks.push(match crate::provenance::engine_patch_level() {
        Some(engine) if crate::provenance::consistent() => check(
            "Build identity",
            Verdict::Pass,
            format!(
                "app {} runs the bundled, unmodified Aether core {engine}",
                crate::provenance::APP_PATCH_LEVEL
            ),
        ),
        Some(engine) => check(
            "Build identity",
            Verdict::Fail,
            format!(
                "WRONG ENGINE: this app ships Aether core {} but {} reports {engine}. \
                 Reinstall so the engine and the app match.",
                crate::provenance::expected_core_version(),
                crate::engine::ENGINE_EXE,
            ),
        ),
        None => check(
            "Build identity",
            Verdict::Warn,
            format!(
                "app patch level {}; the engine has not reported its core version yet",
                crate::provenance::APP_PATCH_LEVEL
            ),
        ),
    });

    let guard = leakguard::status();
    checks.push(if guard.engaged && guard.firewall_rules > 0 {
        check(
            "Leak guard",
            Verdict::Pass,
            format!(
                "{} firewall rule(s) + {} browser policy value(s) active",
                guard.firewall_rules, guard.browser_policies
            ),
        )
    } else if guard.engaged {
        check(
            "Leak guard",
            Verdict::Warn,
            format!(
                "{} browser policy value(s) active; firewall layer needs elevated privileges",
                guard.browser_policies
            ),
        )
    } else {
        check(
            "Leak guard",
            Verdict::Warn,
            "Not engaged (expected while disconnected)",
        )
    });

    let failed = checks.iter().filter(|c| c.verdict == Verdict::Fail).count();
    let warned = checks.iter().filter(|c| c.verdict == Verdict::Warn).count();
    let summary = if failed > 0 {
        format!("{failed} blocking problem(s) found")
    } else if warned > 0 {
        format!("{warned} warning(s), nothing blocking")
    } else {
        "Everything looks healthy".to_string()
    };

    Report { checks, summary }
}

#[cfg(windows)]
pub(crate) fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub(crate) fn is_elevated() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(euid) = rest.split_whitespace().nth(1) {
                    return euid == "0";
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_always_has_every_check() {
        let r = run(&ConnectionProfile::default());
        let names: Vec<&str> = r.checks.iter().map(|c| c.name.as_str()).collect();
        for expected in ["Build identity", "Profile", "Leak guard", "Tunnel egress"] {
            assert!(
                names.contains(&expected),
                "check `{expected}` is missing from {names:?}"
            );
        }
        assert_eq!(r.checks.len(), 8, "checks were {names:?}");
        assert!(!r.summary.is_empty());
    }

    #[test]
    fn reset_populates_every_live_check() {
        reset_checks();
        let checks = DiagnosticsLog::checks();
        assert_eq!(checks.len(), 5);
        assert!(checks.iter().any(|c| c.id == C_LEAK));
        assert!(checks.iter().all(|c| c.state == "PENDING"));
    }

    const FIELD_LINE_15: &str = "1789462449037 D/engine: [2026-09-15T08:54:09.037Z INFO  \
                                 aether::tor::with_tor] [*] tor reaching the network: 15%: \
                                 connecting successfully; directory is fetching a consensus";

    fn at_15() {
        crate::tor_bootstrap::reset();
        crate::tor_bootstrap::ingest(FIELD_LINE_15);
        assert_eq!(crate::tor_bootstrap::snapshot().percent, Some(15));
    }

    #[test]
    fn without_tor_the_message_is_the_tunnel_self_test() {
        let msg = stage_failure_message(None);
        assert!(msg.contains("self-test"), "{msg}");
        assert!(!msg.contains("Tor"), "{msg}");
    }

    #[test]
    fn tor_inside_the_tunnel_never_advises_bridges() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::ThroughTunnel));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("tunnel is up"), "{msg}");
        assert!(!msg.to_lowercase().contains("bridges on"), "{msg}");
        assert!(!msg.contains("Aether \u{2192} Tor"), "{msg}");
    }

    #[test]
    fn tor_facing_the_network_with_a_transport_advises_bridges() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::FacingNetwork {
            bridges_allowed: true,
            transport_installed: true,
        }));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("bridges on"), "{msg}");
        assert!(!msg.contains("No pluggable transport"), "{msg}");
    }

    #[test]
    fn tor_without_a_transport_says_bridges_cannot_run_properly() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::FacingNetwork {
            bridges_allowed: true,
            transport_installed: false,
        }));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("No pluggable transport"), "{msg}");
        assert!(msg.contains("plain bridges"), "{msg}");
        assert!(msg.contains("Aether \u{2192} Tor"), "{msg}");
    }

    #[test]
    fn a_silent_tor_never_invents_a_percentage() {
        for shape in [
            TorShape::ThroughTunnel,
            TorShape::FacingNetwork {
                bridges_allowed: true,
                transport_installed: true,
            },
            TorShape::FacingNetwork {
                bridges_allowed: false,
                transport_installed: false,
            },
        ] {
            crate::tor_bootstrap::reset();
            let msg = stage_failure_message(Some(shape));
            assert!(!msg.contains('%'), "{shape:?}: {msg}");
            assert!(
                msg.contains("never reported any progress"),
                "{shape:?}: {msg}"
            );
        }
    }

    #[test]
    fn no_stun_reply_is_not_a_leak() {
        let r = LeakReport {
            leaking: false,
            ip: None,
            server: None,
            detail: "no reply — direct UDP is blocked".to_string(),
        };
        assert!(!r.leaking);
    }
}
