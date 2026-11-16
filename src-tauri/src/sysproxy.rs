//! System proxy integration (Windows WinINET / Linux GNOME & KDE).
//!
//! When connected:
//!   1. Local HTTP<->SOCKS5 bridge (`share.rs`) listens on 127.0.0.1:10811.
//!   2. System proxy (WinINET on Windows, `org.gnome.system.proxy` on Ubuntu/GNOME)
//!      is pointed to the local bridge, after backing up the user's prior settings.
//!   3. On disconnect, error, or app exit, the exact prior settings are restored.

use crate::log::DiagnosticsLog;
use parking_lot::Mutex;
use std::process::Command;
use std::sync::OnceLock;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
#[cfg(windows)]
const BACKUP_KEY: &str = r"HKCU\Software\Aether\ProxyBackup";

/// Destinations that must never go through the proxy (loopback & LAN).
const BYPASS: &str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";

#[cfg(not(windows))]
const LINUX_IGNORE_HOSTS: &str =
    "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']";

#[cfg(windows)]
#[derive(Clone, Debug)]
struct SavedProxy {
    server: Option<String>,
    override_list: Option<String>,
    enable: Option<String>,
    auto_config: Option<String>,
}

#[cfg(not(windows))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SavedLinuxProxy {
    mode: String,
    http_host: String,
    http_port: String,
    https_host: String,
    https_port: String,
    socks_host: String,
    socks_port: String,
    ignore_hosts: String,
}

#[cfg(windows)]
fn saved_proxy() -> &'static Mutex<Option<SavedProxy>> {
    static CELL: OnceLock<Mutex<Option<SavedProxy>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

#[cfg(not(windows))]
fn saved_linux_proxy() -> &'static Mutex<Option<SavedLinuxProxy>> {
    static CELL: OnceLock<Mutex<Option<SavedLinuxProxy>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
pub fn enable(http_port: u16, socks_port: u16) -> bool {
    let mut saved = saved_proxy().lock();
    if saved.is_none() {
        *saved = Some(SavedProxy {
            server: reg_read("ProxyServer"),
            override_list: reg_read("ProxyOverride"),
            enable: reg_read("ProxyEnable"),
            auto_config: reg_read("AutoConfigURL"),
        });
    }
    if let Some(previous) = saved.as_ref() {
        let _ = reg(&["add", BACKUP_KEY, "/f"]);
        backup_write("ProxyServer", previous.server.as_deref());
        backup_write("ProxyOverride", previous.override_list.as_deref());
        backup_write("ProxyEnable", previous.enable.as_deref());
        backup_write("AutoConfigURL", previous.auto_config.as_deref());
        backup_write("AetherActive", Some("REG_DWORD\t1"));
    }
    drop(saved);
    let server = proxy_string(http_port, socks_port);
    let ok = reg(&[
        "add",
        KEY,
        "/v",
        "ProxyServer",
        "/t",
        "REG_SZ",
        "/d",
        &server,
        "/f",
    ]) && reg(&[
        "add",
        KEY,
        "/v",
        "ProxyOverride",
        "/t",
        "REG_SZ",
        "/d",
        BYPASS,
        "/f",
    ]) && reg(&[
        "add",
        KEY,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ]);
    if !ok {
        let _ = disable();
        return false;
    }
    broadcast_change();
    DiagnosticsLog::i(
        "sysproxy",
        &format!("System proxy enabled -> {server} (bypass: {BYPASS})"),
    );
    true
}

#[cfg(not(windows))]
pub fn enable(http_port: u16, socks_port: u16) -> bool {
    let mut saved = saved_linux_proxy().lock();
    if saved.is_none() {
        if let Some(snap) = snapshot_gsettings() {
            let _ = write_linux_backup(&snap);
            *saved = Some(snap);
        }
    }
    drop(saved);

    let http_p = http_port.to_string();
    let socks_p = socks_port.to_string();
    let ok = gset("org.gnome.system.proxy.http", "host", "'127.0.0.1'")
        && gset("org.gnome.system.proxy.http", "port", &http_p)
        && gset("org.gnome.system.proxy.https", "host", "'127.0.0.1'")
        && gset("org.gnome.system.proxy.https", "port", &http_p)
        && gset("org.gnome.system.proxy.socks", "host", "'127.0.0.1'")
        && gset("org.gnome.system.proxy.socks", "port", &socks_p)
        && gset("org.gnome.system.proxy", "ignore-hosts", LINUX_IGNORE_HOSTS)
        && gset("org.gnome.system.proxy", "mode", "'manual'");

    if !ok {
        let _ = disable();
        DiagnosticsLog::w(
            "sysproxy",
            "Could not configure GNOME system proxy via gsettings (headless or non-GNOME session).",
        );
        return false;
    }
    DiagnosticsLog::i(
        "sysproxy",
        &format!(
            "Linux GNOME system proxy enabled -> http/https 127.0.0.1:{http_port}, socks 127.0.0.1:{socks_port}"
        ),
    );
    true
}

#[cfg(windows)]
pub fn recover_stale() -> bool {
    let has_backup = load_persistent_backup().is_some();
    let points_to_aether = reg_read("ProxyServer")
        .map(|v| v.contains("127.0.0.1:10811"))
        .unwrap_or(false);
    if has_backup || points_to_aether {
        disable()
    } else {
        true
    }
}

#[cfg(not(windows))]
pub fn recover_stale() -> bool {
    let has_backup = read_linux_backup().is_some();
    let points_to_aether = gget("org.gnome.system.proxy", "mode")
        .map(|m| m.contains("manual"))
        .unwrap_or(false)
        && gget("org.gnome.system.proxy.http", "host")
            .map(|h| h.contains("127.0.0.1"))
            .unwrap_or(false)
        && gget("org.gnome.system.proxy.http", "port")
            .map(|p| p.trim() == "10811")
            .unwrap_or(false);
    if has_backup || points_to_aether {
        disable()
    } else {
        true
    }
}

#[cfg(windows)]
pub fn disable() -> bool {
    let snapshot = saved_proxy().lock().take().or_else(load_persistent_backup);
    let had_snapshot = snapshot.is_some();
    let ok = match snapshot {
        Some(previous) => {
            restore_value("ProxyServer", previous.server)
                && restore_value("ProxyOverride", previous.override_list)
                && restore_value("ProxyEnable", previous.enable)
                && restore_value("AutoConfigURL", previous.auto_config)
        }
        None => {
            let stale = reg_read("ProxyServer")
                .map(|v| v.contains("127.0.0.1:10811"))
                .unwrap_or(false);
            if stale {
                reg(&[
                    "add",
                    KEY,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ]) && reg_delete("ProxyServer")
                    && reg_delete("ProxyOverride")
            } else {
                true
            }
        }
    };
    if ok && had_snapshot {
        let _ = reg(&["delete", BACKUP_KEY, "/f"]);
    }
    broadcast_change();
    if ok {
        DiagnosticsLog::i(
            "sysproxy",
            "System proxy settings restored to their pre-Aether state.",
        );
    } else {
        DiagnosticsLog::e(
            "sysproxy",
            "Could not fully restore the pre-Aether system proxy settings.",
        );
    }
    ok
}

#[cfg(not(windows))]
pub fn disable() -> bool {
    let snapshot = saved_linux_proxy().lock().take().or_else(read_linux_backup);
    let had_snapshot = snapshot.is_some();
    let ok = match snapshot {
        Some(prev) => {
            gset("org.gnome.system.proxy.http", "host", &prev.http_host)
                && gset("org.gnome.system.proxy.http", "port", &prev.http_port)
                && gset("org.gnome.system.proxy.https", "host", &prev.https_host)
                && gset("org.gnome.system.proxy.https", "port", &prev.https_port)
                && gset("org.gnome.system.proxy.socks", "host", &prev.socks_host)
                && gset("org.gnome.system.proxy.socks", "port", &prev.socks_port)
                && gset("org.gnome.system.proxy", "ignore-hosts", &prev.ignore_hosts)
                && gset("org.gnome.system.proxy", "mode", &prev.mode)
        }
        None => {
            let stale = gget("org.gnome.system.proxy.http", "host")
                .map(|h| h.contains("127.0.0.1"))
                .unwrap_or(false)
                && gget("org.gnome.system.proxy.http", "port")
                    .map(|p| p.trim() == "10811")
                    .unwrap_or(false);
            if stale {
                gset("org.gnome.system.proxy", "mode", "'none'")
            } else {
                true
            }
        }
    };
    if ok && had_snapshot {
        remove_linux_backup();
    }
    if ok {
        DiagnosticsLog::i(
            "sysproxy",
            "Linux system proxy settings restored to their pre-Aether state.",
        );
    }
    ok
}

#[allow(dead_code)]
fn proxy_string(http_port: u16, socks_port: u16) -> String {
    format!("http=127.0.0.1:{http_port};https=127.0.0.1:{http_port};socks=127.0.0.1:{socks_port}")
}

#[cfg(not(windows))]
fn linux_backup_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))?;
    Some(base.join("studio.cluvex.aether.desktop").join("proxy-backup.json"))
}

#[cfg(not(windows))]
fn write_linux_backup(snap: &SavedLinuxProxy) -> std::io::Result<()> {
    let Some(path) = linux_backup_path() else {
        return Ok(());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec(snap).unwrap_or_default();
    std::fs::write(path, json)
}

#[cfg(not(windows))]
fn read_linux_backup() -> Option<SavedLinuxProxy> {
    let path = linux_backup_path()?;
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(not(windows))]
fn remove_linux_backup() {
    if let Some(path) = linux_backup_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(not(windows))]
fn snapshot_gsettings() -> Option<SavedLinuxProxy> {
    Some(SavedLinuxProxy {
        mode: gget("org.gnome.system.proxy", "mode")?,
        http_host: gget("org.gnome.system.proxy.http", "host")?,
        http_port: gget("org.gnome.system.proxy.http", "port")?,
        https_host: gget("org.gnome.system.proxy.https", "host")?,
        https_port: gget("org.gnome.system.proxy.https", "port")?,
        socks_host: gget("org.gnome.system.proxy.socks", "host")?,
        socks_port: gget("org.gnome.system.proxy.socks", "port")?,
        ignore_hosts: gget("org.gnome.system.proxy", "ignore-hosts")?,
    })
}

#[cfg(not(windows))]
fn gget(schema: &str, key: &str) -> Option<String> {
    let out = Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(not(windows))]
fn gset(schema: &str, key: &str, value: &str) -> bool {
    Command::new("gsettings")
        .args(["set", schema, key, value])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn backup_write(name: &str, value: Option<&str>) {
    if let Some(value) = value {
        let _ = reg(&[
            "add", BACKUP_KEY, "/v", name, "/t", "REG_SZ", "/d", value, "/f",
        ]);
    }
}

#[cfg(windows)]
fn load_persistent_backup() -> Option<SavedProxy> {
    if reg_read_backup("AetherActive").is_none() {
        return None;
    }
    Some(SavedProxy {
        server: reg_read_backup("ProxyServer"),
        override_list: reg_read_backup("ProxyOverride"),
        enable: reg_read_backup("ProxyEnable"),
        auto_config: reg_read_backup("AutoConfigURL"),
    })
}

#[cfg(windows)]
fn reg_read_backup(name: &str) -> Option<String> {
    let output = reg_output(&["query", BACKUP_KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut p = t[name.len()..].split_whitespace();
        let kind = p.next()?;
        Some(format!("{}\t{}", kind, p.collect::<Vec<_>>().join(" ")))
    })
}

#[cfg(windows)]
fn reg_read(name: &str) -> Option<String> {
    let output = reg_output(&["query", KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut parts = t[name.len()..].split_whitespace();
        let kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        Some(format!("{kind}\t{value}"))
    })
}

#[cfg(windows)]
fn restore_value(name: &str, encoded: Option<String>) -> bool {
    match encoded {
        Some(raw) => {
            let mut parts = raw.splitn(2, '\t');
            let kind = parts.next().unwrap_or("REG_SZ");
            let value = parts.next().unwrap_or("");
            reg(&["add", KEY, "/v", name, "/t", kind, "/d", value, "/f"])
        }
        None => reg(&["delete", KEY, "/v", name, "/f"]) || reg_missing_ok(),
    }
}

#[cfg(windows)]
fn reg_missing_ok() -> bool {
    true
}

#[cfg(windows)]
fn reg_delete(name: &str) -> bool {
    reg(&["delete", KEY, "/v", name, "/f"]) || reg_missing_ok()
}

#[cfg(windows)]
fn reg_output(args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(windows)]
fn reg(args: &[&str]) -> bool {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(windows)]
fn broadcast_change() {
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hinternet: *mut core::ffi::c_void,
            dwoption: u32,
            lpbuffer: *mut core::ffi::c_void,
            dwbufferlength: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_string_covers_http_https_and_socks() {
        let s = proxy_string(10811, 10810);
        assert!(s.contains("http=127.0.0.1:10811"));
        assert!(s.contains("https=127.0.0.1:10811"));
        assert!(s.contains("socks=127.0.0.1:10810"));
    }

    #[test]
    fn bypass_keeps_loopback_and_lan_direct() {
        for needle in ["localhost", "127.*", "<local>"] {
            assert!(BYPASS.contains(needle));
        }
    }
}
