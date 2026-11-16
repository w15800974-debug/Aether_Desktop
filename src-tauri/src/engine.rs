//! پورت ۱:۱ از `core/AetherProcess.kt`.

use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, CoreCaps};
use anyhow::{anyhow, Result};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const LOCAL_SOCKS_PORT: u16 = 1819;
pub const CHAIN_SOCKS_PORT: u16 = 1825;
pub const TOR_SOCKS_PORT: u16 = 1820;
pub const SHARE_SOCKS_PORT: u16 = 10810;
pub const SHARE_HTTP_PORT: u16 = 10811;

const GRACEFUL_EXIT_MS: u64 = 250;

pub const FIXED_PORTS: [u16; 3] = [LOCAL_SOCKS_PORT, TOR_SOCKS_PORT, CHAIN_SOCKS_PORT];

static EXIT_SOCKS_PORT: AtomicU16 = AtomicU16::new(LOCAL_SOCKS_PORT);
static PSIPHON_READY: AtomicBool = AtomicBool::new(false);

pub fn psiphon_ready() -> bool {
    PSIPHON_READY.load(Ordering::SeqCst)
}

static PSIPHON_ACCESS_HINT: AtomicBool = AtomicBool::new(false);

pub fn reset_psiphon_access_hint() {
    PSIPHON_ACCESS_HINT.store(false, Ordering::SeqCst);
}

fn ingest_access_denied(line: &str) {
    if !line.contains("forbidden by its access permissions") || !line.contains("psiphon") {
        return;
    }
    if PSIPHON_ACCESS_HINT.swap(true, Ordering::SeqCst) {
        return;
    }
    DiagnosticsLog::w(
        "engine",
        if cfg!(windows) {
            "Windows refused a socket of psiphon-tunnel-core.exe (WSAEACCES 10013): a local firewall rule blocks it, not the censor. Checking for leftover Aether rules…"
        } else {
            "OS refused a socket of psiphon-tunnel-core: a local firewall rule blocks it, not the censor. Checking for leftover Aether rules…"
        },
    );
    std::thread::Builder::new()
        .name("aether-wsaeacces".into())
        .spawn(crate::leakguard::diagnose_access_denied)
        .ok();
}

fn ingest_psiphon_ready(line: &str) {
    if line.contains("[+] psiphon is ready") {
        PSIPHON_READY.store(true, Ordering::SeqCst);
    }
}

pub fn exit_socks_port() -> u16 {
    EXIT_SOCKS_PORT.load(Ordering::Relaxed)
}

pub fn set_exit_socks_port(port: u16) {
    let previous = EXIT_SOCKS_PORT.swap(port, Ordering::Relaxed);
    if previous != port {
        crate::ping::reset();
        DiagnosticsLog::i(
            "engine",
            &format!("Pipeline exit SOCKS5 port: {previous} -> {port}"),
        );
    }
}

pub fn reset_exit_socks_port() {
    set_exit_socks_port(LOCAL_SOCKS_PORT);
}

fn engine_core_version(exe: &Path) -> (u32, u32) {
    let Some(dir) = exe.parent() else {
        return (0, 0);
    };
    let Ok(raw) = std::fs::read_to_string(dir.join("CORE_VERSION")) else {
        return (0, 0);
    };
    let mut parts = raw.trim().trim_start_matches('v').split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

pub fn core_version_label(exe: &Path) -> String {
    exe.parent()
        .and_then(|dir| std::fs::read_to_string(dir.join("CORE_VERSION")).ok())
        .map(|raw| raw.trim().trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn engine_supports_log_level(exe: &Path) -> bool {
    engine_core_version(exe) >= (1, 4)
}

pub fn engine_caps(exe: &Path) -> CoreCaps {
    let (major, minor) = engine_core_version(exe);
    CoreCaps::for_version(major, minor)
}

fn detected_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn forced_perf_tier(cpus: usize) -> Option<&'static str> {
    if cpus >= 8 {
        Some("high")
    } else {
        None
    }
}

const TAG: &str = "engine";

#[cfg(windows)]
pub const ENGINE_EXE: &str = "aether.exe";
#[cfg(not(windows))]
pub const ENGINE_EXE: &str = "aether";

#[cfg(windows)]
pub const PSIPHON_BIN: &str = "psiphon-tunnel-core.exe";
#[cfg(not(windows))]
pub const PSIPHON_BIN: &str = "psiphon-tunnel-core";

/// Resolves the directory containing `engine/`.
/// On Windows this is next to the executable; on Linux `.deb` / AppImage it may
/// be `/usr/lib/Aether`, `<exe>/../lib/Aether`, or `<exe_dir>`.
pub fn resolve_install_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?.to_path_buf();
    let mut candidates = vec![exe_dir.clone()];
    #[cfg(not(windows))]
    {
        candidates.push(PathBuf::from("/usr/lib/Aether"));
        candidates.push(PathBuf::from("/usr/lib/aether-desktop"));
        if let Some(parent) = exe_dir.parent() {
            candidates.push(parent.join("lib").join("Aether"));
            candidates.push(parent.join("share").join("aether-desktop"));
        }
    }
    candidates
        .into_iter()
        .find(|d| d.join("engine").join(ENGINE_EXE).is_file() || d.join("engine").is_dir())
        .or(Some(exe_dir))
}

pub struct AetherProcess {
    exe: PathBuf,
    working_dir: PathBuf,
    bundled_dir: PathBuf,
    child: Option<Child>,
    caps: CoreCaps,
    uses_tor: bool,
    upstream_socks: Option<u16>,
    custom_tcp_upstream: bool,
    probe_port: Option<u16>,
    chain_trace: Option<String>,
    tree: Option<crate::procguard::KillTree>,
    psiphon_only: bool,
}

impl AetherProcess {
    pub fn new(install_dir: &Path, working_dir: &Path) -> Self {
        let bundled_dir = install_dir.join("engine");
        let exe = match prepare_runtime_engine(&bundled_dir, working_dir) {
            Ok(exe) => exe,
            Err(e) => {
                DiagnosticsLog::w(
                    "engine",
                    &format!("Could not stage the engine in a writable folder ({e}); running it from the install folder."),
                );
                bundled_dir.join(ENGINE_EXE)
            }
        };
        Self {
            caps: engine_caps(&exe),
            exe,
            working_dir: working_dir.to_path_buf(),
            bundled_dir,
            child: None,
            uses_tor: false,
            upstream_socks: None,
            custom_tcp_upstream: false,
            probe_port: None,
            chain_trace: None,
            tree: None,
            psiphon_only: false,
        }
    }

    pub fn set_chain_trace(&mut self, id: Option<String>) {
        self.chain_trace = id;
    }
    pub fn owns_probe_listener(&self, port: u16) -> bool {
        self.child
            .as_ref()
            .map(|c| crate::procguard::listener_pid(port) == Some(c.id()))
            .unwrap_or(false)
    }
    pub fn probe_bind_port(&self) -> Option<u16> {
        self.probe_port
    }
    pub fn fork_probe(&self, port: u16) -> Self {
        Self {
            exe: self.exe.clone(),
            working_dir: self.working_dir.clone(),
            bundled_dir: self.bundled_dir.clone(),
            caps: self.caps,
            child: None,
            uses_tor: false,
            upstream_socks: None,
            custom_tcp_upstream: false,
            probe_port: Some(port),
            chain_trace: None,
            tree: None,
            psiphon_only: false,
        }
    }
    pub fn psiphon_assets(&self) -> Result<(PathBuf, PathBuf)> {
        if engine_core_version(&self.exe) < (2, 1) {
            return Err(anyhow!("Psiphon chains require Aether Core 2.1.0 or newer"));
        }
        let install = self.working_dir.join("engine");
        let candidates = [
            self.exe.parent().unwrap_or(install.as_path()),
            install.as_path(),
            self.bundled_dir.as_path(),
        ];
        let find = |name: &str| -> Result<PathBuf> {
            candidates
                .iter()
                .map(|d| d.join(name))
                .find(|p| p.is_file())
                .ok_or_else(|| anyhow!("Bundled Psiphon asset missing: {name}"))
        };
        Ok((find(PSIPHON_BIN)?, find("server_entries.txt")?))
    }

    pub fn caps(&self) -> CoreCaps {
        self.caps
    }

    pub fn set_upstream_socks(&mut self, port: Option<u16>) {
        self.upstream_socks = port;
    }

    pub fn set_psiphon_only(&mut self, on: bool) {
        self.psiphon_only = on;
    }

    fn psiphon_only_run(&self, profile: &ConnectionProfile) -> bool {
        profile.backend == crate::profile::TransportBackend::TorPsiphon
            && (self.upstream_socks.is_some() || self.psiphon_only)
    }

    pub fn was_started(&self) -> bool {
        self.child.is_some()
    }

    pub fn core_version(&self) -> String {
        core_version_label(&self.exe)
    }

    pub fn transport_installed(&self) -> bool {
        crate::pt::installed(&self.working_dir)
    }

    pub fn set_custom_tcp_upstream(&mut self, enabled: bool) {
        self.custom_tcp_upstream = enabled;
    }
    fn upstream_env(&self) -> Vec<(String, String)> {
        match self.upstream_socks {
            None => Vec::new(),
            Some(port) => vec![
                (
                    "AETHER_UPSTREAM".to_string(),
                    format!("socks5://127.0.0.1:{port}"),
                ),
                ("AETHER_MASQUE_HTTP2".to_string(), "1".to_string()),
                (
                    "AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS".to_string(),
                    "60".to_string(),
                ),
            ],
        }
    }

    pub fn run_dir(&self) -> PathBuf {
        self.exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.working_dir.clone())
    }

    pub fn forget_cached_gateways(&self) {
        let mut dirs = vec![self.run_dir()];
        if !dirs.contains(&self.working_dir) {
            dirs.push(self.working_dir.clone());
        }
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_gateway_cache_file(&name) && std::fs::remove_file(entry.path()).is_ok() {
                    DiagnosticsLog::i(
                        "engine",
                        &format!("Forgot the cached gateway {name}: the attempt that used it failed its self-test, so the next attempt scans afresh."),
                    );
                }
            }
        }
    }

    pub fn start(
        &mut self,
        profile: &ConnectionProfile,
        rung_budget_ms: Option<u64>,
    ) -> Result<()> {
        if !self.exe.exists() {
            return Err(anyhow!("Engine binary missing: {}", self.exe.display()));
        }
        if let Some(ms) = rung_budget_ms {
            DiagnosticsLog::i(
                "engine",
                &format!("Rung budget {}s (scan sized by --scan).", ms / 1000),
            );
        }

        let caps = self.caps;
        let mut engine_profile = profile.clone();
        engine_profile.route_direct.clear();
        if self.probe_port.is_some() {
            engine_profile.bypass_iran = false;
            engine_profile.block_ads = false;
            engine_profile.lan_share = false;
            engine_profile.route_block.clear();
        }
        let mut args = engine_profile.to_args_with_caps(caps);
        if let Some(port) = self.probe_port {
            args.extend(["--bind".into(), format!("127.0.0.1:{port}")]);
        }
        if self.psiphon_only_run(profile) {
            args.retain(|arg| arg != "--tor-only" && arg != "--psiphon");
            if let Some(at) = args.iter().position(|arg| arg == "--psiphon-bind") {
                args.drain(at..at + 2);
            }
            args.insert(0, "--psiphon-only".into());
        }
        if engine_supports_log_level(&self.exe) {
            args.insert(0, "--log-level".into());
            args.insert(1, "info".into());
            if let Some(tier) = forced_perf_tier(detected_cpus()) {
                args.insert(2, "--perf".into());
                args.insert(3, tier.into());
            }
        }
        let run_dir = self
            .exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.working_dir.clone());
        let tor_dirs = if caps.tor
            && profile.backend.uses_tor()
            && !self.psiphon_only_run(profile)
        {
            tor_runtime_dirs(&self.working_dir)
        } else {
            Vec::new()
        };
        self.uses_tor = !tor_dirs.is_empty();

        let mut smart_env: Vec<(String, String)> = Vec::new();
        if self.custom_tcp_upstream
            && profile.protocol == crate::profile::Protocol::Masque
            && profile.masque_http2
        {
            smart_env.push(("AETHER_CUSTOM_TCP_UPSTREAM".into(), "1".into()));
        }
        if caps.routing {
            if let Some(path) = crate::smart_lists::engine_routes_file(&self.working_dir, profile) {
                smart_env.push(("AETHER_ROUTES_FILE".into(), path.display().to_string()));
            }
        }
        if caps.zero_trust
            && profile.uses_zero_trust()
            && profile.access_mode == crate::profile::AccessMode::Email
        {
            let record = crate::zt_signin::load_record(&self.working_dir);
            let dirs: Vec<&Path> = [Some(run_dir.as_path()), Some(self.working_dir.as_path())]
                .into_iter()
                .flatten()
                .collect();
            match crate::zt_signin::decide(
                record.as_ref(),
                &profile.team,
                &profile.access_email,
                |t| crate::zt_signin::is_enrolled(&dirs, t),
                crate::zt_signin::now_secs(),
            ) {
                crate::zt_signin::Decision::Use(token) => {
                    DiagnosticsLog::i(
                        "zerotrust",
                        "Handing the pre-connect sign-in to the engine.",
                    );
                    smart_env.push(("AETHER_ACCESS_TOKEN".into(), token));
                }
                crate::zt_signin::Decision::AlreadyEnrolled
                | crate::zt_signin::Decision::Unusable => {
                    crate::zt_signin::save_record(&self.working_dir, None);
                }
                _ => {}
            }
        }

        if profile.is_chained() {
            let (binary, servers) = self.psiphon_assets()?;
            args.push("--psiphon-bin".into());
            args.push(binary.display().to_string());
            smart_env.push((
                "AETHER_PSIPHON_SERVER_ENTRIES".into(),
                servers.display().to_string(),
            ));
            smart_env.push((
                "AETHER_PSIPHON_DIR".into(),
                self.working_dir.join("psiphon").display().to_string(),
            ));
        }
        let mut cmd = Command::new(&self.exe);
        cmd.env_remove("AETHER_CUSTOM_TCP_UPSTREAM");
        cmd.env_remove("AETHER_CHAIN_TRACE");
        if let Some(id) = &self.chain_trace {
            cmd.env("AETHER_CHAIN_TRACE", id);
        }
        cmd.args(&args)
            .envs(smart_env)
            .envs(tor_dirs.clone())
            .current_dir(&run_dir)
            .envs(if self.psiphon_only_run(profile) {
                let mut env = profile.to_env_with_caps(caps);
                env.retain(|key, _| !key.starts_with("AETHER_TOR"));
                env
            } else {
                profile.to_env_with_caps(caps)
            })
            .envs(self.upstream_env())
            .env("HOME", &run_dir)
            .env("TMPDIR", &run_dir)
            .env("RUST_BACKTRACE", "full")
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

        if self.probe_port.is_none() {
            PSIPHON_READY.store(false, Ordering::SeqCst);
        }
        let mut child = cmd.spawn()?;
        self.tree = Some(crate::procguard::KillTree::adopt(&child, ENGINE_EXE));

        let stdin_sink: Option<Box<dyn std::io::Write + Send>> = child
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Write + Send>);
        let generation = if self.probe_port.is_none() {
            Some(crate::login_code::attach(stdin_sink))
        } else {
            None
        };

        DiagnosticsLog::i(
            "engine",
            &format!("Spawned {ENGINE_EXE} {}", redact_args(&args).join(" ")),
        );
        for (key, value) in &tor_dirs {
            DiagnosticsLog::i("engine", &format!("{key}={value}"));
        }

        if self.probe_port.is_none() {
            crate::tor_bootstrap::reset();
        }

        if let Some(out) = child.stdout.take() {
            if self.probe_port.is_some() {
                spawn_probe_drain(out);
            } else {
                spawn_drain(out, generation);
            }
        }
        if let Some(err) = child.stderr.take() {
            if self.probe_port.is_some() {
                spawn_probe_drain(err);
            } else {
                spawn_drain(err, None);
            }
        }

        self.child = Some(child);
        Ok(())
    }

    pub fn native_tor(&self) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let support = self.working_dir.join("engine").join("tor");
        let binary = support.join(crate::tor_native::TOR_FILENAME);
        if binary.is_file() {
            Some((binary, support))
        } else {
            None
        }
    }

    pub fn native_tor_home(&self) -> std::path::PathBuf {
        self.working_dir.join("tor-native")
    }

    pub fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => match c.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    DiagnosticsLog::w(
                        "ChainTrace",
                        &format!("engine pid={} exited status={status}", c.id()),
                    );
                    false
                }
                Err(e) => {
                    DiagnosticsLog::w("ChainTrace", &format!("engine wait failed: {e}"));
                    false
                }
            },
            None => false,
        }
    }

    pub fn await_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.as_mut().map(|c| c.try_wait()) {
                None | Some(Ok(Some(_))) => return true,
                Some(Ok(None)) => std::thread::sleep(Duration::from_millis(20)),
                Some(Err(_)) => return false,
            }
        }
        false
    }

    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            self.tree = None;
            return;
        };
        self.uses_tor = false;

        if let Some(tree) = self.tree.as_ref() {
            tree.terminate();
        }
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_millis(GRACEFUL_EXIT_MS);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.wait();
        self.tree = None;
        DiagnosticsLog::w("engine", "Engine stopped and reaped.");
    }
}

impl Drop for AetherProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn prepare_runtime_engine(bundled_dir: &Path, working_dir: &Path) -> Result<PathBuf> {
    let runtime_dir = working_dir.join("engine");
    if runtime_dir == *bundled_dir {
        let exe = runtime_dir.join(ENGINE_EXE);
        return if exe.exists() {
            Ok(exe)
        } else {
            Err(anyhow!("Engine binary missing: {}", exe.display()))
        };
    }
    std::fs::create_dir_all(&runtime_dir)?;
    for entry in std::fs::read_dir(bundled_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let src = entry.path();
        let dst = runtime_dir.join(entry.file_name());
        if !runtime_copy_is_fresh(&src, &dst) {
            std::fs::copy(&src, &dst).map(|n| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                }
                n
            })?;
        }
    }
    let tor_src = bundled_dir.join("tor");
    if tor_src.is_dir() {
        let tor_dst = runtime_dir.join("tor");
        std::fs::create_dir_all(&tor_dst)?;
        for entry in std::fs::read_dir(&tor_src)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let dst = tor_dst.join(entry.file_name());
                if std::fs::copy(entry.path(), &dst).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                    }
                }
            }
        }
    }

    let pt_src = bundled_dir.join("pt");
    if pt_src.is_dir() {
        let pt_dst = runtime_dir.join("pt");
        if let Err(e) = std::fs::create_dir_all(&pt_dst) {
            DiagnosticsLog::w(
                "engine",
                &format!(
                    "Could not create the transport directory ({e}); Tor bridges will have \
                     no transport to run."
                ),
            );
        } else if let Ok(entries) = std::fs::read_dir(&pt_src) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|k| k.is_file()).unwrap_or(false) {
                    continue;
                }
                let src = entry.path();
                let dst = pt_dst.join(entry.file_name());
                if !runtime_copy_is_fresh(&src, &dst) {
                    if let Err(e) = std::fs::copy(&src, &dst).map(|n| {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                        }
                        n
                    }) {
                        DiagnosticsLog::w(
                            "engine",
                            &format!(
                                "Could not install {}: {e}",
                                entry.file_name().to_string_lossy()
                            ),
                        );
                    }
                }
            }
        }
    }

    let xray_src = bundled_dir.join("xray");
    if xray_src.is_dir() {
        let xray_dst = runtime_dir.join("xray");
        let _ = std::fs::create_dir_all(&xray_dst);
        if let Ok(entries) = std::fs::read_dir(&xray_src) {
            for entry in entries.flatten() {
                if entry.file_type().map(|k| k.is_file()).unwrap_or(false) {
                    let src = entry.path();
                    let dst = xray_dst.join(entry.file_name());
                    if !runtime_copy_is_fresh(&src, &dst) {
                        let _ = std::fs::copy(&src, &dst).map(|n| {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
                            }
                            n
                        });
                    }
                }
            }
        }
    }

    for name in ["aether.toml", "aether-secondary.toml"] {
        let src = working_dir.join(name);
        let dst = runtime_dir.join(name);
        if src.is_file() && !dst.exists() {
            let _ = std::fs::copy(&src, &dst);
        }
    }
    let exe = runtime_dir.join(ENGINE_EXE);
    if !exe.exists() {
        return Err(anyhow!(
            "Engine binary missing: {}",
            bundled_dir.join(ENGINE_EXE).display()
        ));
    }
    Ok(exe)
}

fn runtime_copy_is_fresh(src: &Path, dst: &Path) -> bool {
    let (Ok(a), Ok(b)) = (std::fs::metadata(src), std::fs::metadata(dst)) else {
        return false;
    };
    if a.len() != b.len() {
        return false;
    }
    match (std::fs::read(src), std::fs::read(dst)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn redact_args(args: &[String]) -> Vec<String> {
    const SENSITIVE: [&str; 6] = [
        "--tor-bridge",
        "--access-id",
        "--access-secret",
        "--access-token",
        "--access-email",
        "--upstream",
    ];
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for a in args {
        if mask_next {
            out.push("••••••".to_string());
            mask_next = false;
            continue;
        }
        if SENSITIVE.contains(&a.as_str()) {
            mask_next = true;
        }
        out.push(a.clone());
    }
    out
}

fn tor_runtime_dirs(working_dir: &Path) -> Vec<(String, String)> {
    let mut env = Vec::new();

    let dir = working_dir.join("tor");
    match std::fs::create_dir_all(&dir) {
        Ok(()) => env.push(("AETHER_TOR_DIR".into(), dir.to_string_lossy().into_owned())),
        Err(e) => DiagnosticsLog::w(
            "engine",
            &format!(
                "Could not create the Tor cache directory ({e}); Tor will bootstrap from \
                 scratch on every connect."
            ),
        ),
    }

    let mut pt_dirs: Vec<String> = Vec::new();
    for dir in crate::pt::dirs(working_dir) {
        if dir.is_dir() {
            pt_dirs.push(dir.to_string_lossy().into_owned());
        }
    }
    if !crate::pt::installed(working_dir) {
        DiagnosticsLog::w(
            "engine",
            "No pluggable transport installed: Tor can still connect directly and through \
             the tunnel, but bridges have no transport to run.",
        );
    } else {
        env.push(("AETHER_TOR_PT_DIR".into(), pt_dirs.join(";")));
    }

    env
}

fn spawn_drain<R: std::io::Read + Send + 'static>(reader: R, prompt_generation: Option<u64>) {
    std::thread::Builder::new()
        .name("aether-log".into())
        .spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                DiagnosticsLog::d("engine", &line);
                crate::tor_bootstrap::ingest(&line);
                crate::firsthop::ingest(&line);
                crate::provenance::ingest(&line);
                crate::tor_native::ingest_engine_line(&line);
                ingest_psiphon_ready(&line);
                ingest_access_denied(&line);
                if prompt_generation.is_some() {
                    crate::login_code::ingest(&line);
                }
            }
            if let Some(generation) = prompt_generation {
                crate::login_code::detach(generation);
            }
            DiagnosticsLog::w("engine", "Engine output stream closed.");
        })
        .ok();
}

pub fn wait_for_port_release(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(test)]
mod perf_tier_tests {
    use super::forced_perf_tier;

    #[test]
    fn a_four_core_machine_is_left_to_the_engines_own_judgement() {
        assert_eq!(forced_perf_tier(4), None);
        assert_eq!(forced_perf_tier(2), None);
        assert_eq!(forced_perf_tier(6), None);
    }

    #[test]
    fn a_big_machine_still_gets_the_high_tier() {
        assert_eq!(forced_perf_tier(8), Some("high"));
        assert_eq!(forced_perf_tier(16), Some("high"));
    }
}

fn is_gateway_cache_file(name: &str) -> bool {
    name.starts_with("aether") && name.ends_with("-lastconn.toml")
}

#[cfg(test)]
mod gateway_cache_tests {
    use super::is_gateway_cache_file;

    #[test]
    fn only_the_cores_lastconn_files_are_forgotten() {
        assert!(is_gateway_cache_file("aether-lastconn.toml"));
        assert!(is_gateway_cache_file("aether-masque-lastconn.toml"));
        assert!(is_gateway_cache_file("aether-team-acme-lastconn.toml"));
        assert!(!is_gateway_cache_file("aether.toml"));
        assert!(!is_gateway_cache_file("aether-masque.toml"));
        assert!(!is_gateway_cache_file("aether-team-acme.toml"));
    }

    #[test]
    fn the_psiphon_ready_line_is_recognised() {
        super::PSIPHON_READY.store(false, std::sync::atomic::Ordering::SeqCst);
        super::ingest_psiphon_ready("[2026-10-08T12:39:52Z INFO  aether::psiphon] [*] psiphon dials out through the upstream proxy");
        assert!(!super::psiphon_ready());
        super::ingest_psiphon_ready("[2026-10-08T12:39:53.969Z INFO  aether::psiphon] [+] psiphon is ready; 127.0.0.1:1819 leaves through psiphon");
        assert!(super::psiphon_ready());
    }
}

fn spawn_probe_drain<R: std::io::Read + Send + 'static>(reader: R) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            DiagnosticsLog::d("smart+-engine", &crate::custom::process::redact(&line));
        }
    });
}
