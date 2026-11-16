//! پورت از `transport/PsiphonTransport.kt` — استیج ۲ زنجیرهٔ `Aether → Psiphon`.

use crate::engine;
use crate::exit_regions;
use crate::log::DiagnosticsLog;
use crate::probe;
use crate::psiphon_health::{self, Rotation, Target};
use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const TAG: &str = "psiphon";

pub const CONFIG_FAULT_PREFIX: &str = "Psiphon rejected its own launch settings — ";

pub fn is_config_fault(message: &str) -> bool {
    message.contains(CONFIG_FAULT_PREFIX)
}

#[cfg(windows)]
pub const PSIPHON_EXE: &str = "psiphon-tunnel-core.exe";
#[cfg(not(windows))]
pub const PSIPHON_EXE: &str = "psiphon-tunnel-core";
pub const SERVER_LIST_FILE: &str = "server_entries.txt";
const DATA_DIR_NAME: &str = "psiphon";
const CONFIG_FILE: &str = "psiphon.config";

const ESTABLISH_TIMEOUT_SECONDS: u64 = 180;
const ESTABLISH_TIMEOUT_MS: u64 = 200_000;
const PORT_RELEASE_WAIT_MS: u64 = 3_000;
const ROTATION_GRACE_MS: u64 = 90_000;

const REMOTE_SERVER_LIST_PUBLIC_KEY: &str = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=";
const SERVER_ENTRY_SIGNATURE_PUBLIC_KEY: &str = "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=";
const EXCHANGE_OBFUSCATION_KEY: &str = "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=";

fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

struct Shared {
    socks_port: AtomicU16,
    connected: AtomicBool,
    exiting: AtomicBool,
    rotation_deadline: AtomicU64,
    available_regions: Mutex<Vec<String>>,
    connected_region: Mutex<String>,
    noise_notices: AtomicU64,
    generation: AtomicU64,
    config_fault: Mutex<String>,
}

impl Shared {
    fn new() -> Self {
        Self {
            socks_port: AtomicU16::new(0),
            connected: AtomicBool::new(false),
            exiting: AtomicBool::new(false),
            rotation_deadline: AtomicU64::new(0),
            available_regions: Mutex::new(Vec::new()),
            connected_region: Mutex::new(String::new()),
            noise_notices: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            config_fault: Mutex::new(String::new()),
        }
    }

    fn rotating(&self) -> bool {
        let until = self.rotation_deadline.load(Ordering::Relaxed);
        if until == 0 {
            return false;
        }
        if now_ms() < until {
            return true;
        }
        self.rotation_deadline.store(0, Ordering::Relaxed);
        DiagnosticsLog::w(
            TAG,
            &format!(
                "Psiphon rotation did not come back within {}s — handing the session back to the supervisor.",
                ROTATION_GRACE_MS / 1000
            ),
        );
        false
    }
}

struct Inner {
    exe: PathBuf,
    server_list: PathBuf,
    data_dir: PathBuf,
    config_path: PathBuf,
    child: Option<Child>,
    region: String,
    upstream: String,
    local_socks_port: u16,
    config: String,
    avoid_replay: bool,
}

pub struct PsiphonTransport {
    inner: Arc<Mutex<Inner>>,
    shared: Arc<Shared>,
}

impl PsiphonTransport {
    pub fn new(install_dir: &Path, working_dir: &Path) -> Self {
        let runtime_dir = working_dir.join("engine");
        let bundled_dir = install_dir.join("engine");
        let pick = |name: &str| -> PathBuf {
            let staged = runtime_dir.join(name);
            if staged.exists() {
                staged
            } else {
                bundled_dir.join(name)
            }
        };
        Self {
            inner: Arc::new(Mutex::new(Inner {
                exe: pick(PSIPHON_EXE),
                server_list: pick(SERVER_LIST_FILE),
                data_dir: working_dir.join(DATA_DIR_NAME),
                config_path: working_dir.join(CONFIG_FILE),
                child: None,
                region: String::new(),
                upstream: String::new(),
                local_socks_port: engine::CHAIN_SOCKS_PORT,
                config: String::new(),
                avoid_replay: false,
            })),
            shared: Arc::new(Shared::new()),
        }
    }

    pub fn is_available(&self) -> bool {
        let g = self.inner.lock();
        g.exe.exists() && g.server_list.exists()
    }

    pub fn missing_parts(&self) -> String {
        let g = self.inner.lock();
        let mut missing = Vec::new();
        if !g.exe.exists() {
            missing.push(PSIPHON_EXE);
        }
        if !g.server_list.exists() {
            missing.push(SERVER_LIST_FILE);
        }
        missing.join(", ")
    }

    pub fn socks_port(&self) -> u16 {
        let p = self.shared.socks_port.load(Ordering::Relaxed);
        if p != 0 {
            p
        } else {
            self.inner.lock().local_socks_port
        }
    }

    pub fn exit_region(&self) -> Option<String> {
        let r = self.shared.connected_region.lock().clone();
        if r.is_empty() {
            None
        } else {
            Some(r)
        }
    }

    pub fn start(&self, region: &str, upstream: &str) -> Result<u16> {
        let wanted = exit_regions::normalize(region);
        {
            let mut g = self.inner.lock();
            g.region = wanted.clone();
            g.upstream = upstream.to_string();
            g.avoid_replay = false;
            g.local_socks_port = engine::CHAIN_SOCKS_PORT;
        }
        *self.shared.available_regions.lock() = Vec::new();
        psiphon_health::reset();

        if !self.is_available() {
            return Err(anyhow!(
                "The Psiphon stage is missing from this installation ({}). Reinstall Aether or switch the transport back to Aether.",
                self.missing_parts()
            ));
        }

        let attempts: Vec<String> = if wanted.is_empty() {
            vec![String::new()]
        } else {
            vec![wanted.clone(), String::new()]
        };
        let mut last_error: Option<String> = None;

        for (index, egress) in attempts.iter().enumerate() {
            if index > 0 {
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "Psiphon could not establish in {} ({}) — retrying with an automatic exit and a fresh datastore.",
                        exit_regions::name(&wanted),
                        last_error.as_deref().unwrap_or("timed out")
                    ),
                );
                self.stop_quietly();
                self.reset_data_store();
                let port = self.inner.lock().local_socks_port;
                engine::wait_for_port_release(port, Duration::from_millis(PORT_RELEASE_WAIT_MS));
            }
            match self.establish(egress) {
                Ok(port) => return Ok(port),
                Err(e) => {
                    let message = e.to_string();
                    self.stop_quietly();
                    if is_config_fault(&message) {
                        DiagnosticsLog::e(TAG, &message);
                        return Err(e);
                    }
                    last_error = Some(message);
                }
            }
        }

        Err(anyhow!(
            "{}",
            last_error.unwrap_or_else(|| "Psiphon did not establish a tunnel".to_string())
        ))
    }

    fn establish(&self, egress: &str) -> Result<u16> {
        let config = self.build_config(egress);
        let (local_port, upstream) = {
            let mut g = self.inner.lock();
            g.config = config.clone();
            (g.local_socks_port, g.upstream.clone())
        };
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Starting Psiphon (exit={}, socks={}, upstream={})",
                exit_regions::name(egress),
                local_port,
                if upstream.is_empty() {
                    "direct".to_string()
                } else {
                    redact_upstream(&upstream)
                },
            ),
        );
        self.bind_health();
        self.spawn_child(&config)?;

        let deadline = Instant::now() + Duration::from_millis(ESTABLISH_TIMEOUT_MS);
        loop {
            if self.shared.connected.load(Ordering::Relaxed) {
                break;
            }
            if self.shared.exiting.load(Ordering::Relaxed) {
                return Err(self.fault_error("Psiphon stopped before it established a tunnel"));
            }
            if !self.child_alive() {
                return Err(
                    self.fault_error("The Psiphon stage exited before it established a tunnel")
                );
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "Psiphon found no usable server within {}s",
                    ESTABLISH_TIMEOUT_MS / 1000
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let bound = self.socks_port();
        if bound != local_port {
            DiagnosticsLog::w(
                TAG,
                &format!("Psiphon bound SOCKS5 on {bound} instead of {local_port} — the pipeline follows it."),
            );
            self.inner.lock().local_socks_port = bound;
        }
        if !probe::socks_ready(bound) {
            return Err(anyhow!(
                "Psiphon reported a tunnel but nothing is listening on 127.0.0.1:{bound}"
            ));
        }
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Psiphon stage ready on 127.0.0.1:{bound} (exit region {})",
                self.exit_region()
                    .unwrap_or_else(|| "automatic".to_string())
            ),
        );
        Ok(bound)
    }

    fn fault_error(&self, fallback: &str) -> anyhow::Error {
        let fault = self.shared.config_fault.lock().clone();
        if fault.is_empty() {
            anyhow!("{}", fallback)
        } else {
            anyhow!("{}{}", CONFIG_FAULT_PREFIX, fault)
        }
    }

    fn build_config(&self, egress: &str) -> String {
        build_config(&self.inner, egress)
    }

    fn spawn_child(&self, config: &str) -> Result<()> {
        spawn_child(&self.inner, &self.shared, config)
    }

    fn bind_health(&self) {
        let inner = self.inner.clone();
        let shared = self.shared.clone();
        psiphon_health::bind(move |strategy, target| {
            rotate(&inner, &shared, strategy, target);
        });
    }

    fn child_alive(&self) -> bool {
        let mut g = self.inner.lock();
        match g.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    pub fn is_alive(&self) -> bool {
        if self.shared.rotating() {
            return true;
        }
        self.shared.connected.load(Ordering::Relaxed) && self.child_alive()
    }

    fn stop_quietly(&self) {
        self.shared.connected.store(false, Ordering::Relaxed);
        self.shared.generation.fetch_add(1, Ordering::SeqCst);
        let child = self.inner.lock().child.take();
        if let Some(mut c) = child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn reset_data_store(&self) {
        let dir = self.inner.lock().data_dir.clone();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        DiagnosticsLog::i(TAG, "Psiphon datastore reset.");
    }

    pub fn stop(&self) {
        self.shared.rotation_deadline.store(0, Ordering::Relaxed);
        psiphon_health::reset();
        self.stop_quietly();
        *self.shared.connected_region.lock() = String::new();
        self.shared.socks_port.store(0, Ordering::Relaxed);
        DiagnosticsLog::w(TAG, "Psiphon stage stopped and reaped.");
    }
}

impl Drop for PsiphonTransport {
    fn drop(&mut self) {
        self.stop_quietly();
    }
}

fn rotate(inner: &Arc<Mutex<Inner>>, shared: &Arc<Shared>, strategy: Rotation, target: Target) {
    shared
        .rotation_deadline
        .store(now_ms() + ROTATION_GRACE_MS, Ordering::Relaxed);

    crate::ping::reset();

    if strategy == Rotation::Restart {
        prepare_steered_config(inner, shared, &target);
    }

    let config = inner.lock().config.clone();
    {
        shared.connected.store(false, Ordering::Relaxed);
        shared.generation.fetch_add(1, Ordering::SeqCst);
        let child = inner.lock().child.take();
        if let Some(mut c) = child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    let port = inner.lock().local_socks_port;
    engine::wait_for_port_release(port, Duration::from_millis(PORT_RELEASE_WAIT_MS));

    match spawn_child(inner, shared, &config) {
        Ok(()) => DiagnosticsLog::i(
            TAG,
            &format!(
                "Psiphon restarted for rotation ({}) — the pipeline stayed up on 127.0.0.1:{port}.",
                strategy_label(strategy)
            ),
        ),
        Err(e) => {
            DiagnosticsLog::e(TAG, &format!("Psiphon server rotation failed: {e}"));
            shared.rotation_deadline.store(0, Ordering::Relaxed);
        }
    }
}

fn strategy_label(s: Rotation) -> &'static str {
    match s {
        Rotation::Reconnect => "same config",
        Rotation::Restart => "steered config",
    }
}

fn prepare_steered_config(inner: &Arc<Mutex<Inner>>, shared: &Arc<Shared>, target: &Target) {
    let user_egress = {
        let mut g = inner.lock();
        g.avoid_replay = true;
        g.region.clone()
    };
    let egress = if !user_egress.is_empty() {
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Psiphon staying in {} because it was chosen by hand — replay and server affinity \
                 are disabled instead so establishment cannot settle on {} again.",
                exit_regions::name(&user_egress),
                if target.server_id.is_empty() {
                    "(unknown)"
                } else {
                    &target.server_id
                }
            ),
        );
        user_egress
    } else {
        next_egress_away(shared, &target.region)
    };
    let config = build_config(inner, &egress);
    inner.lock().config = config;
}

fn next_egress_away(shared: &Arc<Shared>, bad_region: &str) -> String {
    let mut bad = psiphon_health::filtering_regions();
    if !bad_region.is_empty() {
        bad.insert(bad_region.to_ascii_uppercase());
    }
    let available = shared.available_regions.lock().clone();
    let pool: Vec<String> = available.into_iter().filter(|r| !bad.contains(r)).collect();
    if pool.is_empty() {
        DiagnosticsLog::w(
            TAG,
            "Psiphon has no clean exit region left to steer to — restarting with replay and \
             server affinity disabled and no region filter.",
        );
        return String::new();
    }
    static CURSOR: AtomicU64 = AtomicU64::new(0);
    let idx = (CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % pool.len();
    let pick = pool[idx].clone();
    DiagnosticsLog::i(
        TAG,
        &format!(
            "Psiphon steering the exit away from {} to {} — {} filtering, {} clean regions to choose from.",
            exit_regions::name(bad_region),
            exit_regions::name(&pick),
            if bad.len() == 1 {
                "1 region is".to_string()
            } else {
                format!("{} regions are", bad.len())
            },
            pool.len(),
        ),
    );
    pick
}

fn handle_notice(shared: &Arc<Shared>, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    psiphon_health::on_notice(line);

    let kind = psiphon_health::notice_type(line).unwrap_or_default();
    let message = psiphon_health::json_str(line, "message").unwrap_or_default();

    match kind.as_str() {
        "ListeningSocksProxyPort" => {
            if let Some(port) = psiphon_health::json_u64(line, "port") {
                shared.socks_port.store(port as u16, Ordering::Relaxed);
            }
        }
        "Tunnels" => {
            let count = psiphon_health::json_u64(line, "count").unwrap_or(0);
            if count >= 1 {
                shared.connected.store(true, Ordering::Relaxed);
                if shared.rotation_deadline.swap(0, Ordering::Relaxed) != 0 {
                    DiagnosticsLog::i(
                        TAG,
                        "Psiphon rotation complete — session continues on a new server.",
                    );
                }
            } else {
                if !shared.rotating() {
                    shared.connected.store(false, Ordering::Relaxed);
                }
            }
        }
        "Exiting" => {
            shared.exiting.store(true, Ordering::Relaxed);
            shared.connected.store(false, Ordering::Relaxed);
        }
        "AvailableEgressRegions" => {
            let list = json_string_array(line, "regions");
            if !list.is_empty() {
                *shared.available_regions.lock() = list.clone();
                DiagnosticsLog::i(
                    TAG,
                    &format!("Psiphon egress regions available: {}", list.join(", ")),
                );
            }
        }
        "ConnectedServerRegion" => {
            if let Some(region) = psiphon_health::json_str(line, "serverRegion")
                .or_else(|| psiphon_health::json_str(line, "regionCode"))
                .or_else(|| psiphon_health::json_str(line, "region"))
            {
                *shared.connected_region.lock() = region.to_ascii_uppercase();
            }
        }
        _ => {}
    }

    if let Some(hint) = config_fault_hint(&kind, &message) {
        {
            let mut slot = shared.config_fault.lock();
            if slot.is_empty() {
                *slot = if message.is_empty() {
                    hint.to_string()
                } else {
                    format!("{hint} Psiphon said: {message}")
                };
            }
        }
        shared.exiting.store(true, Ordering::Relaxed);
        shared.connected.store(false, Ordering::Relaxed);
        DiagnosticsLog::e(TAG, &format!("{CONFIG_FAULT_PREFIX}{hint}"));
    }

    if is_noise_notice(&kind, &message) {
        shared.noise_notices.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let suppressed = shared.noise_notices.swap(0, Ordering::Relaxed);
    if suppressed > 0 {
        DiagnosticsLog::d(
            TAG,
            &format!("(+{suppressed} routine server-list notices suppressed)"),
        );
    }
    let body = if message.is_empty() { line } else { &message };
    match kind.as_str() {
        "Error" | "Alert" | "LocalProxyError" | "Exiting" => {
            DiagnosticsLog::w(TAG, &format!("{kind}: {body}"))
        }
        _ => DiagnosticsLog::d(TAG, &format!("{kind}: {body}")),
    }
}

fn config_fault_hint(kind: &str, message: &str) -> Option<&'static str> {
    if kind != "Error" && kind != "Alert" {
        return None;
    }
    let m = message.to_ascii_lowercase();
    if m.contains("error getting listener ip") {
        return Some(
            "it was pointed at a network interface that does not exist on this PC, so it exited              before it could open its SOCKS5 port. This is a launch-argument fault, not a network              problem — please report it with the diagnostics log.",
        );
    }
    if m.contains("error loading configuration file")
        || m.contains("error processing configuration file")
        || m.contains("invalid config")
    {
        return Some(
            "it refused its own configuration file and exited. This is a packaging fault, not a              network problem — reinstall Aether and report it with the diagnostics log.",
        );
    }
    None
}

fn is_noise_notice(kind: &str, message: &str) -> bool {
    if kind == "BytesTransferred" || (kind == "Info" && message.is_empty()) {
        return true;
    }
    kind == "Info"
        && (message.starts_with("updated server ")
            || message.starts_with("discarding server ")
            || message.starts_with("ServerEntryIterator.reset")
            || message.starts_with("Set dial parameters for "))
}

fn json_string_array(line: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let Some(at) = line.find(&needle) else {
        return Vec::new();
    };
    let rest = &line[at + needle.len()..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find(']') else {
        return Vec::new();
    };
    rest[open + 1..open + close]
        .split(',')
        .filter_map(|piece| {
            let cc = piece.trim().trim_matches('"').trim().to_ascii_uppercase();
            if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
                Some(cc)
            } else {
                None
            }
        })
        .collect()
}

fn redact_upstream(raw: &str) -> String {
    match raw.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((_, endpoint)) => format!("{scheme}://••••••@{endpoint}"),
            None => raw.to_string(),
        },
        None => raw.to_string(),
    }
}

fn build_config(inner: &Mutex<Inner>, egress: &str) -> String {
    let g = inner.lock();
    let mut cfg = json!({
        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "1111111111111111",
        "EstablishTunnelTimeoutSeconds": ESTABLISH_TIMEOUT_SECONDS,
        "DataRootDirectory": g.data_dir.to_string_lossy(),
        "ClientVersion": "127",
        "LocalSocksProxyPort": g.local_socks_port,
        "DisableLocalHTTPProxy": true,
        "RemoteServerListSignaturePublicKey": REMOTE_SERVER_LIST_PUBLIC_KEY,
        "ServerEntrySignaturePublicKey": SERVER_ENTRY_SIGNATURE_PUBLIC_KEY,
        "ExchangeObfuscationKey": EXCHANGE_OBFUSCATION_KEY,
        "EmitBytesTransferred": false,
        "EmitDiagnosticNotices": true,
        "DeviceRegion": "IR",
        "ConnectionWorkerPoolSize": 12,
        "DNSResolverPreferredAlternateServers": ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"],
        "DNSResolverPreferAlternateServerProbability": 1.0,
    });
    let map = cfg.as_object_mut().expect("config root is an object");
    if !egress.is_empty() {
        map.insert("EgressRegion".into(), json!(egress));
    }
    if g.avoid_replay {
        map.insert("DisableReplay".into(), json!(true));
        map.insert(
            "EstablishTunnelServerAffinityGracePeriodMilliseconds".into(),
            json!(0),
        );
    }
    if !g.upstream.is_empty() {
        map.insert("UpstreamProxyUrl".into(), json!(g.upstream.clone()));
    }
    cfg.to_string()
}

fn child_args(config_path: &Path, server_list: &Path, data_dir: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "-config".into(),
        config_path.as_os_str().to_os_string(),
        "-serverList".into(),
        server_list.as_os_str().to_os_string(),
        "-dataRootDirectory".into(),
        data_dir.as_os_str().to_os_string(),
    ]
}

fn spawn_child(inner: &Arc<Mutex<Inner>>, shared: &Arc<Shared>, config: &str) -> Result<()> {
    let (exe, server_list, data_dir, config_path) = {
        let g = inner.lock();
        (
            g.exe.clone(),
            g.server_list.clone(),
            g.data_dir.clone(),
            g.config_path.clone(),
        )
    };
    std::fs::create_dir_all(&data_dir)?;
    std::fs::write(&config_path, config)?;

    let generation = shared.generation.fetch_add(1, Ordering::SeqCst) + 1;
    shared.connected.store(false, Ordering::Relaxed);
    shared.exiting.store(false, Ordering::Relaxed);
    shared.socks_port.store(0, Ordering::Relaxed);
    shared.config_fault.lock().clear();

    let mut cmd = Command::new(&exe);
    cmd.args(child_args(&config_path, &server_list, &data_dir))
        .current_dir(&data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("Could not start {}: {e}", exe.display()))?;

    if let Some(err) = child.stderr.take() {
        spawn_notice_reader(shared, err, generation);
    }
    if let Some(out) = child.stdout.take() {
        spawn_notice_reader(shared, out, generation);
    }
    inner.lock().child = Some(child);
    Ok(())
}

fn spawn_notice_reader<R>(shared: &Arc<Shared>, reader: R, generation: u64)
where
    R: std::io::Read + Send + 'static,
{
    let shared = shared.clone();
    std::thread::Builder::new()
        .name("psiphon-notice".into())
        .spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                if shared.generation.load(Ordering::Relaxed) != generation {
                    return;
                }
                handle_notice(&shared, &line);
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> Arc<Shared> {
        Arc::new(Shared::new())
    }

    #[test]
    fn follows_the_reported_socks_port() {
        let s = shared();
        handle_notice(
            &s,
            r#"{"data":{"port":1825},"noticeType":"ListeningSocksProxyPort"}"#,
        );
        assert_eq!(s.socks_port.load(Ordering::Relaxed), 1825);
    }

    #[test]
    fn tunnels_notice_drives_connected() {
        let s = shared();
        assert!(!s.connected.load(Ordering::Relaxed));
        handle_notice(&s, r#"{"data":{"count":1},"noticeType":"Tunnels"}"#);
        assert!(s.connected.load(Ordering::Relaxed));
        handle_notice(&s, r#"{"data":{"count":0},"noticeType":"Tunnels"}"#);
        assert!(!s.connected.load(Ordering::Relaxed));
    }

    #[test]
    fn rotation_grace_survives_a_tunnels_zero() {
        let s = shared();
        handle_notice(&s, r#"{"data":{"count":1},"noticeType":"Tunnels"}"#);
        s.rotation_deadline
            .store(now_ms() + ROTATION_GRACE_MS, Ordering::Relaxed);
        handle_notice(&s, r#"{"data":{"count":0},"noticeType":"Tunnels"}"#);
        assert!(
            s.connected.load(Ordering::Relaxed),
            "an in-flight rotation must not read as death"
        );
    }

    #[test]
    fn parses_available_egress_regions() {
        let s = shared();
        handle_notice(
            &s,
            r#"{"data":{"regions":["AT","BE","DE"]},"noticeType":"AvailableEgressRegions"}"#,
        );
        assert_eq!(
            *s.available_regions.lock(),
            vec!["AT".to_string(), "BE".to_string(), "DE".to_string()]
        );
    }

    #[test]
    fn routine_server_list_notices_are_noise() {
        assert!(is_noise_notice("Info", "updated server abcdefgh"));
        assert!(is_noise_notice("Info", "discarding server abcdefgh"));
        assert!(is_noise_notice("BytesTransferred", ""));
        assert!(!is_noise_notice(
            "LocalProxyError",
            "ssh: rejected: administratively prohibited"
        ));
        assert!(!is_noise_notice(
            "Info",
            "port forward failures for abc: 12"
        ));
    }

    #[test]
    fn stage_two_is_never_told_which_interface_to_bind() {
        let args = child_args(
            Path::new("C:\\data\\psiphon.config"),
            Path::new("C:\\data\\engine\\server_entries.txt"),
            Path::new("C:\\data\\psiphon"),
        );
        let flat: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            !flat.iter().any(|a| a == "-listenInterface"),
            "ListenInterface takes an interface name, not an IP; the default already binds \
             127.0.0.1 — passing anything here killed the Psiphon stage on startup"
        );
        assert!(flat.iter().any(|a| a == "-config"));
        assert!(flat.iter().any(|a| a == "-serverList"));
        assert!(flat.iter().any(|a| a == "-dataRootDirectory"));
        assert_eq!(flat.len(), 6, "exactly three flags with one value each");
    }

    #[test]
    fn the_listener_ip_error_is_a_config_fault() {
        let s = shared();
        handle_notice(
            &s,
            r#"{"data":{"message":"error getting listener IP: psiphon.(*Controller).Run#424: common.GetInterfaceIPAddresses#38: route ip+net: no such network interface"},"noticeType":"Error","timestamp":"2026-09-04T05:54:19.510Z"}"#,
        );
        let fault = s.config_fault.lock().clone();
        assert!(!fault.is_empty(), "the fault must be recorded");
        assert!(s.exiting.load(Ordering::Relaxed), "no retry can fix this");
        assert!(is_config_fault(&format!("{CONFIG_FAULT_PREFIX}{fault}")));
    }

    #[test]
    fn a_network_error_is_not_a_config_fault() {
        let s = shared();
        handle_notice(
            &s,
            r#"{"data":{"message":"ssh: rejected: administratively prohibited"},"noticeType":"LocalProxyError"}"#,
        );
        handle_notice(
            &s,
            r#"{"data":{"message":"upstreamproxy error: dial tcp 127.0.0.1:1819: connect: connection refused"},"noticeType":"Error"}"#,
        );
        assert!(s.config_fault.lock().is_empty());
        assert!(!s.exiting.load(Ordering::Relaxed));
        assert!(!is_config_fault(
            "Psiphon found no usable server within 200s"
        ));
    }

    #[test]
    fn upstream_credentials_are_redacted() {
        assert_eq!(
            redact_upstream("socks5://user:pass@127.0.0.1:1819"),
            "socks5://••••••@127.0.0.1:1819"
        );
        assert_eq!(
            redact_upstream("socks5://127.0.0.1:1819"),
            "socks5://127.0.0.1:1819"
        );
    }
}
