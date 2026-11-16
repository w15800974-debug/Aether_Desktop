#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Aether Desktop — entry point.

mod ai_client;
mod ai_gate;
mod ai_http;
mod ai_model_policy;
mod ai_patch;
mod ai_prompts;
mod ai_redaction;
mod ai_session;
mod ai_topic;
mod diagnostics;
mod engine;
mod exit_regions;
mod filedrop;
mod firsthop;
mod geoip;
mod budgets;
mod custom;
mod custom_commands;
mod leakguard;
mod log;
mod login_code;
mod mini_https;
mod ping;
mod uplink;
mod uplink_policy;
mod probe;
mod procguard;
mod profile;
mod provenance;
pub mod presets;
mod savedialog;
mod pt;
mod secret_store;
mod share;
mod share_guard;
mod share_pages;
mod smart_auto;
mod smart_plus;
mod smart_lists;
mod smart_routes;
mod state;
mod store;
mod sysproxy;
mod tor_bootstrap;
mod zt_signin;
mod zt_web;
mod tor_native;
mod tor_relay;
mod tun;
mod window;

use ai_session::{AiSession, AiSnapshot};
use profile::ConnectionProfile;
use state::{AetherController, Snapshot};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};

pub const RELEASES_URL: &str = "https://github.com/w15800974-debug/Aether_Desktop/releases";
const TICK: Duration = Duration::from_millis(200);

pub struct AppState {
    controller: Mutex<AetherController>,
    presets: Mutex<presets::PresetStore>,
    latest: parking_lot::Mutex<Arc<Snapshot>>,
    ai: Arc<AiSession>,
}

#[derive(Default)]
struct StartupStatus(parking_lot::Mutex<Option<String>>);

#[tauri::command]
async fn startup_ready(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let began = Instant::now();
        loop {
            if app.try_state::<AppState>().is_some() { return Ok(()); }
            if let Some(status) = app.try_state::<StartupStatus>() {
                if let Some(error) = status.0.lock().clone() { return Err(error); }
            }
            if began.elapsed() > Duration::from_secs(90) {
                return Err("Aether initialization timed out; restart the app and check diagnostics".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }).await.map_err(|_| "Startup worker interrupted".to_owned())?
}

const UI_MIN_INTERVAL: Duration = Duration::from_millis(500);

fn only_counters_changed(previous: Option<&Snapshot>, next: &Snapshot) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    let strip = |s: &Snapshot| {
        let mut c = s.clone();
        c.uptime_secs = 0;
        c.rx_bytes = 0;
        c.tx_bytes = 0;
        c
    };
    strip(previous) == strip(next)
}

fn publish(
    app: &AppHandle,
    state: &AppState,
    snapshot: Snapshot,
    last: &mut Option<Arc<Snapshot>>,
    last_emit_at: &mut Option<Instant>,
) {
    let snapshot = Arc::new(snapshot);
    *state.latest.lock() = snapshot.clone();
    if last.as_deref() == Some(snapshot.as_ref()) {
        return;
    }
    if only_counters_changed(last.as_deref(), snapshot.as_ref()) {
        if let Some(at) = last_emit_at {
            if at.elapsed() < UI_MIN_INTERVAL {
                return;
            }
        }
    }
    *last = Some(snapshot.clone());
    *last_emit_at = Some(Instant::now());
    let _ = app.emit("aether://state", snapshot.as_ref());
}

#[tauri::command]
fn get_snapshot(app: State<'_, AppState>) -> Snapshot {
    app.latest.lock().as_ref().clone()
}

#[tauri::command]
fn get_profile(app: State<'_, AppState>) -> ConnectionProfile {
    app.controller.lock().unwrap().profile()
}

#[tauri::command]
fn set_profile(app: State<'_, AppState>, profile: ConnectionProfile) -> Result<(), String> {
    app.controller
        .lock()
        .unwrap()
        .set_profile(profile)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn preset_state(app: State<'_, AppState>) -> serde_json::Value {
    app.presets.lock().unwrap().data.view()
}

#[tauri::command]
fn preset_action(handle: AppHandle, app: State<'_, AppState>, action:String,
    id:Option<String>, name:Option<String>) -> Result<serde_json::Value,String> {
    let mut controller=app.controller.lock().map_err(|_|"Controller unavailable")?;
    if !matches!(controller.snapshot().state, state::ConnectionState::Disconnected | state::ConnectionState::Failed) {
        return Err("Disconnect before changing connection profiles".into());
    }
    let current=controller.profile();
    let mut store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    let live_custom=presets::CustomSel::from_state(&custom::store::snapshot());
    let (next,target,custom_apply)=store.data.change_with(&action,id.as_deref().unwrap_or(""),name.as_deref().unwrap_or(""),
        serde_json::to_value(&current).map_err(|e|e.to_string())?,live_custom)?;
    let target=target.map(serde_json::from_value::<ConnectionProfile>).transpose().map_err(|e|e.to_string())?;
    if let Some(profile)=target {
        let is_factory=serde_json::to_value(&profile).ok().as_ref()==Some(&presets::factory_profile());
        if is_factory { controller.reset_profile().map(|_|()).map_err(|e|e.to_string())?; }
        else { controller.set_profile(profile).map_err(|e|e.to_string())?; }
    }
    if let Err(error)=store.persist(&next) {
        let _=controller.set_profile(current);
        return Err(error);
    }
    store.data=next;
    if let Some(sel)=custom_apply {
        let s=sel.apply();
        let _=handle.emit("aether://custom", &custom_commands::view(&s));
    }
    let profile=controller.profile();
    let _=handle.emit("aether://profile", &profile);
    Ok(store.data.view())
}

#[tauri::command]
fn preset_export(app: State<'_, AppState>) -> Result<String,String> {
    let current=app.controller.lock().map_err(|_|"Controller unavailable")?.profile();
    let store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    let live=presets::CustomSel::from_state(&custom::store::snapshot());
    store.data.export_selected(serde_json::to_value(&current).map_err(|e|e.to_string())?,&live)
}

#[tauri::command]
async fn preset_export_save(window: tauri::WebviewWindow, app: State<'_, AppState>) -> Result<Option<String>,String> {
    let text=preset_export(app)?;
    #[cfg(windows)]
    let owner=window.hwnd().map(|h|h.0 as isize).unwrap_or(0);
    #[cfg(not(windows))]
    let owner=0isize;
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path)=savedialog::pick_save_path(owner,"Aether-1.4.0-profile.json")? else { return Ok(None) };
        std::fs::write(&path,text.as_bytes()).map_err(|e|format!("Could not save the file: {e}"))?;
        Ok(path.file_name().map(|n|n.to_string_lossy().into_owned()))
    }).await.map_err(|e|e.to_string())?
}

#[tauri::command]
fn preset_import(handle: AppHandle, app: State<'_, AppState>, text:String) -> Result<serde_json::Value,String> {
    let mut controller=app.controller.lock().map_err(|_|"Controller unavailable")?;
    let idle=matches!(controller.snapshot().state, state::ConnectionState::Disconnected | state::ConnectionState::Failed);
    let mut store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    if !idle {
        let (next,_count)=store.data.import(&text)?;
        store.persist(&next)?;
        store.data=next;
        let mut view=store.data.view();view["applied"]=serde_json::json!(false);
        return Ok(view);
    }
    let current=controller.profile();
    let live_custom=presets::CustomSel::from_state(&custom::store::snapshot());
    let (next,target,sel,_count)=store.data.import_and_select(&text,
        serde_json::to_value(&current).map_err(|e|e.to_string())?,live_custom)?;
    let profile:ConnectionProfile=serde_json::from_value(target).map_err(|e|e.to_string())?;
    let is_factory=serde_json::to_value(&profile).ok().as_ref()==Some(&presets::factory_profile());
    if is_factory { controller.reset_profile().map(|_|()).map_err(|e|e.to_string())?; }
    else { controller.set_profile(profile).map_err(|e|e.to_string())?; }
    if let Err(error)=store.persist(&next) {
        let _=controller.set_profile(current);
        return Err(error);
    }
    store.data=next;
    let s=sel.apply();
    let _=handle.emit("aether://custom", &custom_commands::view(&s));
    let _=handle.emit("aether://profile", &controller.profile());
    let mut view=store.data.view();view["applied"]=serde_json::json!(true);
    Ok(view)
}

#[tauri::command]
fn reset_profile(app: State<'_, AppState>) -> Result<ConnectionProfile, String> {
    app.controller
        .lock()
        .unwrap()
        .reset_profile()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn toggle_connection(handle: AppHandle, app: State<'_, AppState>) -> Result<(), String> {
    let snapshot = {
        let mut c = app.controller.lock().unwrap();
        c.request_toggle();
        c.snapshot()
    };
    let cached = Arc::new(snapshot);
    *app.latest.lock() = cached.clone();
    let _ = handle.emit("aether://state", cached.as_ref());
    Ok(())
}

#[tauri::command]
fn read_logs(limit: Option<usize>) -> Vec<String> {
    log::DiagnosticsLog::tail(limit.unwrap_or(800))
}

#[tauri::command]
fn export_logs() -> String {
    log::DiagnosticsLog::export_text()
}

#[tauri::command]
fn clear_logs() {
    log::DiagnosticsLog::clear();
}

#[tauri::command]
fn get_checks() -> Vec<log::ComponentCheck> {
    log::DiagnosticsLog::checks()
}

#[tauri::command]
fn run_self_test() {
    std::thread::Builder::new()
        .name("aether-manual-test".into())
        .spawn(|| {
            diagnostics::self_test(20_000);
        })
        .ok();
}

#[tauri::command]
fn run_diagnostics(app: State<'_, AppState>) -> diagnostics::Report {
    let profile = app.controller.lock().unwrap().profile();
    diagnostics::run(&profile)
}

#[tauri::command]
fn webrtc_leak_test(app: State<'_, AppState>) -> diagnostics::LeakReport {
    let exit = app
        .controller
        .lock()
        .unwrap()
        .snapshot()
        .ip_info
        .and_then(|i| if i.via_tunnel { Some(i.ip) } else { None });
    diagnostics::webrtc_leak_check(exit.as_deref())
}

#[tauri::command]
fn about_info() -> serde_json::Value {
    serde_json::json!({
        "appVersion": env!("CARGO_PKG_VERSION"),
        "coreVersion": core_version(),
        "arch": std::env::consts::ARCH,
        "releasesUrl": RELEASES_URL,
    })
}

#[tauri::command]
fn core_caps() -> serde_json::Value {
    let exe = engine::resolve_install_dir()
        .map(|d| d.join("engine").join(engine::ENGINE_EXE))
        .unwrap_or_default();
    let caps = engine::engine_caps(&exe);
    serde_json::json!({
        "zeroTrust": caps.zero_trust,
        "routing": caps.routing,
        "customDns": caps.custom_dns,
        "upstream": caps.upstream,
        "routeSniff": caps.route_sniff,
        "tor": caps.tor,
        "tls24": caps.tls24,
    })
}

fn core_version() -> String {
    engine::resolve_install_dir()
        .map(|d| d.join("engine").join("CORE_VERSION"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

const UI_LANG_KEY: &str = "ui.lang";

#[tauri::command]
fn get_ui_lang(app: AppHandle) -> Option<String> {
    let dir = app.path().app_local_data_dir().ok()?;
    store::PrefsStore::new(&dir)
        .get_string(UI_LANG_KEY)
        .filter(|v| v == "fa" || v == "en")
}

#[tauri::command]
fn set_ui_lang(app: AppHandle, lang: String) -> Result<(), String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    store::PrefsStore::new(&dir)
        .set_string(UI_LANG_KEY, lang)
        .map_err(|e| e.to_string())
}

const NEWS_LAST_LAUNCHED_KEY: &str = "news.last_launched";
const NEWS_SUPPRESSED_KEY: &str = "news.suppressed";

#[tauri::command]
fn news_state(app: AppHandle) -> serde_json::Value {
    let prefs = app
        .path()
        .app_local_data_dir()
        .ok()
        .map(|dir| store::PrefsStore::new(&dir));
    let read = |key: &str| prefs.as_ref().and_then(|p| p.get_string(key));
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "lastLaunched": read(NEWS_LAST_LAUNCHED_KEY),
        "suppressed": read(NEWS_SUPPRESSED_KEY),
    })
}

#[tauri::command]
fn news_mark(app: AppHandle, suppress: bool) -> Result<(), String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let prefs = store::PrefsStore::new(&dir);
    let version = env!("CARGO_PKG_VERSION");
    prefs
        .set_string(NEWS_LAST_LAUNCHED_KEY, version)
        .map_err(|e| e.to_string())?;
    if suppress {
        prefs
            .set_string(NEWS_SUPPRESSED_KEY, version)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn ai_snapshot(app: State<'_, AppState>) -> AiSnapshot {
    let snapshot = app.latest.lock().as_ref().clone();
    let profile = app.controller.lock().unwrap().profile();
    app.ai.snapshot(snapshot.state, &profile)
}

fn publish_ai(app: &AppHandle) {
    let state: State<'_, AppState> = app.state();
    let snapshot = state.latest.lock().as_ref().clone();
    let profile = state.controller.lock().unwrap().profile();
    let _ = app.emit("aether://ai", state.ai.snapshot(snapshot.state, &profile));
}

fn publish_profile(app: &AppHandle) {
    let _ = app.emit("aether://profile", profile_copy(app));
}

fn profile_copy(app: &AppHandle) -> ConnectionProfile {
    let state: State<'_, AppState> = app.state();
    let profile = state.controller.lock().unwrap().profile();
    profile
}

fn zt_paths(app: &AppHandle) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let state: State<'_, AppState> = app.state();
    let guard = state.controller.lock().unwrap();
    let out = (guard.data_dir().to_path_buf(), guard.identity_dirs());
    drop(guard);
    out
}

fn zt_status_now(app: &AppHandle, team: &str, email: &str) -> zt_signin::Status {
    let (data_dir, dirs) = zt_paths(app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    zt_signin::status(&data_dir, &refs, team, email)
}

#[tauri::command]
fn zt_status(app: AppHandle) -> zt_signin::Status {
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ZtProblem {
    kind: &'static str,
    status: Option<u16>,
    detail: Option<String>,
    host: String,
}

impl ZtProblem {
    fn of(failure: &zt_signin::Failure, raw_team: &str) -> Self {
        use zt_signin::Failure as F;
        let (kind, status, detail) = match failure {
            F::BadTeam => ("badTeam", None, None),
            F::BadEmail => ("badEmail", None, None),
            F::NoEmailCode => ("noEmailCode", None, None),
            F::Refused(code) => ("refused", Some(*code), None),
            F::NoNonce => ("noNonce", None, None),
            F::NoSession => ("noSession", None, None),
            F::NoToken(code) => ("noToken", Some(*code), None),
            F::Network(d) => ("network", None, Some(d.clone())),
        };
        Self::bare(kind, raw_team).with(status, detail)
    }

    fn bare(kind: &'static str, raw_team: &str) -> Self {
        let host = zt_web::normalize_team(raw_team)
            .map(|t| zt_web::team_host(&t))
            .unwrap_or_else(|| raw_team.trim().to_string());
        Self {
            kind,
            status: None,
            detail: None,
            host,
        }
    }

    fn with(mut self, status: Option<u16>, detail: Option<String>) -> Self {
        self.status = status;
        self.detail = detail;
        self
    }
}

fn zt_thread_died(raw_team: &str) -> ZtProblem {
    ZtProblem::bare("network", raw_team)
        .with(None, Some("the request thread stopped unexpectedly".into()))
}

#[tauri::command]
async fn zt_request_code(app: AppHandle) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let (team, email) = (p.team.clone(), p.access_email.clone());
    let session =
        tauri::async_runtime::spawn_blocking(move || zt_signin::request_code(&team, &email))
            .await
            .map_err(|_| zt_thread_died(&p.team))?
            .map_err(|f| ZtProblem::of(&f, &p.team))?;
    *zt_signin::pending().lock() = Some(session);
    Ok(zt_status_now(&app, &p.team, &p.access_email))
}

#[tauri::command]
async fn zt_resend_code(app: AppHandle) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let mut session = zt_signin::pending()
        .lock()
        .clone()
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::NoSession, &p.team))?;
    let session = tauri::async_runtime::spawn_blocking(move || {
        zt_signin::resend_code(&mut session).map(|_| session)
    })
    .await
    .map_err(|_| zt_thread_died(&p.team))?
    .map_err(|f| ZtProblem::of(&f, &p.team))?;
    *zt_signin::pending().lock() = Some(session);
    Ok(zt_status_now(&app, &p.team, &p.access_email))
}

#[tauri::command]
async fn zt_submit_code(app: AppHandle, code: String) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let mut session = zt_signin::pending()
        .lock()
        .clone()
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::NoSession, &p.team))?;
    let (outcome, session) = tauri::async_runtime::spawn_blocking(move || {
        let r = zt_signin::submit_code(&mut session, &code);
        (r, session)
    })
    .await
    .map_err(|_| zt_thread_died(&p.team))?;
    match outcome.map_err(|f| ZtProblem::of(&f, &p.team))? {
        zt_signin::CodeOutcome::Token(token) => {
            let now = zt_signin::now_secs();
            if !matches!(zt_web::inspect(&token, now), zt_web::Verdict::Usable(_)) {
                *zt_signin::pending().lock() = Some(session);
                return Err(ZtProblem::bare("expiredOnArrival", &p.team));
            }
            let (data_dir, _) = zt_paths(&app);
            let record = zt_signin::Record::of(&session.team, &session.email, &token, now)
                .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::BadTeam, &p.team))?;
            zt_signin::save_record(&data_dir, Some(&record));
            *zt_signin::pending().lock() = None;
            if zt_signin::load_record(&data_dir).as_ref() != Some(&record) {
                return Err(ZtProblem::bare("storeFailed", &p.team));
            }
            Ok(zt_status_now(&app, &p.team, &p.access_email))
        }
        zt_signin::CodeOutcome::Rejected(code) => {
            *zt_signin::pending().lock() = Some(session);
            Err(ZtProblem::bare("rejected", &p.team).with(Some(code), None))
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ZtMembership {
    team: Option<String>,
    enrolled: bool,
    editable: bool,
    mode: String,
    service_complete: bool,
}

fn zt_editable(app: &AppHandle) -> bool {
    !connection_state(app).is_active()
}

#[tauri::command]
fn share_info(app: AppHandle) -> share::ShareCredentials {
    let (data_dir, _) = zt_paths(&app);
    share::load_credentials(&data_dir)
}

#[tauri::command]
fn share_set_auth(app: AppHandle, required: bool) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::set_auth_required(&data_dir, required).map_err(|e| e.to_string())
}

#[tauri::command]
fn share_set_credentials(
    app: AppHandle,
    user: String,
    password: String,
) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::set_credentials(&data_dir, &user, &password)
}

#[tauri::command]
fn share_rotate_password(app: AppHandle) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::rotate_password(&data_dir).map_err(|e| e.to_string())
}

#[tauri::command]
fn zt_membership(app: AppHandle) -> ZtMembership {
    let p = profile_copy(&app);
    let team = zt_web::normalize_team(&p.team);
    let (_, dirs) = zt_paths(&app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    let enrolled = team
        .as_deref()
        .is_some_and(|t| zt_signin::is_enrolled(&refs, t));
    let mode = serde_json::to_value(p.access_mode)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    ZtMembership {
        team,
        enrolled,
        editable: zt_editable(&app),
        mode,
        service_complete: !p.access_id.trim().is_empty() && !p.access_secret.trim().is_empty(),
    }
}

#[tauri::command]
fn zt_forget_membership(app: AppHandle) -> Result<usize, ZtProblem> {
    let p = profile_copy(&app);
    if !zt_editable(&app) {
        return Err(ZtProblem::bare("busy", &p.team));
    }
    let team = zt_web::normalize_team(&p.team)
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::BadTeam, &p.team))?;
    let (_, dirs) = zt_paths(&app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    Ok(zt_signin::forget_membership(&refs, &team))
}

#[tauri::command]
async fn zt_test_service_token(app: AppHandle) -> Result<(), ZtProblem> {
    let p = profile_copy(&app);
    let (team, id, secret) = (p.team.clone(), p.access_id.clone(), p.access_secret.clone());
    tauri::async_runtime::spawn_blocking(move || zt_signin::test_service_token(&team, &id, &secret))
        .await
        .map_err(|_| zt_thread_died(&p.team))?
        .map_err(|f| ZtProblem::of(&f, &p.team))
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenCheck {
    verdict: &'static str,
    seconds_left: Option<i64>,
}

#[tauri::command]
fn zt_inspect_token(app: AppHandle, raw: Option<String>) -> TokenCheck {
    let typed = raw.unwrap_or_default();
    let token = if typed.trim().is_empty() {
        profile_copy(&app).access_token
    } else {
        typed
    };
    let now = zt_signin::now_secs();
    let verdict = match zt_web::inspect(&token, now) {
        zt_web::Verdict::Empty => "empty",
        zt_web::Verdict::Malformed => "malformed",
        zt_web::Verdict::Expired => "expired",
        zt_web::Verdict::Usable(_) => "usable",
    };
    TokenCheck {
        verdict,
        seconds_left: (verdict == "usable")
            .then(|| zt_web::expiry_seconds(token.trim()).map(|exp| exp - now))
            .flatten(),
    }
}

#[tauri::command]
fn zt_login_code_submit(code: String) -> bool {
    login_code::submit(&code)
}

#[tauri::command]
fn zt_login_code_dismiss() {
    login_code::dismiss();
}

#[tauri::command]
fn zt_forget(app: AppHandle) -> zt_signin::Status {
    let (data_dir, _) = zt_paths(&app);
    zt_signin::save_record(&data_dir, None);
    *zt_signin::pending().lock() = None;
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

#[tauri::command]
fn zt_cancel(app: AppHandle) -> zt_signin::Status {
    *zt_signin::pending().lock() = None;
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

#[tauri::command]
fn smart_list_counts(app: AppHandle) -> smart_lists::ListCounts {
    let (data_dir, _) = zt_paths(&app);
    smart_lists::counts(&data_dir)
}

fn connection_state(app: &AppHandle) -> state::ConnectionState {
    let state: State<'_, AppState> = app.state();
    let current = state.latest.lock().as_ref().state;
    current
}

fn ai_handle(app: &AppHandle) -> Arc<AiSession> {
    let state: State<'_, AppState> = app.state();
    state.ai.clone()
}

#[tauri::command]
fn ai_set_key(app: AppHandle, key: String) -> Result<(), String> {
    let result = ai_handle(&app).set_api_key(&key);
    publish_ai(&app);
    result
}

#[tauri::command]
fn ai_select_model(app: AppHandle, id: String) -> Result<(), String> {
    let result = ai_handle(&app).select_model(&id);
    publish_ai(&app);
    result
}

#[tauri::command]
fn ai_clear_chat(app: AppHandle) {
    ai_handle(&app).clear_chat();
    publish_ai(&app);
}

#[tauri::command]
fn ai_dismiss_error(app: AppHandle) {
    ai_handle(&app).dismiss_error();
    publish_ai(&app);
}

#[tauri::command]
fn ai_dismiss_advisor(app: AppHandle) {
    ai_handle(&app).dismiss_advisor();
    publish_ai(&app);
}

#[tauri::command]
async fn ai_test_key(app: AppHandle) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    session.mark_probe_running();
    publish_ai(&app);
    let result = tauri::async_runtime::spawn_blocking(move || session.test_connection(&profile))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
async fn ai_refresh_models(app: AppHandle) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let result = tauri::async_runtime::spawn_blocking(move || session.refresh_models(&profile))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
async fn ai_explain(
    app: AppHandle,
    lang: String,
    title: String,
    subtitle: String,
    value: String,
) -> Result<String, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let result = tauri::async_runtime::spawn_blocking(move || {
        session.explain(&profile, &lang, &title, &subtitle, &value)
    })
    .await
    .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
async fn ai_send_chat(app: AppHandle, lang: String, text: String) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let prompt = session.append_user_message(&text)?;
    publish_ai(&app);
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.ask_existing(&profile, status, &lang, &prompt)
    });
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
async fn ai_retry(app: AppHandle, lang: String, id: u64) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let prompt = session.take_failed_prompt(id)?;
    publish_ai(&app);
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.ask_existing(&profile, status, &lang, &prompt)
    });
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
async fn ai_edit_message(
    app: AppHandle,
    lang: String,
    id: u64,
    text: String,
) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let echo = app.clone();
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.edit_message(&profile, status, &lang, id, &text)
    });
    publish_ai(&echo);
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

#[tauri::command]
fn ai_delete_messages(app: AppHandle, ids: Vec<u64>) {
    ai_handle(&app).delete_messages(&ids);
    publish_ai(&app);
}

#[tauri::command]
fn ai_stop(app: AppHandle) {
    ai_handle(&app).stop();
    publish_ai(&app);
}

#[tauri::command]
fn ai_apply_changes(app: AppHandle, id: u64) -> Result<Vec<(String, String)>, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let (patched, applied) = session.changes_for(&profile, id)?;
    if !applied.is_empty() {
        let state: State<'_, AppState> = app.state();
        let written = state.controller.lock().unwrap().set_profile(patched);
        if let Err(e) = written {
            log::DiagnosticsLog::e("ai", &format!("chat changes could not be saved: {e}"));
            publish_ai(&app);
            return Err(format!("The changes could not be saved: {e}"));
        }
        publish_profile(&app);
        log::DiagnosticsLog::i(
            "ai",
            &format!(
                "chat applied: {}",
                applied
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    session.mark_applied(id);
    publish_ai(&app);
    Ok(applied)
}

#[tauri::command]
async fn ai_advise(app: AppHandle, lang: String) -> Result<ai_session::AdvisorResult, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let outcome = tauri::async_runtime::spawn_blocking(move || session.advise(&profile, &lang))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    let result = match outcome {
        Ok((patched, result)) => {
            if !result.applied.is_empty() {
                let state: State<'_, AppState> = app.state();
                let written = state.controller.lock().unwrap().set_profile(patched);
                if written.is_ok() {
                    publish_profile(&app);
                }
                if let Err(e) = written {
                    log::DiagnosticsLog::e(
                        "ai",
                        &format!("advisor changes could not be saved: {e}"),
                    );
                    publish_ai(&app);
                    return Err(format!("The changes could not be saved: {e}"));
                }
            }
            Ok(result)
        }
        Err(message) => Err(message),
    };
    publish_ai(&app);
    result
}

fn restore_window_geometry(win: &tauri::WebviewWindow, prefs: &store::PrefsStore) {
    let saved = prefs
        .get_string(window::PREFS_KEY)
        .as_deref()
        .and_then(window::decode);

    let scale = win.scale_factor().unwrap_or(1.0).max(0.1);
    let monitor = match win.current_monitor() {
        Ok(Some(m)) => Some(m),
        _ => win.primary_monitor().ok().flatten(),
    };
    let Some(monitor) = monitor else {
        log::DiagnosticsLog::w(
            "ui",
            "No monitor could be queried, so the window keeps the size from the config.",
        );
        return;
    };
    let area = monitor.work_area();
    let work = window::Rect::new(
        (f64::from(area.position.x) / scale).round() as i32,
        (f64::from(area.position.y) / scale).round() as i32,
        (f64::from(area.size.width) / scale).round() as u32,
        (f64::from(area.size.height) / scale).round() as u32,
    );

    let (default_w, default_h) = match win.inner_size() {
        Ok(s) => (
            (f64::from(s.width) / scale).round() as u32,
            (f64::from(s.height) / scale).round() as u32,
        ),
        Err(_) => (window::MIN_W, window::MIN_H),
    };

    let g = window::place(saved, work, default_w, default_h);
    let _ = win.set_size(tauri::LogicalSize::new(g.rect.w, g.rect.h));
    let _ = win.set_position(tauri::LogicalPosition::new(g.rect.x, g.rect.y));
    if g.maximized {
        let _ = win.maximize();
    }
}

fn remember_window_geometry(win: &tauri::WebviewWindow, prefs: &store::PrefsStore) {
    let maximized = win.is_maximized().unwrap_or(false);
    let previous = prefs
        .get_string(window::PREFS_KEY)
        .as_deref()
        .and_then(window::decode);

    let rect = if maximized {
        match previous {
            Some(g) => g.rect,
            None => match current_rect(win) {
                Some(r) => r,
                None => return,
            },
        }
    } else {
        match current_rect(win) {
            Some(r) => r,
            None => return,
        }
    };

    let g = window::Geometry { rect, maximized };
    if previous == Some(g) {
        return;
    }
    if let Err(e) = prefs.set_string(window::PREFS_KEY, &window::encode(&g)) {
        log::DiagnosticsLog::w("ui", &format!("Could not save the window size: {e}"));
    }
}

fn current_rect(win: &tauri::WebviewWindow) -> Option<window::Rect> {
    let scale = win.scale_factor().unwrap_or(1.0).max(0.1);
    let size = win.inner_size().ok()?;
    let pos = win.outer_position().ok()?;
    let w = (f64::from(size.width) / scale).round() as u32;
    let h = (f64::from(size.height) / scale).round() as u32;
    if w == 0 || h == 0 {
        return None;
    }
    Some(window::Rect::new(
        (f64::from(pos.x) / scale).round() as i32,
        (f64::from(pos.y) / scale).round() as i32,
        w,
        h,
    ))
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            log::DiagnosticsLog::init(&data_dir);
            let prefs = Arc::new(store::PrefsStore::new(&data_dir));
            app.manage(StartupStatus::default());

            if let Some(win) = app.get_webview_window("main") {
                restore_window_geometry(&win, &prefs);
                filedrop::install(&win);
                let prefs_for_events = prefs.clone();
                let watched = win.clone();
                win.on_window_event(move |event| match event {
                    tauri::WindowEvent::Resized(_) | tauri::WindowEvent::Moved(_) => {
                        remember_window_geometry(&watched, &prefs_for_events);
                    }
                    tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed => {
                        remember_window_geometry(&watched, &prefs_for_events);
                    }
                    _ => {}
                });
            }
            let handle = app.handle().clone();
            std::thread::Builder::new().name("aether-bootstrap".into()).spawn(move || {
                let initialized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    custom::store::init(&data_dir);
                    let controller = AetherController::new(&data_dir);
                    let first = controller.snapshot();
                    let preset_store = presets::PresetStore::new(&data_dir,
                        serde_json::to_value(controller.profile()).unwrap_or_default());
                    handle.manage(AppState {
                        presets: Mutex::new(preset_store),
                        controller: Mutex::new(controller),
                        latest: parking_lot::Mutex::new(Arc::new(first)),
                        ai: Arc::new(AiSession::new(&data_dir, prefs)),
                    });
                }));
                if initialized.is_err() {
                    *handle.state::<StartupStatus>().0.lock() = Some("Aether background initialization failed".into());
                    return;
                }
                let mut last: Option<Arc<Snapshot>> = None;
                let mut last_emit_at: Option<Instant> = None;
                let mut last_gate_state: Option<state::ConnectionState> = None;
                loop {
                    let began = Instant::now();
                    let st: State<'_, AppState> = handle.state();
                    let snapshot = match st.controller.try_lock() {
                        Ok(mut c) => {
                            c.tick();
                            Some(c.snapshot())
                        }
                        Err(TryLockError::WouldBlock) => None,
                        Err(TryLockError::Poisoned(p)) => {
                            let mut c = p.into_inner();
                            c.tick();
                            Some(c.snapshot())
                        }
                    };
                    if let Some(snap) = snapshot {
                        let current_state = snap.state;
                        publish(&handle, &st, snap, &mut last, &mut last_emit_at);
                        if last_gate_state != Some(current_state) {
                            last_gate_state = Some(current_state);
                            let ai_handle = handle.clone();
                            std::thread::spawn(move || publish_ai(&ai_handle));
                        }
                    }
                    std::thread::sleep(TICK.saturating_sub(began.elapsed()));
                }
            })?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            startup_ready,
            preset_state,
            preset_action,
            preset_export,
            preset_export_save,
            preset_import,
            custom_commands::cc_state,
            custom_commands::cc_tab_save,
            custom_commands::cc_tab_delete,
            custom_commands::cc_move,
            custom_commands::cc_subscription_save,
            custom_commands::cc_subscription_refresh,
            custom_commands::cc_subscription_delete,
            custom_commands::cc_import_text,
            custom_commands::cc_import_file,
            custom_commands::cc_import_bytes,
            custom_commands::cc_read_qr_image,
            custom_commands::cc_import_path,
            custom_commands::cc_select,
            custom_commands::cc_set_mode,
            custom_commands::cc_set_enabled,
            custom_commands::cc_rename,
            custom_commands::cc_get_raw,
            custom_commands::cc_edit,
            custom_commands::cc_delete,
            custom_commands::cc_delete_all,
            custom_commands::cc_ping,
            custom_commands::cc_ping_all,
            custom_commands::cc_scan_options,
            custom_commands::cc_scan_set_options,
            custom_commands::cc_scan_state,
            custom_commands::cc_scan_start,
            custom_commands::cc_scan_stop,
            custom_commands::cc_scan_dismiss,
            custom_commands::cc_speed_test,
            custom_commands::cc_speed_state,
            share_info,
            share_set_auth,
            share_set_credentials,
            share_rotate_password,
            get_snapshot,
            get_profile,
            set_profile,
            reset_profile,
            toggle_connection,
            read_logs,
            export_logs,
            clear_logs,
            get_checks,
            run_self_test,
            run_diagnostics,
            webrtc_leak_test,
            about_info,
            core_caps,
            ai_snapshot,
            get_ui_lang,
            set_ui_lang,
            news_state,
            news_mark,
            ai_set_key,
            ai_test_key,
            ai_select_model,
            ai_refresh_models,
            ai_explain,
            ai_send_chat,
            ai_retry,
            ai_apply_changes,
            ai_edit_message,
            ai_delete_messages,
            ai_stop,
            ai_advise,
            ai_clear_chat,
            ai_dismiss_error,
            ai_dismiss_advisor,
            zt_status,
            zt_request_code,
            zt_resend_code,
            zt_submit_code,
            zt_forget,
            zt_cancel,
            zt_membership,
            zt_forget_membership,
            zt_test_service_token,
            zt_inspect_token,
            zt_login_code_submit,
            zt_login_code_dismiss,
            smart_list_counts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aether");
}
