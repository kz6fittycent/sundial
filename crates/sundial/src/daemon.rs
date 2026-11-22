//! The root daemon: ticks every few seconds, counts active time, enforces limits,
//! and serves the agent and admin sockets (and the web page, see `web.rs`).

use crate::{logind, sys};
use anyhow::{Context, Result};
use chrono::Local;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use sundial_core::activity::{self, Classified};
use sundial_core::config::{
    ADMIN_SOCKET, AGENT_SOCKET, Action, Config, PolicyUpdate, UserPolicy, edit_user_policy,
};
use sundial_core::proto::{
    ActivityLine, AdminRequest, AdminResponse, AgentReport, AgentStatus, SessionInfo, Tracking,
    UserStatus,
};
use sundial_core::rules::{self, Verdict};
use sundial_core::state::State;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

pub const TICK_SECS: u64 = 5;
/// Notice given when a session shows up while the account is blocked (logged in some
/// way the PAM check didn't cover, or a parent locked with no countdown).
pub const GRACE_SECS: i64 = 60;
/// Deadline changes this small are jitter, not a new countdown.
const DEADLINE_SLACK: i64 = 15;
/// Agent reports older than this are ignored (agent hung or gone).
const REPORT_FRESH_SECS: i64 = 20;

/// Per-user enforcement memory; not persisted.
#[derive(Default)]
struct Runtime {
    /// Unix time the session ends/locks while a countdown runs.
    deadline: Option<i64>,
    last_enforce: Option<i64>,
    /// Deadline we already sent a fallback notification for.
    notified: Option<i64>,
}

pub struct Daemon {
    cfg: Config,
    cfg_path: PathBuf,
    cfg_mtime: Option<SystemTime>,
    state: State,
    state_path: PathBuf,
    runtime: HashMap<String, Runtime>,
    statuses: Vec<UserStatus>,
    sessions: Vec<logind::Session>,
    last_tick: Option<tokio::time::Instant>,
    agents_tx: watch::Sender<HashMap<String, AgentStatus>>,
    /// Connected agents per user.
    agents: HashMap<String, usize>,
    /// Latest agent report per user, with the time it arrived.
    reports: HashMap<String, (i64, AgentReport)>,
}

pub type Shared = Arc<Mutex<Daemon>>;

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Daemon {
    pub fn new(cfg_path: PathBuf, state_path: PathBuf) -> Result<Daemon> {
        let cfg = Config::load(&cfg_path).map_err(anyhow::Error::msg)?;
        let state = match State::load(&state_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sundial: state unreadable ({e}); starting fresh");
                let _ = std::fs::rename(&state_path, state_path.with_extension("json.bad"));
                State::default()
            }
        };
        let (agents_tx, _) = watch::channel(HashMap::new());
        Ok(Daemon {
            cfg_mtime: mtime(&cfg_path),
            cfg,
            cfg_path,
            state,
            state_path,
            runtime: HashMap::new(),
            statuses: Vec::new(),
            sessions: Vec::new(),
            last_tick: None,
            agents_tx,
            agents: HashMap::new(),
            reports: HashMap::new(),
        })
    }

    fn managed_names(&self) -> Vec<String> {
        self.cfg.users.iter().map(|u| u.name.clone()).collect()
    }

    fn log(&mut self, user: &str, text: impl Into<String>) {
        let text = text.into();
        println!("{user}: {text}");
        self.state.log(Local::now().timestamp(), user, text);
    }

    /// Reload the config if the file changed. Returns true if it did.
    fn maybe_reload(&mut self) -> bool {
        let m = mtime(&self.cfg_path);
        if m == self.cfg_mtime {
            return false;
        }
        self.cfg_mtime = m;
        match Config::load(&self.cfg_path) {
            Ok(cfg) => {
                self.cfg = cfg;
                self.log("sundial", "config reloaded");
                true
            }
            Err(e) => {
                self.log("sundial", format!("config not reloaded: {e}"));
                false
            }
        }
    }

    /// What is in front for this user, from a fresh agent report.
    fn focus_now(&self, user: &str, t: i64) -> Option<Classified> {
        let (ts, rep) = self.reports.get(user)?;
        if t - ts > REPORT_FRESH_SECS || self.agents.get(user).copied().unwrap_or(0) == 0 {
            return None;
        }
        activity::classify(rep.focus.as_ref()?, &self.cfg.activities)
    }

    /// One tick: count, decide, and return what needs doing outside the lock.
    fn tick(&mut self, sessions: Vec<logind::Session>) -> Vec<Effect> {
        let now = Local::now();
        let t = now.timestamp();
        let mono = tokio::time::Instant::now();
        // Monotonic time excludes suspend; cap so a stall never counts as a big chunk of use.
        let delta = self
            .last_tick
            .map(|l| mono.duration_since(l).as_secs().min(TICK_SECS * 3))
            .unwrap_or(0);
        self.last_tick = Some(mono);
        self.sessions = sessions;

        let before = self.state.users.clone();
        let mut effects = Vec::new();
        for p in self.cfg.users.clone() {
            let mine: Vec<&logind::Session> =
                self.sessions.iter().filter(|s| s.user == p.name).collect();
            let in_use = mine.iter().any(|s| s.in_use()) && !self.agent_says_away(&p, t);
            let has_sessions = !mine.is_empty();
            let unlocked: Vec<String> = mine
                .iter()
                .filter(|s| !s.locked)
                .map(|s| s.id.clone())
                .collect();
            let us = self.state.users.entry(p.name.clone()).or_default();
            let events = rules::account(&p, us, &now, if in_use { delta } else { 0 }, in_use);
            let verdict = rules::evaluate(&p, us, &now);
            for e in events {
                self.log(&p.name, e);
            }
            if p.track_activity
                && in_use
                && let Some(c) = self.focus_now(&p.name, t)
            {
                let us = self.state.users.entry(p.name.clone()).or_default();
                activity::record(us, &now.date_naive().to_string(), &c, delta);
            }

            let rt = self.runtime.entry(p.name.clone()).or_default();
            let warn = i64::from(p.warn_minutes) * 60;
            match verdict {
                Verdict::Allowed { until: Some(u), .. } if u - t <= warn => {
                    // Session-limit deadlines drift by a second per tick (tick vs. counted
                    // time); keep the first one so the countdown and notices stay put.
                    if rt.deadline.is_none_or(|d| (d - u).abs() > DEADLINE_SLACK) {
                        rt.deadline = Some(u);
                    }
                }
                Verdict::Allowed { .. } => rt.deadline = None,
                Verdict::Blocked { .. } if !has_sessions => rt.deadline = None,
                Verdict::Blocked { .. } => {
                    let fresh = rt.deadline.is_none();
                    let due = *rt.deadline.get_or_insert(t + GRACE_SECS);
                    if fresh {
                        let msg = format!(
                            "signed in while blocked; {} in {GRACE_SECS} s",
                            if p.action == Action::Lock {
                                "locking"
                            } else {
                                "logging out"
                            }
                        );
                        self.log(&p.name, msg);
                    }
                    let rt = self.runtime.get_mut(&p.name).expect("runtime");
                    let due_now = t >= due && rt.last_enforce.is_none_or(|l| t - l >= 10);
                    if due_now && (p.action == Action::Logout || !unlocked.is_empty()) {
                        rt.last_enforce = Some(t);
                        effects.push(match p.action {
                            Action::Logout => Effect::Terminate(p.name.clone()),
                            Action::Lock => Effect::Lock(unlocked.clone()),
                        });
                        let what = if p.action == Action::Lock {
                            "locked the screen"
                        } else {
                            "logged out"
                        };
                        let why = rules::describe(&verdict, &now);
                        self.log(&p.name, format!("{what}: {why}"));
                    }
                }
            }

            // Countdown notice when the agent isn't there to show it.
            let rt = self.runtime.get_mut(&p.name).expect("runtime");
            if let Some(d) = rt.deadline
                && has_sessions
                && rt.notified != Some(d)
                && self.agents.get(&p.name).copied().unwrap_or(0) == 0
            {
                rt.notified = Some(d);
                effects.push(Effect::Notify(
                    p.name.clone(),
                    format!("Sundial: {} left", rules::fmt_duration(d - t)),
                    format!("{} Save your work now.", rules::describe(&verdict, &now)),
                ));
            }
        }
        self.refresh_status();
        if self.state.users != before || !effects.is_empty() {
            effects.push(Effect::Save);
        }
        effects
    }

    /// Recompute the status views (web/CLI/agents) without counting time.
    fn refresh_status(&mut self) {
        let now = Local::now();
        let t = now.timestamp();
        let mut statuses = Vec::new();
        let mut agent = HashMap::new();
        for p in &self.cfg.users {
            let us = self.state.users.get(&p.name).cloned().unwrap_or_default();
            let v = rules::evaluate(p, &us, &now);
            let deadline = self.runtime.get(&p.name).and_then(|r| r.deadline);
            let summary = rules::describe(&v, &now);
            let sessions: Vec<SessionInfo> = self
                .sessions
                .iter()
                .filter(|s| s.user == p.name)
                .map(|s| SessionInfo {
                    id: s.id.clone(),
                    kind: s.kind.clone(),
                    active: s.active,
                    locked: s.locked,
                    idle: s.idle,
                })
                .collect();
            let remaining = match v {
                Verdict::Allowed { until, .. } => until.map(|u| u - t),
                Verdict::Blocked { .. } => Some(0),
            };
            agent.insert(
                p.name.clone(),
                AgentStatus {
                    managed: true,
                    allowed: v.is_allowed(),
                    remaining_secs: remaining,
                    deadline,
                    message: summary.clone(),
                    action: if p.action == Action::Lock {
                        "lock"
                    } else {
                        "logout"
                    }
                    .into(),
                },
            );
            statuses.push(UserStatus {
                name: p.name.clone(),
                verdict: v,
                summary,
                used_secs: us.used_secs,
                session_secs: u64::from(p.session_minutes) * 60,
                break_secs: u64::from(p.break_minutes) * 60,
                break_until: us.break_until.filter(|&b| b > t),
                allow_until: us.allow_until.filter(|&a| a > t),
                block: us.block.filter(|b| b.until > t),
                today_active_secs: if us.today == now.date_naive().to_string() {
                    us.today_active_secs
                } else {
                    0
                },
                schedule_today: schedule_today(p, &now),
                deadline,
                policy: PolicyUpdate::from_policy(p),
                track_activity: p.track_activity,
                tracking: self.tracking(p, !sessions.is_empty(), t),
                tracking_source: self.tracking_source(p, t),
                now_doing: self.now_doing(p, &sessions, t),
                activity_today: activity_lines(&us, &now, 1, 6),
                activity_week: activity_lines(&us, &now, 7, 0),
                sessions,
            });
        }
        self.statuses = statuses;
        self.agents_tx.send_replace(agent);
    }

    fn tracking(&self, p: &UserPolicy, signed_in: bool, t: i64) -> Tracking {
        if !p.track_activity {
            return Tracking::Off;
        }
        if !signed_in {
            return Tracking::NotSignedIn;
        }
        if self.agents.get(&p.name).copied().unwrap_or(0) == 0 {
            return Tracking::NoAgent;
        }
        match self.reports.get(&p.name) {
            Some((ts, rep)) if t - ts <= REPORT_FRESH_SECS && rep.focus_ok => Tracking::Ok,
            _ => Tracking::NoExtension,
        }
    }

    /// A fresh agent report says the screen is locked, or nobody has touched the
    /// keyboard/mouse for `idle_minutes` with no media playing. This covers desktops
    /// that don't report idle/lock to logind (most besides GNOME and Plasma).
    fn agent_says_away(&self, p: &UserPolicy, t: i64) -> bool {
        let Some((ts, rep)) = self.reports.get(&p.name) else {
            return false;
        };
        if t - ts > REPORT_FRESH_SECS {
            return false;
        }
        let idle = rep
            .idle_secs
            .is_some_and(|i| i >= u64::from(p.idle_minutes) * 60 && !rep.media_playing);
        rep.locked == Some(true) || idle
    }

    fn tracking_source(&self, p: &UserPolicy, t: i64) -> Option<String> {
        self.reports
            .get(&p.name)
            .filter(|(ts, _)| t - ts <= REPORT_FRESH_SECS)
            .map(|(_, r)| r.source.clone())
            .filter(|s| !s.is_empty())
    }

    fn now_doing(&self, p: &UserPolicy, sessions: &[SessionInfo], t: i64) -> Option<String> {
        if !p.track_activity || sessions.is_empty() {
            return None;
        }
        if let Some((ts, rep)) = self.reports.get(&p.name)
            && t - ts <= REPORT_FRESH_SECS
        {
            if rep.locked == Some(true) {
                return Some("Screen locked".into());
            }
            if self.agent_says_away(p, t) {
                return Some("Idle".into());
            }
        }
        let front = sessions.iter().find(|s| s.active);
        match front {
            None => Some("Signed in, in the background".into()),
            Some(s) if s.locked => Some("Screen locked".into()),
            Some(s) if s.idle => Some("Idle".into()),
            Some(_) => self.focus_now(&p.name, t).map(|c| match c.detail {
                Some(d) => format!("{}: {d}", c.name),
                None => c.name,
            }),
        }
    }

    /// Replace one account's limits and hours in the config file, then reload it.
    fn set_policy(
        &mut self,
        user: &str,
        by: &str,
        policy: &PolicyUpdate,
    ) -> Result<String, String> {
        let text = std::fs::read_to_string(&self.cfg_path)
            .map_err(|e| format!("reading {}: {e}", self.cfg_path.display()))?;
        let out = edit_user_policy(&text, user, policy)?;
        if out == text {
            return Ok("no changes".into());
        }
        let bak = self.cfg_path.with_extension("toml.bak");
        let tmp = self.cfg_path.with_extension("toml.tmp");
        std::fs::write(&bak, &text).map_err(|e| format!("backup: {e}"))?;
        std::fs::write(&tmp, &out).map_err(|e| format!("writing config: {e}"))?;
        std::fs::rename(&tmp, &self.cfg_path).map_err(|e| format!("writing config: {e}"))?;
        self.cfg = Config::parse(&out)?;
        self.cfg_mtime = mtime(&self.cfg_path);
        let days: Vec<String> = sundial_core::config::DAY_KEYS
            .iter()
            .zip(policy.days)
            .map(|(d, w)| {
                format!(
                    "{d} {}",
                    w.map(|w| w.to_string()).unwrap_or_else(|| "none".into())
                )
            })
            .collect();
        let text = format!(
            "limits set: {} min on, {} min break, {} min warning, {}; hours {}",
            policy.session_minutes,
            policy.break_minutes,
            policy.warn_minutes,
            if policy.action == Action::Lock {
                "lock"
            } else {
                "logout"
            },
            days.join(", ")
        );
        self.log(user, format!("{text} (by {by})"));
        Ok(text)
    }

    pub fn handle(&mut self, req: AdminRequest) -> AdminResponse {
        let now = Local::now();
        let mut resp = AdminResponse {
            ok: true,
            now: now.timestamp(),
            ..Default::default()
        };
        if let AdminRequest::SetPolicy { user, by, policy } = &req {
            match self.set_policy(user, by, policy) {
                Ok(m) => resp.message = Some(m),
                Err(e) => {
                    resp.ok = false;
                    resp.error = Some(e);
                }
            }
            self.refresh_status();
        }
        if let AdminRequest::Act { user, by, action } = req {
            match self.cfg.user(&user).cloned() {
                None => {
                    resp.ok = false;
                    resp.error = Some(format!("{user} is not managed by Sundial"));
                }
                Some(p) => {
                    let us = self.state.users.entry(user.clone()).or_default();
                    let text = rules::apply(&p, us, &now, action);
                    // A new countdown or lifted block starts over.
                    if let Some(rt) = self.runtime.get_mut(&user) {
                        rt.deadline = None;
                    }
                    self.log(&user, format!("{text} (by {by})"));
                    if let Err(e) = self.state.save(&self.state_path) {
                        eprintln!("sundial: saving state: {e}");
                    }
                    resp.message = Some(text);
                    self.refresh_status();
                }
            }
        }
        resp.users = self.statuses.clone();
        resp.log = self.state.log.iter().rev().take(50).cloned().collect();
        resp
    }
}

/// Activity totals for the last `days` days (1 = today), largest first, with up to
/// `details` top titles each.
fn activity_lines(
    us: &sundial_core::state::UserState,
    now: &chrono::DateTime<Local>,
    days: i64,
    details: usize,
) -> Vec<ActivityLine> {
    let first = (now.date_naive() - chrono::Duration::days(days - 1)).to_string();
    let mut totals: HashMap<String, u64> = HashMap::new();
    let mut titles: HashMap<String, HashMap<String, u64>> = HashMap::new();
    for (_, day) in us.activity.range(first..) {
        for (name, secs) in &day.totals {
            *totals.entry(name.clone()).or_default() += secs;
        }
        for (name, ts) in &day.details {
            let m = titles.entry(name.clone()).or_default();
            for (title, secs) in ts {
                *m.entry(title.clone()).or_default() += secs;
            }
        }
    }
    let mut lines: Vec<ActivityLine> = totals
        .into_iter()
        .map(|(name, secs)| {
            let mut d: Vec<(String, u64)> = titles
                .remove(&name)
                .unwrap_or_default()
                .into_iter()
                .collect();
            d.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            d.truncate(details);
            ActivityLine {
                name,
                secs,
                details: d,
            }
        })
        .collect();
    lines.sort_by(|a, b| b.secs.cmp(&a.secs).then(a.name.cmp(&b.name)));
    lines
}

/// "08:00-20:00" or "no access" for today.
fn schedule_today(p: &UserPolicy, now: &chrono::DateTime<Local>) -> String {
    use chrono::Datelike;
    match p.schedule.days[now.weekday().num_days_from_monday() as usize] {
        Some(w) => w.to_string(),
        None => "no access today".into(),
    }
}

enum Effect {
    Terminate(String),
    Lock(Vec<String>),
    Notify(String, String, String),
    Save,
}

pub async fn run(cfg_path: PathBuf, state_path: PathBuf, web: bool) -> Result<()> {
    if let Some(dir) = state_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let daemon = Daemon::new(cfg_path, state_path)?;
    let names = daemon.managed_names();
    let web_cfg = daemon.cfg.web.clone();
    let shared: Shared = Arc::new(Mutex::new(daemon));
    for e in sys::ensure_group_members(&names).await {
        shared.lock().unwrap().log("sundial", e);
    }
    shared
        .lock()
        .unwrap()
        .log("sundial", format!("started; managing {}", names.join(", ")));

    tokio::spawn(agent_server(shared.clone()));
    tokio::spawn(admin_server(shared.clone()));
    if web && web_cfg.enabled {
        let s = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::web::serve(s, &web_cfg.listen).await {
                eprintln!("sundial: web server stopped: {e:#}");
            }
        });
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(TICK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
        let sessions = match logind::sessions().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sundial: {e:#}");
                continue;
            }
        };
        let reloaded = shared.lock().unwrap().maybe_reload();
        if reloaded {
            let names = shared.lock().unwrap().managed_names();
            for e in sys::ensure_group_members(&names).await {
                shared.lock().unwrap().log("sundial", e);
            }
        }
        let effects = shared.lock().unwrap().tick(sessions);
        for e in effects {
            match e {
                Effect::Terminate(u) => {
                    if let Err(e) = logind::terminate_user(&u).await {
                        eprintln!("sundial: {e:#}");
                    }
                }
                Effect::Lock(ids) => {
                    for id in ids {
                        if let Err(e) = logind::lock_session(&id).await {
                            eprintln!("sundial: {e:#}");
                        }
                    }
                }
                Effect::Notify(u, title, body) => sys::notify_user(&u, &title, &body),
                Effect::Save => {
                    let d = shared.lock().unwrap();
                    if let Err(e) = d.state.save(&d.state_path) {
                        eprintln!("sundial: saving state: {e}");
                    }
                }
            }
        }
    }
    let d = shared.lock().unwrap();
    let _ = d.state.save(&d.state_path);
    println!("sundial: stopped");
    Ok(())
}

fn bind_socket(path: &str, mode: u32) -> Result<UnixListener> {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(p);
    let l = UnixListener::bind(p).with_context(|| format!("binding {path}"))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    Ok(l)
}

/// Agents connect here; the peer's uid (from the kernel, not the client) picks the status sent.
async fn agent_server(shared: Shared) {
    let listener = match bind_socket(AGENT_SOCKET, 0o666) {
        Ok(l) => l,
        Err(e) => return eprintln!("sundial: agent socket: {e:#}"),
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let Ok(cred) = stream.peer_cred() else { return };
            let Some(user) = sys::user_by_uid(cred.uid()) else {
                return;
            };
            serve_agent(shared, stream, user).await;
        });
    }
}

async fn serve_agent(shared: Shared, stream: UnixStream, user: String) {
    let mut rx = {
        let mut d = shared.lock().unwrap();
        *d.agents.entry(user.clone()).or_default() += 1;
        d.agents_tx.subscribe()
    };
    let unmanaged = AgentStatus {
        managed: false,
        allowed: true,
        remaining_secs: None,
        deadline: None,
        message: String::new(),
        action: String::new(),
    };
    let (r, mut w) = stream.into_split();
    // Reports are small; a line this long is not from a real agent.
    let mut lines = BufReader::new(r.take(1 << 20)).lines();
    let mut send = true;
    loop {
        if send {
            let status = rx
                .borrow_and_update()
                .get(&user)
                .cloned()
                .unwrap_or_else(|| unmanaged.clone());
            let mut line = serde_json::to_string(&status).unwrap_or_default();
            line.push('\n');
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    break;
                }
                send = true;
            }
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { break };
                if let Ok(rep) = serde_json::from_str::<AgentReport>(&line) {
                    let t = Local::now().timestamp();
                    shared.lock().unwrap().reports.insert(user.clone(), (t, rep));
                }
                send = false;
            }
        }
    }
    let mut d = shared.lock().unwrap();
    if let Some(n) = d.agents.get_mut(&user) {
        *n = n.saturating_sub(1);
    }
}

/// Root-only socket for the `sundial` CLI.
async fn admin_server(shared: Shared) {
    let listener = match bind_socket(ADMIN_SOCKET, 0o600) {
        Ok(l) => l,
        Err(e) => return eprintln!("sundial: admin socket: {e:#}"),
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if stream.peer_cred().map(|c| c.uid()).ok() != Some(0) {
                return;
            }
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            if BufReader::new(r).read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<AdminRequest>(&line) {
                Ok(req) => shared.lock().unwrap().handle(req),
                Err(e) => AdminResponse {
                    ok: false,
                    error: Some(format!("bad request: {e}")),
                    ..Default::default()
                },
            };
            let mut out = serde_json::to_string(&resp).unwrap_or_default();
            out.push('\n');
            let _ = w.write_all(out.as_bytes()).await;
        });
    }
}
