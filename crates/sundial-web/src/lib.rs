//! The parent page, shared by Sundial and Sundial Server: sign-in, the account cards
//! and the overrides. Server-rendered HTML, no JavaScript framework.

pub mod auth;

use auth::{Auth, SESSION_DAYS};
use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Local, NaiveTime, TimeZone, Timelike};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use sundial_core::config::{Action, DAY_KEYS, PolicyUpdate, Window};
use sundial_core::proto::{AdminRequest, AdminResponse, Tracking, UsageBar, UserStatus};
use sundial_core::rules::{Override, Reason, Verdict, fmt_duration, fmt_when};

const COOKIE: &str = "sundial_session";

/// One computer on the page.
pub struct Section {
    /// Empty on the computer itself; the computer's id on a server.
    pub key: String,
    /// Heading above its accounts; None = no heading.
    pub title: Option<String>,
    /// A line under the heading, such as "offline since ...".
    pub note: Option<String>,
    pub status: AdminResponse,
}

/// Where the page gets its data and sends changes.
pub trait Backend: Send + Sync + 'static {
    /// After the page title, such as "on family-pc".
    fn subtitle(&self) -> String;
    fn sections(&self) -> Vec<Section>;
    /// Ok = message for the parent.
    fn handle(&self, key: &str, req: AdminRequest) -> Result<String, String>;
    /// Shown on the sign-in page while there are no logins.
    fn passwd_command(&self) -> &'static str;
    /// HTML shown after the accounts.
    fn extra(&self) -> String {
        String::new()
    }
}

#[derive(Clone)]
pub struct App {
    pub backend: Arc<dyn Backend>,
    pub auth: Arc<Auth>,
}

/// Serve with connect info; the sign-in lockout needs the peer's address.
pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/act", post(act))
        .route("/settings", post(settings))
        .route("/api/status", get(api_status))
        .with_state(app)
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

pub fn signed_in(app: &App, headers: &HeaderMap) -> Option<String> {
    cookie_token(headers).and_then(|t| app.auth.check(&t, Local::now().timestamp()))
}

/// Reject cross-site form posts: the Origin (or Referer) must match the Host.
/// HTTP/2 carries the host in `:authority` (the URI), HTTP/1.1 in the Host header.
pub fn same_origin(headers: &HeaderMap, uri: &Uri) -> bool {
    let host = uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let src = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let src_host = src
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    !host.is_empty() && src_host == host
}

pub fn security_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("referrer-policy", "same-origin".parse().unwrap());
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    r
}

#[derive(Deserialize, Default)]
struct IndexQuery {
    msg: Option<String>,
    err: Option<String>,
}

async fn index(
    State(app): State<App>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let page = match signed_in(&app, &headers) {
        None => login_page(
            q.err.as_deref(),
            app.auth.has_admins(),
            app.backend.passwd_command(),
        ),
        Some(parent) => dashboard(
            &parent,
            app.backend.as_ref(),
            q.msg.as_deref(),
            q.err.as_deref(),
        ),
    };
    security_headers(Html(page).into_response())
}

async fn api_status(State(app): State<App>, headers: HeaderMap) -> Response {
    if signed_in(&app, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut s = app.backend.sections();
    if s.len() == 1 && s[0].key.is_empty() {
        return security_headers(Json(s.remove(0).status).into_response());
    }
    let all: HashMap<String, AdminResponse> = s.into_iter().map(|x| (x.key, x.status)).collect();
    security_headers(Json(all).into_response())
}

#[derive(Deserialize)]
struct LoginForm {
    user: String,
    password: String,
}

async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    if !same_origin(&headers, &uri) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let now = Local::now().timestamp();
    let ip = peer.ip();
    if app.auth.throttled(ip, now) {
        return Redirect::to("/?err=Too%20many%20tries.%20Wait%2015%20minutes.").into_response();
    }
    let auth = app.auth.clone();
    let (user, pw) = (f.user.trim().to_string(), f.password);
    // Argon2 is deliberately slow; keep it off the async workers.
    let token = tokio::task::spawn_blocking(move || auth.login(ip, &user, &pw, now))
        .await
        .ok()
        .flatten();
    match token {
        Some(t) => {
            let cookie = format!(
                "{COOKIE}={t}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                SESSION_DAYS * 86_400
            );
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        None => {
            println!("sundial: failed web sign-in from {ip}");
            Redirect::to("/?err=Wrong%20name%20or%20password.").into_response()
        }
    }
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_token(&headers) {
        app.auth.logout(&t);
    }
    let clear = format!("{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    ([(header::SET_COOKIE, clear)], Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
struct ActForm {
    user: String,
    action: String,
    at: Option<String>,
    lock_in: Option<u32>,
    lock_for: Option<String>,
}

/// "21:30" -> the next time it is 21:30 local.
fn next_clock(hhmm: &str) -> Option<i64> {
    let t = NaiveTime::parse_from_str(hhmm.trim(), "%H:%M").ok()?;
    let now = Local::now();
    let mut d = now.date_naive();
    loop {
        let ts = Local
            .from_local_datetime(&d.and_time(t))
            .earliest()?
            .timestamp();
        if ts > now.timestamp() {
            return Some(ts);
        }
        d = d.succ_opt()?;
    }
}

fn parse_action(f: &ActForm) -> Result<Override, &'static str> {
    let now = Local::now().timestamp();
    Ok(match f.action.as_str() {
        "grant15" => Override::Grant { minutes: 15 },
        "grant30" => Override::Grant { minutes: 30 },
        "grant60" => Override::Grant { minutes: 60 },
        "end_break" => Override::EndBreak,
        "allow_until" => Override::AllowUntil {
            at: f
                .at
                .as_deref()
                .and_then(next_clock)
                .ok_or("Pick a time to allow until.")?,
        },
        "lock" => {
            let until = match f.lock_for.as_deref().unwrap_or("rest") {
                "rest" => None,
                m => Some(
                    now + i64::from(f.lock_in.unwrap_or(0))
                        + m.parse::<i64>().map_err(|_| "Bad lock length.")? * 60,
                ),
            };
            Override::Lock {
                in_secs: f.lock_in.unwrap_or(300).min(3600),
                until,
            }
        }
        "clear" => Override::Clear,
        "take15" => Override::TakeTime { minutes: 15 },
        _ => return Err("Unknown action."),
    })
}

pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// "computer/account" on a server, just "account" on the computer itself. Account names
/// never contain a slash.
fn split_key(v: &str) -> (&str, &str) {
    v.rsplit_once('/').unwrap_or(("", v))
}

/// Safe in an HTML id.
fn html_id(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn back(user: &str, r: Result<String, String>) -> Response {
    let target = match r {
        Ok(m) => format!("/?msg={}", enc(&format!("{user}: {m}"))),
        Err(e) => format!("/?err={}", enc(&e)),
    };
    Redirect::to(&target).into_response()
}

async fn act(
    State(app): State<App>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<ActForm>,
) -> Response {
    if !same_origin(&headers, &uri) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(parent) = signed_in(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (key, user) = split_key(&f.user);
    let r = parse_action(&f).map_err(String::from).and_then(|action| {
        let req = AdminRequest::Act {
            user: user.to_string(),
            by: parent,
            action,
        };
        app.backend.handle(key, req)
    });
    back(user, r)
}

async fn settings(
    State(app): State<App>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    if !same_origin(&headers, &uri) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(parent) = signed_in(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let target = f.get("user").cloned().unwrap_or_default();
    let (key, user) = split_key(&target);
    let r = parse_settings(&f).and_then(|policy| {
        let req = AdminRequest::SetPolicy {
            user: user.to_string(),
            by: parent,
            policy,
        };
        app.backend.handle(key, req)
    });
    back(user, r)
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub const STYLE: &str = r#"
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d1b16;--muted:#6b665c;--line:#e4dfd4;--accent:#c47a12;--ok:#2e7d4f;--stop:#b3261e;--wait:#8a6d1d}
@media (prefers-color-scheme:dark){:root{--bg:#16150f;--card:#211f18;--ink:#eee9dd;--muted:#a39d8f;--line:#38342a;--accent:#e6a23c;--ok:#5cc28a;--stop:#ef7b72;--wait:#d8b24a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:720px;margin:0 auto;padding:20px 16px 48px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
h1{font-size:22px;margin:0;display:flex;align-items:center;gap:8px}h1 span{color:var(--accent)}
h2{font-size:20px;margin:0 0 4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.pill{font-size:13px;font-weight:600;padding:2px 10px;border-radius:99px;border:1px solid currentColor}
.ok{color:var(--ok)}.stop{color:var(--stop)}.wait{color:var(--wait)}
.big{font-size:18px;margin:6px 0 12px}
.meta{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;color:var(--muted);font-size:14px;margin:0 0 14px}.meta dd{margin:0;color:var(--ink)}
.bar{height:8px;border-radius:9px;background:var(--line);overflow:hidden;margin:0 0 14px}.bar i{display:block;height:100%;background:var(--accent)}
form{margin:0}.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px}
button,input,select{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:8px 12px}
button{cursor:pointer;font-weight:600}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--stop);border-color:var(--stop)}
label{color:var(--muted);font-size:14px}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:16px;border:1px solid var(--ok);color:var(--ok)}.flash.err{border-color:var(--stop);color:var(--stop)}
.log{list-style:none;padding:0;margin:0;font-size:14px}.log li{padding:6px 0;border-top:1px solid var(--line)}.log time{color:var(--muted);margin-right:8px}
.login{max-width:360px;margin:12vh auto 0}.login input{width:100%;margin-bottom:10px}.login button{width:100%}
.muted{color:var(--muted);font-size:14px}
h3{font-size:16px;margin:18px 0 6px;padding-top:12px;border-top:1px solid var(--line)}
.acts{list-style:none;padding:0;margin:0}.acts>li{margin-bottom:10px}.acts .bar{margin:4px 0}
.actrow{display:flex;justify-content:space-between;gap:12px}
details{margin-top:6px}summary{cursor:pointer;color:var(--muted);font-size:14px}
details ol{margin:6px 0 0;padding-left:22px;font-size:14px}details li{margin:2px 0}
table{border-collapse:collapse;font-size:14px}td,th{padding:4px 10px 4px 0;text-align:left}
.settings{margin-top:16px;padding-top:12px;border-top:1px solid var(--line)}.settings summary{font-size:16px;color:var(--ink);font-weight:600}
.days input[type=time]{padding:6px 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px}.grid label{display:flex;flex-direction:column;gap:4px}
.grid input,.grid select{width:100%}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px 20px;flex-wrap:wrap}
.usage{flex:0 1 300px;min-width:0;width:300px;max-width:100%;position:relative}
.usage>input{position:absolute;opacity:0;pointer-events:none}
.usage>label{display:inline-block;font-size:13px;font-weight:600;padding:2px 12px;border:1px solid var(--line);color:var(--muted);cursor:pointer}
.usage>label[for^=ud]{border-radius:99px 0 0 99px}.usage>label[for^=uw]{border-radius:0 99px 99px 0;margin-left:-1px}
.usage>input:checked+label{background:var(--accent);border-color:var(--accent);color:#fff}
.usage>input:focus-visible+label{outline:2px solid var(--accent);outline-offset:2px}
.usage .cw,.usage .tw:checked~.cd{display:none}.usage .tw:checked~.cw{display:block}
.usage .note{margin:6px 0 2px;font-size:13px;color:var(--muted)}
.usage svg{display:block;width:100%;height:auto}
.usage .axis{font-size:10px;fill:var(--muted)}.usage .grid{stroke:var(--line);stroke-dasharray:3 3}.usage .base{stroke:var(--line)}
.usage .past{fill:var(--accent);opacity:.5}.usage .cur{fill:var(--accent)}.usage .hit{fill:transparent}
h2.host{margin:24px 0 8px}
.code{font:600 22px/1.3 ui-monospace,monospace;letter-spacing:.04em}
.usage g:hover .past{opacity:.8}
"#;

pub fn shell(title: &str, body: &str, refresh: bool) -> String {
    let script = if refresh {
        // Reload every 30 s unless the parent is typing or picking something.
        "<script>try{for(const i of document.querySelectorAll('.usage input')){if(sessionStorage.getItem(i.name)===i.id)i.checked=true;i.addEventListener('change',()=>sessionStorage.setItem(i.name,i.id))}}catch(e){}\
         setInterval(()=>{const a=document.activeElement;if(!a||a===document.body||a.matches('.usage input'))location.reload()},30000)</script>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><meta name=color-scheme content=\"light dark\">\
         <link rel=icon href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ccircle cx='8' cy='8' r='7' fill='%23c47a12'/%3E%3Cpath d='M8 8V3' stroke='white' stroke-width='1.6'/%3E%3C/svg%3E\">\
         <style>{STYLE}</style></head><body><main>{body}</main>{script}</body></html>",
        esc(title)
    )
}

fn login_page(err: Option<&str>, has_admins: bool, command: &str) -> String {
    let flash = err
        .map(|e| format!("<div class='flash err'>{}</div>", esc(e)))
        .unwrap_or_default();
    let hint = if has_admins {
        String::new()
    } else {
        format!(
            "<p class=muted>No parent logins yet. On this computer run <code>{}</code>.</p>",
            esc(command)
        )
    };
    shell(
        "Sundial",
        &format!(
            "<div class='card login'><h1>☀ <span>Sundial</span></h1><p class=muted>Parent sign-in</p>{flash}\
             <form method=post action=/login><input name=user placeholder=Name autocomplete=username autocapitalize=none required>\
             <input name=password type=password placeholder=Password autocomplete=current-password required>\
             <button class=primary>Sign in</button></form>{hint}</div>"
        ),
        false,
    )
}

fn pill(u: &UserStatus) -> (&'static str, &'static str) {
    match u.verdict {
        Verdict::Allowed { .. } if u.deadline.is_some() => ("Time almost up", "wait"),
        Verdict::Allowed { .. } => ("Allowed", "ok"),
        Verdict::Blocked {
            reason: Reason::Break,
            ..
        } => ("On a break", "wait"),
        Verdict::Blocked {
            reason: Reason::OutsideHours,
            ..
        } => ("Outside hours", "stop"),
        Verdict::Blocked {
            reason: Reason::ParentLock,
            ..
        } => ("Locked by parent", "stop"),
    }
}

fn user_card(u: &UserStatus, key: &str, now: &chrono::DateTime<Local>) -> String {
    let (label, class) = pill(u);
    let name = esc(&u.name);
    let key = esc(key);
    let id = html_id(&key);
    let mut meta = String::new();
    let mut add = |k: &str, v: String| meta.push_str(&format!("<dt>{k}</dt><dd>{}</dd>", esc(&v)));
    if u.session_secs > 0 {
        add(
            "This session",
            format!(
                "{} of {} used",
                fmt_duration(u.used_secs as i64),
                fmt_duration(u.session_secs as i64)
            ),
        );
    }
    add(
        "Today",
        format!("{} of active use", fmt_duration(u.today_active_secs as i64)),
    );
    add("Hours today", u.schedule_today.clone());
    if let Some(b) = u.break_until {
        add("Break ends", fmt_when(b, now));
    }
    if let Some(a) = u.allow_until {
        add("Extra time until", fmt_when(a, now));
    }
    if let Some(b) = u.block {
        add(
            "Parent lock",
            format!("{} to {}", fmt_when(b.from, now), fmt_when(b.until, now)),
        );
    }
    let sess = if u.sessions.is_empty() {
        "not signed in".to_string()
    } else {
        u.sessions
            .iter()
            .map(|s| {
                let st = if !s.active {
                    "in background"
                } else if s.locked {
                    "locked"
                } else if s.idle {
                    "idle"
                } else {
                    "in use"
                };
                format!(
                    "{} ({st})",
                    if s.kind.is_empty() {
                        "session"
                    } else {
                        &s.kind
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    add("Signed in", sess);
    let pct = (u.used_secs * 100)
        .checked_div(u.session_secs)
        .unwrap_or(0)
        .min(100);
    let bar = if u.session_secs > 0 {
        format!("<div class=bar><i style='width:{pct}%'></i></div>")
    } else {
        String::new()
    };
    let end_break = if u.break_until.is_some() {
        "<button name=action value=end_break>End break</button>"
    } else if u.session_secs > 0 && u.used_secs > 0 {
        "<button name=action value=end_break>Reset session</button>"
    } else {
        ""
    };
    let clear = if u.allow_until.is_some() || u.block.is_some() {
        format!(
            "<form method=post action=/act class=row><input type=hidden name=user value=\"{key}\">\
             <button name=action value=clear>Clear parent overrides</button></form>"
        )
    } else {
        String::new()
    };
    format!(
        "<section class=card><div class=top><h2>{name} <span class='pill {class}'>{label}</span></h2>{}</div>\
         <p class=big>{}</p>{bar}<dl class=meta>{meta}</dl>\
         <form method=post action=/act class=row><input type=hidden name=user value=\"{key}\">\
           <button class=primary name=action value=grant15>+15 min</button>\
           <button class=primary name=action value=grant30>+30 min</button>\
           <button class=primary name=action value=grant60>+1 hour</button>\
           <button name=action value=take15>&minus;15 min</button>{end_break}</form>\
         <form method=post action=/act class=row><input type=hidden name=user value=\"{key}\">\
           <label for=at-{id}>Allow until</label><input id=at-{id} type=time name=at required>\
           <button name=action value=allow_until>Allow</button></form>\
         <form method=post action=/act class=row><input type=hidden name=user value=\"{key}\">\
           <label>Lock</label><select name=lock_in><option value=300>in 5 min (countdown)</option><option value=0>now (1 min notice)</option></select>\
           <label>until</label><select name=lock_for><option value=rest>tomorrow's start</option><option value=30>30 min</option><option value=60>1 hour</option><option value=120>2 hours</option></select>\
           <button class=danger name=action value=lock>Lock</button></form>{clear}{}{}</section>",
        usage_html(u, &id),
        esc(&u.summary),
        activity_html(u),
        settings_html(u, &key),
    )
}

fn activity_html(u: &UserStatus) -> String {
    if !u.track_activity {
        return String::new();
    }
    let mut h = String::from("<h3>Activity</h3>");
    match u.tracking {
        Tracking::NoAgent => h.push_str(
            "<p class='flash err'>Activity tracking isn't running: the Sundial agent isn't connected in the \
             signed-in session. It was closed, or the session started before Sundial was installed.</p>",
        ),
        Tracking::NoExtension => h.push_str(&format!(
            "<p class='flash err'>Activity tracking isn't running: the agent is connected but can't see which \
             window is in front ({}). On GNOME the Sundial extension loads at the next sign-in; on other \
             desktops see the README's desktop list.</p>",
            esc(u.tracking_source.as_deref().unwrap_or("no source"))
        )),
        _ => {}
    }
    if let Some(now) = &u.now_doing {
        h.push_str(&format!(
            "<p><span class=muted>Right now:</span> {}</p>",
            esc(now)
        ));
    }
    if u.activity_today.is_empty() {
        h.push_str("<p class=muted>Nothing recorded today.</p>");
    } else {
        let max = u.activity_today.first().map(|a| a.secs).unwrap_or(1).max(1);
        h.push_str("<ul class=acts>");
        for a in &u.activity_today {
            let pct = a.secs * 100 / max;
            h.push_str(&format!(
                "<li><div class=actrow><span>{}</span><b>{}</b></div><div class=bar><i style='width:{pct}%'></i></div>",
                esc(&a.name),
                fmt_duration(a.secs as i64)
            ));
            if !a.details.is_empty() {
                h.push_str("<details><summary>Top titles</summary><ol>");
                for (title, secs) in &a.details {
                    h.push_str(&format!(
                        "<li>{} <span class=muted>{}</span></li>",
                        esc(title),
                        fmt_duration(*secs as i64)
                    ));
                }
                h.push_str("</ol></details>");
            }
            h.push_str("</li>");
        }
        h.push_str("</ul>");
    }
    if !u.activity_week.is_empty() {
        h.push_str("<details><summary>Last 7 days</summary><table class=week>");
        for a in &u.activity_week {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                esc(&a.name),
                fmt_duration(a.secs as i64)
            ));
        }
        h.push_str("</table></details>");
    }
    h
}

/// Usage report beside the name: active time per day (14 days) or per week (8 weeks),
/// switched with CSS-only tabs.
fn usage_html(u: &UserStatus, id: &str) -> String {
    if u.usage_days.is_empty() {
        return String::new();
    }
    let parse = |d: &str| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok();
    let day_bars: Vec<(String, String, u64)> = u
        .usage_days
        .iter()
        .map(|b| {
            let d = parse(&b.date);
            (
                d.map(|d| d.format("%a").to_string()[..1].to_string())
                    .unwrap_or_default(),
                d.map(|d| d.format("%a %b %-d").to_string())
                    .unwrap_or_default(),
                b.secs,
            )
        })
        .collect();
    let week_bars: Vec<(String, String, u64)> = u
        .usage_weeks
        .iter()
        .map(|b| {
            let d = parse(&b.date);
            (
                d.map(|d| d.format("%-m/%-d").to_string())
                    .unwrap_or_default(),
                d.map(|d| format!("Week of {}", d.format("%b %-d")))
                    .unwrap_or_default(),
                b.secs,
            )
        })
        .collect();
    let today = u.usage_days.last().map_or(0, |b| b.secs);
    let week = u.usage_weeks.last().map_or(0, |b| b.secs);
    let used = |secs: u64| {
        if secs == 0 {
            "none yet".to_string()
        } else {
            fmt_duration(secs as i64)
        }
    };
    let day_note = format!("Today {}{}", used(today), avg_note(&u.usage_days, "day"));
    let week_note = format!(
        "This week {}{}",
        used(week),
        avg_note(&u.usage_weeks, "week")
    );
    format!(
        "<div class=usage role=group aria-label='Computer time'>\
         <input type=radio name=u-{id} id=ud-{id} class=td checked><label for=ud-{id}>Day</label>\
         <input type=radio name=u-{id} id=uw-{id} class=tw><label for=uw-{id}>Week</label>\
         <div class=cd><p class=note>{}</p>{}</div><div class=cw><p class=note>{}</p>{}</div></div>",
        esc(&day_note),
        bar_svg(&day_bars, "Active time per day, last 14 days"),
        esc(&week_note),
        bar_svg(&week_bars, "Active time per week, last 8 weeks"),
    )
}

/// " · avg 52 min/day", counted from the first bar with any use, excluding the
/// current (unfinished) one.
fn avg_note(bars: &[UsageBar], unit: &str) -> String {
    let done = &bars[..bars.len().saturating_sub(1)];
    let Some(first) = done.iter().position(|b| b.secs > 0) else {
        return String::new();
    };
    let span = &done[first..];
    let avg = span.iter().map(|b| b.secs).sum::<u64>() / span.len() as u64;
    format!(" · avg {}/{unit}", fmt_duration(avg as i64))
}

/// Small bar chart: (axis label, tooltip, seconds); the last bar is the current one.
fn bar_svg(bars: &[(String, String, u64)], title: &str) -> String {
    const W: f64 = 300.0;
    const TOP: f64 = 14.0;
    const BASE: f64 = 86.0;
    let max = bars.iter().map(|b| b.2).max().unwrap_or(0);
    let hours = max.div_ceil(3600).max(1);
    let scale = (hours * 3600) as f64;
    let slot = W / bars.len().max(1) as f64;
    let bw = (slot * 0.64).min(26.0);
    // Every attribute is quoted: in HTML an unquoted value before "/>" takes the slash.
    let mut out = format!(
        "<svg viewBox=\"0 0 {W} 104\" role=\"img\" aria-label=\"{t}\"><title>{t}</title>\
         <line class=\"grid\" x1=\"0\" x2=\"{W}\" y1=\"{TOP}\" y2=\"{TOP}\"></line>\
         <text class=\"axis\" x=\"{W}\" y=\"{y}\" text-anchor=\"end\">{hours} h</text>\
         <line class=\"base\" x1=\"0\" x2=\"{W}\" y1=\"{BASE}\" y2=\"{BASE}\"></line>",
        t = esc(title),
        y = TOP - 4.0,
    );
    for (i, (label, tip, secs)) in bars.iter().enumerate() {
        let h = if *secs > 0 {
            ((BASE - TOP) * *secs as f64 / scale).max(1.5)
        } else {
            0.0
        };
        let left = slot * i as f64;
        let x = left + (slot - bw) / 2.0;
        let cls = if i + 1 == bars.len() { "cur" } else { "past" };
        let shown = if *secs == 0 {
            "no use".to_string()
        } else {
            fmt_duration(*secs as i64)
        };
        out.push_str(&format!(
            "<g><title>{}: {shown}</title>\
             <rect class=\"hit\" x=\"{left:.1}\" y=\"{TOP}\" width=\"{slot:.1}\" height=\"{:.1}\"></rect>\
             <rect class=\"{cls}\" x=\"{x:.1}\" y=\"{:.1}\" width=\"{bw:.1}\" height=\"{h:.1}\" rx=\"2\"></rect>\
             <text class=\"axis\" x=\"{:.1}\" y=\"100\" text-anchor=\"middle\">{}</text></g>",
            esc(tip),
            BASE - TOP,
            BASE - h,
            x + bw / 2.0,
            esc(label),
        ));
    }
    out.push_str("</svg>");
    out
}

/// "HH:MM" for a time input; end of day (24:00) shows as 00:00.
fn hhmm(min: u32) -> String {
    let m = min % 1440;
    format!("{:02}:{:02}", m / 60, m % 60)
}

fn settings_html(u: &UserStatus, key: &str) -> String {
    let p = &u.policy;
    let mut rows = String::new();
    for (i, (key, label)) in DAY_KEYS.iter().zip(DAY_LABELS).enumerate() {
        let w = p.days[i];
        let (on, start, end) = match w {
            Some(w) => ("checked", hhmm(w.start), hhmm(w.end)),
            None => ("", "08:00".into(), "20:00".into()),
        };
        rows.push_str(&format!(
            "<tr><td><label><input type=checkbox name=on_{key} {on}> {label}</label></td>\
             <td><input type=time name=start_{key} value={start} required></td>\
             <td><input type=time name=end_{key} value={end} required></td></tr>"
        ));
    }
    let sel = |a: Action| if p.action == a { "selected" } else { "" };
    format!(
        "<details class=settings><summary>Hours &amp; limits</summary>\
         <form method=post action=/settings><input type=hidden name=user value=\"{key}\">\
         <table class=days><tr><th>Day</th><th>Start</th><th>Stop</th></tr>{rows}</table>\
         <p class=muted>Unchecked = no access that day. A stop time of 00:00 means midnight.</p>\
         <div class=grid>\
           <label>Minutes on <input type=number name=session_minutes min=0 max=1440 value={}></label>\
           <label>Break minutes <input type=number name=break_minutes min=1 max=1440 value={}></label>\
           <label>Countdown minutes <input type=number name=warn_minutes min=1 max=60 value={}></label>\
           <label>When time is up <select name=action><option value=logout {}>Log out</option><option value=lock {}>Lock screen</option></select></label>\
         </div><p class=muted>Minutes on = 0 turns off the session limit (hours still apply).</p>\
         <div class=row><button class=primary>Save</button></div></form></details>",
        p.session_minutes,
        p.break_minutes,
        p.warn_minutes,
        sel(Action::Logout),
        sel(Action::Lock),
    )
}

const DAY_LABELS: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

fn parse_minutes(v: Option<&String>, end: bool) -> Option<u32> {
    let t = NaiveTime::parse_from_str(v?.trim(), "%H:%M").ok()?;
    let m = t.hour() * 60 + t.minute();
    Some(if end && m == 0 { 1440 } else { m })
}

fn parse_settings(f: &HashMap<String, String>) -> Result<PolicyUpdate, String> {
    let num = |k: &str| -> Result<u32, String> {
        f.get(k)
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| format!("{k}: enter a number"))
    };
    let mut days = [None; 7];
    for (i, key) in DAY_KEYS.iter().enumerate() {
        if !f.contains_key(&format!("on_{key}")) {
            continue;
        }
        let start = parse_minutes(f.get(&format!("start_{key}")), false)
            .ok_or(format!("{}: bad start time", DAY_LABELS[i]))?;
        let end = parse_minutes(f.get(&format!("end_{key}")), true)
            .ok_or(format!("{}: bad stop time", DAY_LABELS[i]))?;
        if end <= start {
            return Err(format!("{}: stop must be after start", DAY_LABELS[i]));
        }
        days[i] = Some(Window { start, end });
    }
    let warn = num("warn_minutes")?;
    if !(1..=60).contains(&warn) {
        return Err("Countdown must be 1 to 60 minutes.".into());
    }
    Ok(PolicyUpdate {
        session_minutes: num("session_minutes")?,
        break_minutes: num("break_minutes")?.max(1),
        warn_minutes: warn,
        action: if f.get("action").map(String::as_str) == Some("lock") {
            Action::Lock
        } else {
            Action::Logout
        },
        days,
    })
}

fn dashboard(parent: &str, backend: &dyn Backend, msg: Option<&str>, err: Option<&str>) -> String {
    let now = Local::now();
    let mut body = format!(
        "<header><h1>☀ <span>Sundial</span> <small class=muted>{}</small></h1>\
         <form method=post action=/logout><button>Sign out {}</button></form></header>",
        esc(&backend.subtitle()),
        esc(parent)
    );
    if let Some(m) = msg {
        body.push_str(&format!("<div class=flash>{}</div>", esc(m)));
    }
    if let Some(e) = err {
        body.push_str(&format!("<div class='flash err'>{}</div>", esc(e)));
    }
    for s in backend.sections() {
        if let Some(t) = &s.title {
            body.push_str(&format!("<h2 class=host>{}</h2>", esc(t)));
        }
        if let Some(n) = &s.note {
            body.push_str(&format!("<p class=muted>{}</p>", esc(n)));
        }
        if s.status.users.is_empty() {
            body.push_str("<section class=card>No accounts are managed. Add one to <code>/etc/sundial/config.toml</code> on the computer.</section>");
        }
        for u in &s.status.users {
            let key = if s.key.is_empty() {
                u.name.clone()
            } else {
                format!("{}/{}", s.key, u.name)
            };
            body.push_str(&user_card(u, &key, &now));
        }
        if !s.status.log.is_empty() {
            body.push_str("<section class=card><h2>Recent</h2><ul class=log>");
            for e in s.status.log.iter().take(25) {
                body.push_str(&format!(
                    "<li><time>{}</time><b>{}</b> {}</li>",
                    esc(&fmt_when(e.ts, &now)),
                    esc(&e.user),
                    esc(&e.text)
                ));
            }
            body.push_str("</ul></section>");
        }
    }
    body.push_str(&backend.extra());
    body.push_str(&format!(
        "<p class=muted>Updated {}</p>",
        now.format("%-I:%M:%S %p")
    ));
    shell("Sundial", &body, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(k.clone(), v.parse().unwrap());
        }
        m
    }

    #[test]
    fn origin_check() {
        let plain: Uri = "/act".parse().unwrap();
        let h2: Uri = "https://pc:8461/act".parse().unwrap();
        // HTTP/1.1: Host header.
        assert!(same_origin(
            &h(&[
                (header::HOST, "pc:8461"),
                (header::ORIGIN, "https://pc:8461")
            ]),
            &plain
        ));
        // HTTP/2: authority in the URI, no Host header.
        assert!(same_origin(&h(&[(header::ORIGIN, "https://pc:8461")]), &h2));
        assert!(same_origin(
            &h(&[(header::REFERER, "https://pc:8461/?msg=x")]),
            &h2
        ));
        assert!(!same_origin(
            &h(&[(header::ORIGIN, "https://evil.example")]),
            &h2
        ));
        assert!(!same_origin(&h(&[]), &h2));
        assert!(!same_origin(
            &h(&[(header::ORIGIN, "https://pc:8461")]),
            &plain
        ));
    }
}
