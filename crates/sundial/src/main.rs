//! `sundial`: the daemon, the PAM login check, and the admin CLI.

mod daemon;
mod link;
mod logind;
mod sys;
mod web;

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveTime, TimeZone};
use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use sundial_core::config::{
    ADMIN_SOCKET, Config, DEFAULT_ADMINS_PATH, DEFAULT_CONFIG_PATH, DEFAULT_STATE_PATH,
};
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_core::rules::{self, Override, fmt_duration, fmt_when};
use sundial_core::state::State;

#[derive(Parser)]
#[command(
    name = "sundial",
    version,
    about = "Screen time limits for Linux desktop accounts"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (systemd starts this as root).
    Daemon {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
        /// Don't start the web page.
        #[arg(long)]
        no_web: bool,
    },
    /// PAM account check: exit 1 if PAM_USER (or USER) may not sign in now.
    CheckLogin {
        /// Account to check; defaults to $PAM_USER.
        user: Option<String>,
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Check a config file and print each account's weekly schedule.
    CheckConfig {
        #[arg(default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Set (or delete) a parent login for the web page.
    Passwd {
        name: String,
        #[arg(long)]
        delete: bool,
        /// Read the password from the first line of stdin (for scripts and Ansible).
        #[arg(long, conflicts_with = "delete")]
        stdin: bool,
    },
    /// Connect this computer to a Sundial Server (get the code there).
    Pair {
        /// Server address, for example sundial.example.com or 192.168.1.5:8461.
        server: String,
        code: String,
    },
    /// Disconnect from the Sundial Server.
    Unpair,
    /// Show each managed account's status and recent events.
    Status,
    /// Give extra minutes now (on top of any time left).
    Grant { user: String, minutes: u32 },
    /// Take minutes off the current session (the countdown is always left).
    Take { user: String, minutes: u32 },
    /// End the current break (or reset the session); a fresh session starts.
    EndBreak { user: String },
    /// Allow use until a clock time (HH:MM), regardless of rules.
    AllowUntil { user: String, time: String },
    /// Lock the account. Default: 5 minute countdown, until tomorrow's start.
    Lock {
        user: String,
        /// Skip the 5 minute countdown (a 1 minute notice still applies).
        #[arg(long)]
        now: bool,
        /// Lock until this clock time (HH:MM) instead of tomorrow's start.
        #[arg(long)]
        until: Option<String>,
    },
    /// Remove parent overrides (extra time and locks).
    Clear { user: String },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("sundial: {e:#}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon {
            config,
            state,
            no_web,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(daemon::run(config, state, !no_web))
        }
        Cmd::CheckLogin {
            user,
            config,
            state,
        } => check_login(user, config, state),
        Cmd::CheckConfig { config } => check_config(config),
        Cmd::Passwd {
            name,
            delete,
            stdin,
        } => passwd(&name, delete, stdin),
        Cmd::Pair { server, code } => {
            tokio::runtime::Runtime::new()?.block_on(link::pair(&server, &code))
        }
        Cmd::Unpair => link::unpair(),
        Cmd::Status => print_status(send(AdminRequest::Status)?),
        Cmd::Grant { user, minutes } => act(user, Override::Grant { minutes }),
        Cmd::Take { user, minutes } => act(user, Override::TakeTime { minutes }),
        Cmd::EndBreak { user } => act(user, Override::EndBreak),
        Cmd::AllowUntil { user, time } => act(
            user,
            Override::AllowUntil {
                at: next_clock(&time)?,
            },
        ),
        Cmd::Lock { user, now, until } => {
            let until = until.map(|t| next_clock(&t)).transpose()?;
            act(
                user,
                Override::Lock {
                    in_secs: if now { 0 } else { 300 },
                    until,
                },
            )
        }
        Cmd::Clear { user } => act(user, Override::Clear),
    }
}

/// Evaluated from the files directly, so logins are still checked if the daemon is down.
/// Only accounts in the `sundial-managed` group get here (see packaging/pam-config).
fn check_login(user: Option<String>, config: PathBuf, state: PathBuf) -> Result<()> {
    let user = user
        .or_else(|| std::env::var("PAM_USER").ok())
        .context("no user (set PAM_USER)")?;
    let cfg = match Config::load(&config) {
        Ok(c) => c,
        Err(e) => {
            // Fail closed: this account is in the managed group, so it is meant to be limited.
            println!("Sundial can't read its settings; ask a parent.");
            bail!("{e}");
        }
    };
    let Some(p) = cfg.user(&user) else {
        return Ok(());
    };
    let st = State::load(&state).unwrap_or_default();
    let us = st.users.get(&user).cloned().unwrap_or_default();
    let now = Local::now();
    let v = rules::evaluate(p, &us, &now);
    if v.is_allowed() {
        return Ok(());
    }
    println!("{}", rules::describe(&v, &now));
    std::process::exit(1);
}

fn check_config(path: PathBuf) -> Result<()> {
    let cfg = Config::load(&path).map_err(anyhow::Error::msg)?;
    println!("{}: OK", path.display());
    println!(
        "web: {} ({})",
        cfg.web.listen,
        if cfg.web.enabled { "on" } else { "off" }
    );
    for u in &cfg.users {
        println!(
            "\n{}: {} min on, {} min break, {} min warning, then {:?}",
            u.name, u.session_minutes, u.break_minutes, u.warn_minutes, u.action
        );
        for (i, d) in sundial_core::config::DAY_KEYS.iter().enumerate() {
            let w = u.schedule.days[i]
                .map(|w| w.to_string())
                .unwrap_or_else(|| "no access".into());
            println!("  {d}  {w}");
        }
    }
    Ok(())
}

fn passwd(name: &str, delete: bool, stdin: bool) -> Result<()> {
    if name.is_empty() || name.contains(':') || name.contains(char::is_whitespace) {
        bail!("name can't be empty or contain ':' or spaces");
    }
    let path = PathBuf::from(DEFAULT_ADMINS_PATH);
    let mut admins = sundial_web::auth::read_admins(&path);
    if delete {
        if admins.remove(name).is_none() {
            bail!("no login named {name}");
        }
        sundial_web::auth::write_admins(&path, &admins).context("writing admins (run as root)")?;
        println!("Removed {name}.");
        return Ok(());
    }
    let pw = if stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password(format!("New password for {name}: "))?
    };
    if pw.chars().count() < 8 {
        bail!("use at least 8 characters");
    }
    if !stdin && rpassword::prompt_password("Again: ")? != pw {
        bail!("passwords don't match");
    }
    admins.insert(name.to_string(), sundial_web::auth::hash_password(&pw)?);
    sundial_web::auth::write_admins(&path, &admins).context("writing admins (run as root)")?;
    println!("Saved login {name}.");
    Ok(())
}

fn next_clock(hhmm: &str) -> Result<i64> {
    let t = NaiveTime::parse_from_str(hhmm.trim(), "%H:%M")
        .with_context(|| format!("{hhmm:?}: use HH:MM"))?;
    let now = Local::now();
    let mut d = now.date_naive();
    for _ in 0..2 {
        if let Some(ts) = Local
            .from_local_datetime(&d.and_time(t))
            .earliest()
            .map(|x| x.timestamp())
            && ts > now.timestamp()
        {
            return Ok(ts);
        }
        d = d.succ_opt().context("date overflow")?;
    }
    bail!("{hhmm}: no such time")
}

fn send(req: AdminRequest) -> Result<AdminResponse> {
    let mut s = UnixStream::connect(ADMIN_SOCKET).with_context(|| {
        format!("connecting to {ADMIN_SOCKET} (is the daemon running? are you root?)")
    })?;
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    s.write_all(line.as_bytes())?;
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out)?;
    let resp: AdminResponse = serde_json::from_str(&out).context("bad reply from daemon")?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "failed".into()));
    }
    Ok(resp)
}

fn act(user: String, action: Override) -> Result<()> {
    let by = std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into());
    let resp = send(AdminRequest::Act {
        user: user.clone(),
        by: format!("{by} (cli)"),
        action,
    })?;
    if let Some(m) = &resp.message {
        println!("{user}: {m}");
    }
    print_status(resp)
}

fn print_status(resp: AdminResponse) -> Result<()> {
    let now = Local::now();
    for u in &resp.users {
        println!("\n{}: {}", u.name, u.summary);
        if u.session_secs > 0 {
            println!(
                "  session   {} of {} used",
                fmt_duration(u.used_secs as i64),
                fmt_duration(u.session_secs as i64)
            );
        }
        println!(
            "  today     {} active, hours {}",
            fmt_duration(u.today_active_secs as i64),
            u.schedule_today
        );
        if let Some(b) = u.break_until {
            println!("  break     until {}", fmt_when(b, &now));
        }
        if let Some(a) = u.allow_until {
            println!("  extra     until {}", fmt_when(a, &now));
        }
        if let Some(b) = u.block {
            println!(
                "  lock      {} to {}",
                fmt_when(b.from, &now),
                fmt_when(b.until, &now)
            );
        }
        if let Some(d) = u.deadline {
            println!("  countdown {} left", fmt_duration(d - now.timestamp()));
        }
        if let Some(n) = &u.now_doing {
            println!("  now       {n}");
        }
        for a in u.activity_today.iter().take(8) {
            println!("  activity  {:<16} {}", a.name, fmt_duration(a.secs as i64));
        }
        for s in &u.sessions {
            println!(
                "  session {} {} active={} locked={} idle={}",
                s.id, s.kind, s.active, s.locked, s.idle
            );
        }
    }
    if !resp.log.is_empty() {
        println!("\nrecent:");
        for e in resp.log.iter().take(10) {
            println!("  {:>16}  {}: {}", fmt_when(e.ts, &now), e.user, e.text);
        }
    }
    Ok(())
}
