//! `/etc/sundial/config.toml`: which accounts are managed and their rules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/sundial/config.toml";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/sundial/state.json";
pub const DEFAULT_ADMINS_PATH: &str = "/etc/sundial/admins";
pub const AGENT_SOCKET: &str = "/run/sundial/agent.sock";
pub const ADMIN_SOCKET: &str = "/run/sundial/admin.sock";
pub const MANAGED_GROUP: &str = "sundial-managed";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default, rename = "user")]
    pub users: Vec<UserPolicy>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut seen = std::collections::BTreeSet::new();
        for u in &cfg.users {
            if !seen.insert(u.name.as_str()) {
                return Err(format!("user {} is listed twice", u.name));
            }
            if u.session_minutes > 0 && u.break_minutes == 0 {
                return Err(format!("user {}: break_minutes must be > 0 when session_minutes is set", u.name));
            }
        }
        Ok(cfg)
    }

    pub fn user(&self, name: &str) -> Option<&UserPolicy> {
        self.users.iter().find(|u| u.name == name)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_listen")]
    pub listen: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig { enabled: true, listen: default_listen() }
    }
}

fn default_true() -> bool {
    true
}
fn default_listen() -> String {
    "0.0.0.0:8461".into()
}

/// What happens when time runs out.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// End every session of the account (default).
    #[default]
    Logout,
    /// Lock the screen, and keep re-locking it while blocked. Apps keep running.
    Lock,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPolicy {
    pub name: String,
    /// Active minutes allowed before a break. 0 = no session limit.
    #[serde(default = "default_session")]
    pub session_minutes: u32,
    /// Length of the break after a session.
    #[serde(default = "default_break")]
    pub break_minutes: u32,
    /// Countdown shown before time runs out.
    #[serde(default = "default_warn")]
    pub warn_minutes: u32,
    #[serde(default)]
    pub action: Action,
    #[serde(default)]
    pub schedule: Schedule,
}

fn default_session() -> u32 {
    60
}
fn default_break() -> u32 {
    120
}
fn default_warn() -> u32 {
    5
}

/// Allowed window within one day, in minutes after midnight. `end` may be 1440 (24:00).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: u32,
    pub end: u32,
}

impl Window {
    pub const ALL_DAY: Window = Window { start: 0, end: 1440 };

    pub fn parse(s: &str) -> Result<Window, String> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| format!("{s:?}: expected HH:MM-HH:MM or \"none\""))?;
        let w = Window { start: parse_hhmm(a.trim())?, end: parse_hhmm(b.trim())? };
        if w.end <= w.start {
            return Err(format!("{s:?}: end must be after start (windows can't cross midnight; use 24:00)"));
        }
        Ok(w)
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}-{:02}:{:02}", self.start / 60, self.start % 60, self.end / 60, self.end % 60)
    }
}

fn parse_hhmm(s: &str) -> Result<u32, String> {
    let (h, m) = s.split_once(':').ok_or_else(|| format!("{s:?}: expected HH:MM"))?;
    let h: u32 = h.parse().map_err(|_| format!("{s:?}: bad hour"))?;
    let m: u32 = m.parse().map_err(|_| format!("{s:?}: bad minute"))?;
    if m > 59 || h > 24 || (h == 24 && m != 0) {
        return Err(format!("{s:?}: out of range"));
    }
    Ok(h * 60 + m)
}

pub const DAY_KEYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// Allowed window per weekday (index 0 = Monday). `None` = no access that day.
/// Keys: `mon`..`sun`, plus `default` for days not listed. Missing entirely = all day.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "BTreeMap<String, String>")]
pub struct Schedule {
    pub days: [Option<Window>; 7],
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule { days: [Some(Window::ALL_DAY); 7] }
    }
}

impl TryFrom<BTreeMap<String, String>> for Schedule {
    type Error = String;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self, String> {
        let parse = |v: &str| -> Result<Option<Window>, String> {
            if v.trim().eq_ignore_ascii_case("none") {
                Ok(None)
            } else {
                Window::parse(v).map(Some)
            }
        };
        let default = match map.get("default") {
            Some(v) => parse(v)?,
            None => Some(Window::ALL_DAY),
        };
        let mut days = [default; 7];
        for (k, v) in &map {
            if k == "default" {
                continue;
            }
            let i = DAY_KEYS
                .iter()
                .position(|d| d == k)
                .ok_or_else(|| format!("unknown schedule key {k:?} (use mon..sun or default)"))?;
            days[i] = parse(v)?;
        }
        Ok(Schedule { days })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example() {
        let cfg = Config::parse(
            r#"
            [web]
            listen = "0.0.0.0:9000"

            [[user]]
            name = "kid"
            [user.schedule]
            default = "08:00-20:00"
            fri = "08:00-22:00"
            sat = "08:00-22:00"
            "#,
        )
        .unwrap();
        let u = cfg.user("kid").unwrap();
        assert_eq!(u.session_minutes, 60);
        assert_eq!(u.break_minutes, 120);
        assert_eq!(u.warn_minutes, 5);
        assert_eq!(u.action, Action::Logout);
        assert_eq!(u.schedule.days[0], Some(Window { start: 480, end: 1200 }));
        assert_eq!(u.schedule.days[4], Some(Window { start: 480, end: 1320 }));
        assert_eq!(u.schedule.days[6], Some(Window { start: 480, end: 1200 }));
        assert_eq!(cfg.web.listen, "0.0.0.0:9000");
    }

    #[test]
    fn rejects_bad_windows() {
        assert!(Window::parse("20:00-08:00").is_err());
        assert!(Window::parse("08:00").is_err());
        assert!(Window::parse("08:00-24:01").is_err());
        assert_eq!(Window::parse("00:00-24:00").unwrap(), Window::ALL_DAY);
        assert!(Config::parse("[[user]]\nname='a'\n[user.schedule]\nmonday='08:00-09:00'").is_err());
        assert!(Config::parse("[[user]]\nname='a'\n[[user]]\nname='a'").is_err());
    }

    #[test]
    fn none_day() {
        let cfg = Config::parse("[[user]]\nname='a'\n[user.schedule]\nsun='none'").unwrap();
        assert_eq!(cfg.users[0].schedule.days[6], None);
        assert_eq!(cfg.users[0].schedule.days[0], Some(Window::ALL_DAY));
    }
}
