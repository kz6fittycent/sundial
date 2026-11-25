//! Messages on the daemon's Unix sockets (one JSON object per line).

use crate::activity::Focus;
use crate::config::PolicyUpdate;
use crate::rules::{Override, Verdict};
use crate::state::{Block, LogEntry};
use serde::{Deserialize, Serialize};

/// Daemon -> agent, pushed every tick on `/run/sundial/agent.sock`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentStatus {
    /// False = this account isn't managed; the agent should exit.
    pub managed: bool,
    pub allowed: bool,
    /// Seconds until the current allowed stretch ends (None = no limit).
    pub remaining_secs: Option<i64>,
    /// Set while a countdown runs: unix time the session will be ended or locked.
    pub deadline: Option<i64>,
    /// Kid-readable status line.
    pub message: String,
    /// "logout" or "lock".
    pub action: String,
    /// A parent can see where this computer is; the agent says so.
    #[serde(default)]
    pub location: bool,
}

/// Agent -> daemon, every few seconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AgentReport {
    /// The focused window, if the desktop's focus source answered.
    pub focus: Option<Focus>,
    /// False when the focus source isn't answering (extension disabled, script not
    /// loaded yet, unsupported desktop).
    #[serde(alias = "extension")]
    pub focus_ok: bool,
    /// Where focus comes from: "GNOME extension", "KWin script", "X11", "none".
    pub source: String,
    /// Seconds since the last keyboard/mouse input, when the desktop tells us.
    pub idle_secs: Option<u64>,
    /// A media player (browser video included) is playing.
    pub media_playing: bool,
    /// The desktop's screen locker state, when it tells us.
    pub locked: Option<bool>,
}

/// CLI/web -> daemon on `/run/sundial/admin.sock` (root only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
    Status,
    Act {
        user: String,
        by: String,
        action: Override,
    },
    SetPolicy {
        user: String,
        by: String,
        policy: PolicyUpdate,
    },
    /// Only for hosts whose status has `location`.
    SetLocation {
        by: String,
        on: bool,
    },
    /// Mark where the computer is now. Both only for hosts whose `location` has `places`.
    AddPlace {
        by: String,
        name: String,
    },
    RemovePlace {
        by: String,
        name: String,
    },
}

/// A position. Only the latest is ever kept.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: f64,
    pub at: i64,
}

impl Fix {
    pub fn valid(&self) -> bool {
        (-90.0..=90.0).contains(&self.lat)
            && (-180.0..=180.0).contains(&self.lon)
            && self.accuracy_m.is_finite()
            && self.accuracy_m >= 0.0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Location {
    pub on: bool,
    pub fix: Option<Fix>,
    /// Why there is no newer position.
    pub problem: Option<String>,
    /// Names of the marked places. Absent from hosts without them.
    #[serde(default)]
    pub places: Option<Vec<String>>,
    /// The marked place it is at, as of `looked`.
    #[serde(default)]
    pub place: Option<String>,
    /// When it last saw any networks; None = not yet.
    #[serde(default)]
    pub looked: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub message: Option<String>,
    pub users: Vec<UserStatus>,
    pub log: Vec<LogEntry>,
    pub now: i64,
    /// Absent from hosts that can't tell.
    #[serde(default)]
    pub location: Option<Location>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatus {
    pub name: String,
    pub verdict: Verdict,
    pub summary: String,
    pub used_secs: u64,
    pub session_secs: u64,
    pub break_secs: u64,
    pub break_until: Option<i64>,
    pub allow_until: Option<i64>,
    pub block: Option<Block>,
    pub today_active_secs: u64,
    pub schedule_today: String,
    pub sessions: Vec<SessionInfo>,
    pub deadline: Option<i64>,
    /// Current limits, for the settings form.
    pub policy: PolicyUpdate,
    pub track_activity: bool,
    pub tracking: Tracking,
    /// The agent's focus source ("GNOME extension", "KWin script", "X11").
    pub tracking_source: Option<String>,
    /// "Minecraft: Minecraft* 1.21.4 - Singleplayer"
    pub now_doing: Option<String>,
    pub activity_today: Vec<ActivityLine>,
    /// Last 7 days including today.
    pub activity_week: Vec<ActivityLine>,
    /// Active time per day, oldest first, ending today (14 days).
    #[serde(default)]
    pub usage_days: Vec<UsageBar>,
    /// Active time per week (Sunday to Saturday), oldest first, ending this week (8 weeks).
    #[serde(default)]
    pub usage_weeks: Vec<UsageBar>,
}

/// One bar of the usage chart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageBar {
    /// First (or only) day, YYYY-MM-DD.
    pub date: String,
    pub secs: u64,
}

/// Whether activity reports are arriving for a signed-in account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tracking {
    /// Turned off in the config.
    Off,
    /// Not signed in, so nothing to report.
    NotSignedIn,
    Ok,
    /// Signed in but no agent connected (killed, or not autostarted).
    NoAgent,
    /// Agent runs but its focus source doesn't answer (GNOME extension disabled or
    /// not loaded yet, KWin script blocked, or an unsupported desktop).
    NoExtension,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityLine {
    pub name: String,
    pub secs: u64,
    /// Top titles (video, page, game window) with seconds, largest first.
    pub details: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: String,
    pub kind: String,
    pub active: bool,
    pub locked: bool,
    pub idle: bool,
}
