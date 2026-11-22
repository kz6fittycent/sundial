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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub message: Option<String>,
    pub users: Vec<UserStatus>,
    pub log: Vec<LogEntry>,
    pub now: i64,
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
