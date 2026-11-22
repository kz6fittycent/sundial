//! Messages on the daemon's Unix sockets (one JSON object per line).

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

/// CLI/web -> daemon on `/run/sundial/admin.sock` (root only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
    Status,
    Act { user: String, by: String, action: Override },
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: String,
    pub kind: String,
    pub active: bool,
    pub locked: bool,
    pub idle: bool,
}
