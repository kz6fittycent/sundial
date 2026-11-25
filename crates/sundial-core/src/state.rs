//! `/var/lib/sundial/state.json`: usage counters, breaks, overrides and the action log.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserState {
    /// Active seconds used in the current session.
    pub used_secs: u64,
    /// The break ends at this instant.
    pub break_until: Option<i64>,
    /// Last tick the account was in active use.
    pub last_active: Option<i64>,
    /// Parent override: allowed regardless of rules until this instant.
    pub allow_until: Option<i64>,
    /// Parent override: locked between these instants.
    pub block: Option<Block>,
    /// Local date (YYYY-MM-DD) `today_active_secs` belongs to.
    pub today: String,
    pub today_active_secs: u64,
    /// Date (YYYY-MM-DD) -> active seconds that day, for the usage chart.
    pub daily: BTreeMap<String, u64>,
    /// Date (YYYY-MM-DD) -> what was in front and for how long.
    pub activity: BTreeMap<String, crate::activity::DayActivity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub from: i64,
    pub until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: i64,
    pub user: String,
    pub text: String,
}

pub const LOG_KEEP: usize = 200;
/// Days of daily totals kept (enough for 8 full weeks plus this one).
pub const DAILY_KEEP: usize = 70;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub users: BTreeMap<String, UserState>,
    /// A parent turned location on.
    pub location_on: bool,
    pub location: Option<crate::proto::Fix>,
    pub places: Vec<crate::places::Place>,
    pub log: Vec<LogEntry>,
}

impl State {
    /// Missing file = fresh state. A corrupt file is an error so the caller can decide.
    pub fn load(path: &Path) -> Result<State, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write atomically (temp file + rename) so a crash never leaves half a file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)
    }

    pub fn log(&mut self, ts: i64, user: &str, text: impl Into<String>) {
        self.log.push(LogEntry {
            ts,
            user: user.to_string(),
            text: text.into(),
        });
        if self.log.len() > LOG_KEEP {
            let extra = self.log.len() - LOG_KEEP;
            self.log.drain(..extra);
        }
    }
}
