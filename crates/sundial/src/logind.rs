//! Session state and enforcement through `loginctl` (systemd-logind).

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user: String,
    pub kind: String,
    pub active: bool,
    pub locked: bool,
    pub idle: bool,
}

impl Session {
    /// Counts toward the time limit: in front, unlocked, not idle.
    pub fn in_use(&self) -> bool {
        self.active && !self.locked && !self.idle
    }
}

async fn run(args: &[&str]) -> Result<String> {
    let out = Command::new("loginctl")
        .args(args)
        .output()
        .await
        .context("running loginctl")?;
    if !out.status.success() {
        bail!(
            "loginctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Live user sessions (class "user"; greeters, managers and closing sessions skipped).
pub async fn sessions() -> Result<Vec<Session>> {
    let list = run(&["list-sessions", "--no-legend", "--no-pager"]).await?;
    let ids: Vec<&str> = list
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["show-session", "--no-pager"];
    args.extend(&ids);
    args.extend([
        "-p", "Id", "-p", "Name", "-p", "Class", "-p", "Type", "-p", "State",
    ]);
    args.extend(["-p", "Active", "-p", "LockedHint", "-p", "IdleHint"]);
    // A session can vanish between the two calls; then loginctl fails. Treat as empty this tick.
    let text = match run(&args).await {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(parse_show(&text))
}

/// Parse `loginctl show-session` output: blocks of KEY=VALUE separated by blank lines.
fn parse_show(text: &str) -> Vec<Session> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let kv: HashMap<&str, &str> = block.lines().filter_map(|l| l.split_once('=')).collect();
        let get = |k: &str| kv.get(k).copied().unwrap_or("");
        if get("Id").is_empty() || get("Class") != "user" || get("State") == "closing" {
            continue;
        }
        out.push(Session {
            id: get("Id").to_string(),
            user: get("Name").to_string(),
            kind: get("Type").to_string(),
            active: get("Active") == "yes",
            locked: get("LockedHint") == "yes",
            idle: get("IdleHint") == "yes",
        });
    }
    out
}

pub async fn terminate_user(user: &str) -> Result<()> {
    run(&["terminate-user", user]).await.map(|_| ())
}

pub async fn lock_session(id: &str) -> Result<()> {
    run(&["lock-session", id]).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocks() {
        let text = "Id=3\nName=kid\nClass=user\nType=wayland\nState=active\nActive=yes\nLockedHint=no\nIdleHint=no\n\n\
                    Id=c1\nName=gdm-greeter\nClass=greeter\nType=wayland\nState=online\nActive=yes\nLockedHint=no\nIdleHint=no\n\n\
                    Id=7\nName=kid\nClass=user\nType=tty\nState=closing\nActive=no\nLockedHint=no\nIdleHint=no\n";
        let s = parse_show(text);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].user, "kid");
        assert!(s[0].in_use());
    }
}
