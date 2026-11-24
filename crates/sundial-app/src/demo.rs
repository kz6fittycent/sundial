//! Made-up data for `--demo`.

use sundial_core::config::{Action, PolicyUpdate, Window};
use sundial_core::proto::{ActivityLine, AdminResponse, Tracking, UsageBar, UserStatus};
use sundial_core::rules::Verdict;

pub fn status() -> AdminResponse {
    let day = |start: u32, end: u32| {
        Some(Window {
            start: start * 60,
            end: end * 60,
        })
    };
    let mut days = [day(8, 20); 7];
    days[4] = day(8, 22);
    days[5] = day(8, 22);
    let line = |name: &str, mins: u64| ActivityLine {
        name: name.into(),
        secs: mins * 60,
        details: vec![],
    };
    let alex = UserStatus {
        name: "alex".into(),
        verdict: Verdict::Allowed {
            until: None,
            limit: None,
        },
        summary: "26 min left, then a break.".into(),
        used_secs: 64 * 60,
        session_secs: 90 * 60,
        break_secs: 3600,
        break_until: None,
        allow_until: None,
        block: None,
        today_active_secs: 155 * 60,
        schedule_today: "08:00-20:00".into(),
        sessions: vec![],
        deadline: None,
        policy: PolicyUpdate {
            session_minutes: 90,
            break_minutes: 60,
            warn_minutes: 5,
            action: Action::Logout,
            days,
        },
        track_activity: true,
        tracking: Tracking::Ok,
        tracking_source: None,
        now_doing: Some("Minecraft".into()),
        activity_today: vec![
            line("Minecraft", 111),
            line("YouTube", 28),
            line("Web browsing", 16),
        ],
        activity_week: vec![],
        usage_days: [70, 95, 60, 120, 150, 165, 155]
            .iter()
            .enumerate()
            .map(|(i, m)| UsageBar {
                date: format!("2026-11-{}", 18 + i),
                secs: m * 60,
            })
            .collect(),
        usage_weeks: vec![],
    };
    let sam = UserStatus {
        name: "sam".into(),
        verdict: Verdict::Blocked {
            reason: sundial_core::rules::Reason::Break,
            until: None,
        },
        summary: "Break time. Back at 4:45 PM.".into(),
        used_secs: 0,
        now_doing: None,
        activity_today: vec![line("YouTube", 45)],
        ..alex.clone()
    };
    AdminResponse {
        ok: true,
        users: vec![alex, sam],
        ..Default::default()
    }
}
