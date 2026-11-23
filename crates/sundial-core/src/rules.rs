//! The rules engine. Pure functions of (policy, state, now) so they can be tested
//! without logind, clocks or files. Times are unix seconds; the time zone only
//! matters for turning schedule windows ("08:00-20:00") into instants.

use crate::config::UserPolicy;
use crate::state::{Block, UserState};
use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDate, TimeZone};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Why an allowed stretch ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    /// The session (e.g. 1 hour) is used up; a break follows.
    Session,
    /// The day's allowed hours end.
    Bedtime,
    /// A parent scheduled a lock.
    ParentLock,
    /// Extra time a parent granted runs out.
    ParentAllow,
}

/// Why the account may not be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    ParentLock,
    OutsideHours,
    Break,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Verdict {
    /// `until` = when the current allowed stretch ends (None = no limit in sight).
    Allowed {
        until: Option<i64>,
        limit: Option<Limit>,
    },
    /// `until` = when the account may be used again (None = not within a week).
    Blocked { reason: Reason, until: Option<i64> },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allowed { .. })
    }
}

/// A parent's change, from the web page or `sundial` CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Override {
    /// Add minutes on top of whatever time is left (or start from now if blocked).
    /// Overrides breaks and allowed hours until it runs out.
    Grant { minutes: u32 },
    /// End the current break (if any) and start a fresh session.
    EndBreak,
    /// Take minutes off the current session (and off a parent's extra time). Always
    /// leaves the countdown's worth, so the kid still gets the warning.
    TakeTime { minutes: u32 },
    /// Allow use until this instant regardless of rules.
    AllowUntil { at: i64 },
    /// Lock after `in_secs` (the countdown) until `until`; None = the start of the next day's window.
    Lock { in_secs: u32, until: Option<i64> },
    /// Drop all parent overrides.
    Clear,
}

fn day_index(d: NaiveDate) -> usize {
    d.weekday().num_days_from_monday() as usize
}

/// Unix time of `minute` minutes after midnight on `d` (1440 = next midnight).
fn at_minute<Tz: TimeZone>(tz: &Tz, d: NaiveDate, minute: u32) -> i64 {
    let (d, minute) = if minute >= 1440 {
        (d + Duration::days(1), minute - 1440)
    } else {
        (d, minute)
    };
    let naive = d
        .and_hms_opt(minute / 60, minute % 60, 0)
        .expect("valid time");
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(t) => t.timestamp(),
        LocalResult::Ambiguous(a, _) => a.timestamp(),
        // Inside a DST gap: the first valid instant after it.
        LocalResult::None => tz
            .from_local_datetime(&(naive + Duration::hours(1)))
            .earliest()
            .map(|t| t.timestamp())
            .unwrap_or_else(|| naive.and_utc().timestamp()),
    }
}

/// Allowed intervals [start, end) from yesterday to 8 days ahead, merged where they touch
/// (so "00:00-24:00" every day is one interval, and midnight is not a bedtime).
fn intervals<Tz: TimeZone>(p: &UserPolicy, now: &DateTime<Tz>) -> Vec<(i64, i64)> {
    let tz = now.timezone();
    let today = now.date_naive();
    let mut v: Vec<(i64, i64)> = Vec::new();
    for off in -1..=8 {
        let d = today + Duration::days(off);
        if let Some(w) = p.schedule.days[day_index(d)] {
            let (s, e) = (at_minute(&tz, d, w.start), at_minute(&tz, d, w.end));
            match v.last_mut() {
                Some(last) if last.1 >= s => last.1 = last.1.max(e),
                _ => v.push((s, e)),
            }
        }
    }
    v
}

/// First instant >= `t` inside an allowed interval.
fn next_allowed(iv: &[(i64, i64)], t: i64) -> Option<i64> {
    iv.iter().find(|(_, e)| *e > t).map(|(s, _)| (*s).max(t))
}

/// Start of the first allowed window on a later day (tomorrow 08:00, say).
pub fn next_day_start<Tz: TimeZone>(p: &UserPolicy, now: &DateTime<Tz>) -> Option<i64> {
    let tz = now.timezone();
    let today = now.date_naive();
    (1..=7).find_map(|off| {
        let d = today + Duration::days(off);
        p.schedule.days[day_index(d)].map(|w| at_minute(&tz, d, w.start))
    })
}

/// Ends further away than this are treated as "no limit".
const HORIZON: i64 = 7 * 86_400;

pub fn evaluate<Tz: TimeZone>(p: &UserPolicy, s: &UserState, now: &DateTime<Tz>) -> Verdict {
    let t = now.timestamp();
    if let Some(b) = s.block
        && b.from <= t
        && t < b.until
    {
        return Verdict::Blocked {
            reason: Reason::ParentLock,
            until: Some(b.until),
        };
    }
    let mut ends: Vec<(i64, Limit)> = Vec::new();
    if let Some(b) = s.block.filter(|b| b.from > t) {
        ends.push((b.from, Limit::ParentLock));
    }
    if let Some(a) = s.allow_until.filter(|&a| a > t) {
        ends.push((a, Limit::ParentAllow));
        return soonest(ends);
    }
    let iv = intervals(p, now);
    let Some(&(_, end)) = iv.iter().find(|(st, e)| *st <= t && t < *e) else {
        return Verdict::Blocked {
            reason: Reason::OutsideHours,
            until: next_allowed(&iv, t),
        };
    };
    if let Some(bu) = s.break_until.filter(|&b| b > t) {
        return Verdict::Blocked {
            reason: Reason::Break,
            until: next_allowed(&iv, bu),
        };
    }
    if end - t <= HORIZON {
        ends.push((end, Limit::Bedtime));
    }
    if p.session_minutes > 0 {
        let left = (i64::from(p.session_minutes) * 60 - s.used_secs as i64).max(0);
        ends.push((t + left, Limit::Session));
    }
    soonest(ends)
}

fn soonest(ends: Vec<(i64, Limit)>) -> Verdict {
    match ends.into_iter().min_by_key(|e| e.0) {
        Some((until, limit)) => Verdict::Allowed {
            until: Some(until),
            limit: Some(limit),
        },
        None => Verdict::Allowed {
            until: None,
            limit: None,
        },
    }
}

/// Advance the state by one tick. `active_secs` = seconds of active use since the last tick
/// (0 if nobody was active). Returns log lines for anything that changed.
pub fn account<Tz: TimeZone>(
    p: &UserPolicy,
    s: &mut UserState,
    now: &DateTime<Tz>,
    active_secs: u64,
    any_active: bool,
) -> Vec<String>
where
    Tz::Offset: Display,
{
    let t = now.timestamp();
    let mut ev = Vec::new();
    if s.allow_until.is_some_and(|a| a <= t) {
        s.allow_until = None;
        ev.push("parent's extra time ended".to_string());
    }
    if s.block.is_some_and(|b| b.until <= t) {
        s.block = None;
        ev.push("parent lock ended".to_string());
    }
    if s.break_until.is_some_and(|b| b <= t) {
        s.break_until = None;
        s.used_secs = 0;
        ev.push("break over; fresh session".to_string());
    }
    let today = now.date_naive().to_string();
    if s.today != today {
        s.today = today;
        s.today_active_secs = 0;
    }

    if any_active {
        if evaluate(p, s, now).is_allowed() {
            s.used_secs += active_secs;
            s.today_active_secs += active_secs;
            *s.daily.entry(s.today.clone()).or_default() += active_secs;
            while s.daily.len() > crate::state::DAILY_KEEP {
                let oldest = s.daily.keys().next().cloned().expect("non-empty");
                s.daily.remove(&oldest);
            }
        }
        s.last_active = Some(t);
    } else if p.session_minutes > 0
        && s.used_secs > 0
        && s.break_until.is_none()
        && let Some(la) = s.last_active
        && t - la >= i64::from(p.break_minutes) * 60
    {
        s.used_secs = 0;
        ev.push("away long enough; fresh session".to_string());
    }

    let allow_active = s.allow_until.is_some_and(|a| a > t);
    let limit = u64::from(p.session_minutes) * 60;
    if p.session_minutes > 0 && !allow_active && s.break_until.is_none() && s.used_secs >= limit {
        let until = t + i64::from(p.break_minutes) * 60;
        s.break_until = Some(until);
        s.used_secs = 0;
        ev.push(format!(
            "session used up; break until {}",
            fmt_when(until, now)
        ));
    }
    ev
}

/// Apply a parent's override. Returns a description for the log.
pub fn apply<Tz: TimeZone>(
    p: &UserPolicy,
    s: &mut UserState,
    now: &DateTime<Tz>,
    o: Override,
) -> String
where
    Tz::Offset: Display,
{
    let t = now.timestamp();
    match o {
        Override::Grant { minutes } => {
            let base = match evaluate(p, s, now) {
                Verdict::Allowed { until: Some(u), .. } => u.max(t),
                Verdict::Allowed { until: None, .. } => {
                    return "no limit right now; nothing to add".into();
                }
                Verdict::Blocked { .. } => t,
            };
            let until = base + i64::from(minutes) * 60;
            s.allow_until = Some(until);
            if s.block.is_some_and(|b| b.from <= until) {
                s.block = None;
            }
            format!(
                "granted {minutes} min; allowed until {}",
                fmt_when(until, now)
            )
        }
        Override::EndBreak => {
            s.break_until = None;
            s.used_secs = 0;
            "fresh session started".into()
        }
        Override::TakeTime { minutes } => {
            let take = u64::from(minutes) * 60;
            let warn = i64::from(p.warn_minutes) * 60;
            if let Some(a) = s.allow_until.filter(|&a| a > t) {
                s.allow_until = Some((a - take as i64).max(t + warn));
            }
            if p.session_minutes > 0 {
                let limit = u64::from(p.session_minutes) * 60;
                let ceiling = limit.saturating_sub(warn as u64).max(s.used_secs);
                s.used_secs = (s.used_secs + take).min(ceiling);
            }
            match evaluate(p, s, now) {
                Verdict::Allowed { until: Some(u), .. } => {
                    format!("took {minutes} min; {} left", fmt_duration(u - t))
                }
                _ => format!("took {minutes} min"),
            }
        }
        Override::AllowUntil { at } => {
            s.allow_until = Some(at);
            s.block = None;
            format!("allowed until {}", fmt_when(at, now))
        }
        Override::Lock { in_secs, until } => {
            let from = t + i64::from(in_secs);
            let until = until
                .or_else(|| next_day_start(p, now))
                .unwrap_or(t + 86_400)
                .max(from + 60);
            s.block = Some(Block { from, until });
            s.allow_until = None;
            if in_secs == 0 {
                format!("locked now until {}", fmt_when(until, now))
            } else {
                format!(
                    "lock at {} until {}",
                    fmt_when(from, now),
                    fmt_when(until, now)
                )
            }
        }
        Override::Clear => {
            s.allow_until = None;
            s.block = None;
            "cleared parent overrides".into()
        }
    }
}

/// "3:45 PM", "tomorrow at 8:00 AM" or "Mon at 8:00 AM", relative to `now`.
pub fn fmt_when<Tz: TimeZone>(ts: i64, now: &DateTime<Tz>) -> String
where
    Tz::Offset: Display,
{
    let tz = now.timezone();
    let Some(dt) = tz.timestamp_opt(ts, 0).single() else {
        return ts.to_string();
    };
    let clock = dt.format("%-I:%M %p").to_string();
    let days = (dt.date_naive() - now.date_naive()).num_days();
    match days {
        0 => clock,
        1 => format!("tomorrow at {clock}"),
        _ => format!("{} at {clock}", dt.format("%a")),
    }
}

/// "1 h 5 min", "12 min", "45 s".
pub fn fmt_duration(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 60 {
        return format!("{secs} s");
    }
    let mins = (secs + 59) / 60;
    match (mins / 60, mins % 60) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// One-line, kid-readable explanation of a verdict.
pub fn describe<Tz: TimeZone>(v: &Verdict, now: &DateTime<Tz>) -> String
where
    Tz::Offset: Display,
{
    let t = now.timestamp();
    match *v {
        Verdict::Allowed { until: None, .. } => "No limit right now.".into(),
        Verdict::Allowed {
            until: Some(u),
            limit,
        } => {
            let left = fmt_duration(u - t);
            match limit {
                Some(Limit::Session) => format!("{left} left, then a break."),
                Some(Limit::Bedtime) => {
                    format!("{left} left; computer time ends at {}.", fmt_when(u, now))
                }
                Some(Limit::ParentLock) => {
                    format!("{left} left; a parent set a lock at {}.", fmt_when(u, now))
                }
                Some(Limit::ParentAllow) | None => {
                    format!("{left} left (extra time from a parent).")
                }
            }
        }
        Verdict::Blocked { reason, until } => {
            let when = until
                .map(|u| fmt_when(u, now))
                .unwrap_or_else(|| "later".into());
            // "Back at 3:45 PM" / "Back tomorrow at 8:00 AM" / "Back later".
            let back = if when.starts_with(|c: char| c.is_ascii_digit()) {
                format!("Back at {when}")
            } else {
                format!("Back {when}")
            };
            match reason {
                Reason::Break => format!("Break time. {back}."),
                Reason::OutsideHours => format!("Computer time is over. {back}."),
                Reason::ParentLock => format!("A parent locked the computer until {when}."),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use chrono::FixedOffset;

    fn policy() -> UserPolicy {
        Config::parse(
            r#"
            [[user]]
            name = "kid"
            [user.schedule]
            default = "08:00-20:00"
            fri = "08:00-22:00"
            sat = "08:00-22:00"
            "#,
        )
        .unwrap()
        .users
        .remove(0)
    }

    fn tz() -> FixedOffset {
        FixedOffset::west_opt(6 * 3600).unwrap()
    }

    /// 2026-11-23 is a Monday.
    fn at(day: u32, h: u32, m: u32) -> DateTime<FixedOffset> {
        tz().with_ymd_and_hms(2026, 11, day, h, m, 0).unwrap()
    }

    fn ts(day: u32, h: u32, m: u32) -> i64 {
        at(day, h, m).timestamp()
    }

    /// Run active (or idle) ticks of 5 s from `from` for `secs`.
    fn run(
        p: &UserPolicy,
        s: &mut UserState,
        from: DateTime<FixedOffset>,
        secs: i64,
        active: bool,
    ) -> DateTime<FixedOffset> {
        let mut now = from;
        for _ in 0..secs / 5 {
            now += Duration::seconds(5);
            account(p, s, &now, if active { 5 } else { 0 }, active);
        }
        now
    }

    #[test]
    fn before_eight_is_blocked() {
        let v = evaluate(&policy(), &UserState::default(), &at(23, 7, 30));
        assert_eq!(
            v,
            Verdict::Blocked {
                reason: Reason::OutsideHours,
                until: Some(ts(23, 8, 0))
            }
        );
    }

    #[test]
    fn fresh_morning_gets_an_hour() {
        let v = evaluate(&policy(), &UserState::default(), &at(23, 8, 0));
        assert_eq!(
            v,
            Verdict::Allowed {
                until: Some(ts(23, 9, 0)),
                limit: Some(Limit::Session)
            }
        );
    }

    #[test]
    fn bedtime_cuts_the_session_short() {
        let v = evaluate(&policy(), &UserState::default(), &at(23, 19, 30));
        assert_eq!(
            v,
            Verdict::Allowed {
                until: Some(ts(23, 20, 0)),
                limit: Some(Limit::Bedtime)
            }
        );
        // Friday runs to 22:00.
        let v = evaluate(&policy(), &UserState::default(), &at(27, 21, 30));
        assert_eq!(
            v,
            Verdict::Allowed {
                until: Some(ts(27, 22, 0)),
                limit: Some(Limit::Bedtime)
            }
        );
    }

    #[test]
    fn sunday_night_waits_for_monday() {
        // 2026-11-29 is a Sunday; stop at 20:00.
        let v = evaluate(&policy(), &UserState::default(), &at(29, 20, 0));
        assert_eq!(
            v,
            Verdict::Blocked {
                reason: Reason::OutsideHours,
                until: Some(ts(30, 8, 0))
            }
        );
        // Saturday 21:00 is still fine.
        assert!(evaluate(&policy(), &UserState::default(), &at(28, 21, 0)).is_allowed());
    }

    #[test]
    fn hour_on_two_hours_off() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 8, 0), 3600, true);
        assert_eq!(s.break_until, Some(ts(23, 11, 0)));
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Blocked {
                reason: Reason::Break,
                until: Some(ts(23, 11, 0))
            }
        );
        // Idle through the break, then a fresh hour.
        let now = run(&p, &mut s, now, 7200, false);
        assert_eq!(s.break_until, None);
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(ts(23, 12, 0)),
                limit: Some(Limit::Session)
            }
        );
        assert_eq!(s.today_active_secs, 3600);
    }

    #[test]
    fn break_past_bedtime_waits_for_morning() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 18, 0), 3600, true);
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Blocked {
                reason: Reason::Break,
                until: Some(ts(24, 8, 0))
            }
        );
    }

    #[test]
    fn idle_does_not_count_and_long_absence_refills() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 8, 0), 1200, true);
        let now = run(&p, &mut s, now, 3600, false);
        assert_eq!(s.used_secs, 1200);
        let now = run(&p, &mut s, now, 3600, false);
        assert_eq!(s.used_secs, 0, "2 h away refills the session");
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(now.timestamp() + 3600),
                limit: Some(Limit::Session)
            }
        );
    }

    #[test]
    fn grant_adds_to_remaining_and_break_follows() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 8, 0), 2400, true); // 20 min left
        apply(&p, &mut s, &now, Override::Grant { minutes: 30 });
        assert_eq!(s.allow_until, Some(ts(23, 9, 30)));
        let now = run(&p, &mut s, now, 2995, true);
        assert!(evaluate(&p, &s, &now).is_allowed());
        assert_eq!(s.break_until, None, "no break while extra time runs");
        let now = run(&p, &mut s, now, 10, true);
        assert_eq!(s.break_until, Some(ts(23, 11, 30)));
        assert!(!evaluate(&p, &s, &now).is_allowed());
    }

    #[test]
    fn grant_after_bedtime() {
        let p = policy();
        let mut s = UserState::default();
        let now = at(23, 20, 5);
        apply(&p, &mut s, &now, Override::Grant { minutes: 30 });
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(ts(23, 20, 35)),
                limit: Some(Limit::ParentAllow)
            }
        );
        assert!(!evaluate(&p, &s, &at(23, 20, 36)).is_allowed());
    }

    #[test]
    fn lock_with_countdown_then_until_tomorrow() {
        let p = policy();
        let mut s = UserState::default();
        let now = at(23, 10, 0);
        apply(
            &p,
            &mut s,
            &now,
            Override::Lock {
                in_secs: 300,
                until: None,
            },
        );
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(ts(23, 10, 5)),
                limit: Some(Limit::ParentLock)
            }
        );
        assert_eq!(
            evaluate(&p, &s, &at(23, 10, 5)),
            Verdict::Blocked {
                reason: Reason::ParentLock,
                until: Some(ts(24, 8, 0))
            }
        );
        apply(&p, &mut s, &now, Override::Clear);
        assert!(evaluate(&p, &s, &at(23, 10, 5)).is_allowed());
    }

    #[test]
    fn end_break() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 8, 0), 3600, true);
        assert!(!evaluate(&p, &s, &now).is_allowed());
        apply(&p, &mut s, &now, Override::EndBreak);
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(now.timestamp() + 3600),
                limit: Some(Limit::Session)
            }
        );
    }

    #[test]
    fn take_time_keeps_the_countdown() {
        let p = policy();
        let mut s = UserState::default();
        let now = run(&p, &mut s, at(23, 8, 0), 1800, true); // 30 min left
        apply(&p, &mut s, &now, Override::TakeTime { minutes: 15 });
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(now.timestamp() + 900),
                limit: Some(Limit::Session)
            }
        );
        apply(&p, &mut s, &now, Override::TakeTime { minutes: 60 });
        assert_eq!(
            evaluate(&p, &s, &now),
            Verdict::Allowed {
                until: Some(now.timestamp() + 300),
                limit: Some(Limit::Session)
            },
            "5 min countdown left"
        );
    }

    #[test]
    fn no_limits_configured() {
        let p = Config::parse("[[user]]\nname='a'\nsession_minutes=0")
            .unwrap()
            .users
            .remove(0);
        assert_eq!(
            evaluate(&p, &UserState::default(), &at(23, 3, 0)),
            Verdict::Allowed {
                until: None,
                limit: None
            }
        );
    }

    #[test]
    fn day_rollover_resets_daily_total() {
        let p = policy();
        let mut s = UserState::default();
        run(&p, &mut s, at(23, 8, 0), 600, true);
        assert_eq!(s.today_active_secs, 600);
        account(&p, &mut s, &at(24, 7, 0), 0, false);
        assert_eq!(s.today_active_secs, 0);
    }

    #[test]
    fn formatting() {
        let now = at(23, 10, 0);
        assert_eq!(fmt_when(ts(23, 15, 45), &now), "3:45 PM");
        assert_eq!(fmt_when(ts(24, 8, 0), &now), "tomorrow at 8:00 AM");
        assert_eq!(fmt_when(ts(26, 8, 0), &now), "Thu at 8:00 AM");
        let v = Verdict::Blocked {
            reason: Reason::Break,
            until: Some(ts(23, 15, 45)),
        };
        assert_eq!(describe(&v, &now), "Break time. Back at 3:45 PM.");
        let v = Verdict::Blocked {
            reason: Reason::OutsideHours,
            until: Some(ts(24, 8, 0)),
        };
        assert_eq!(
            describe(&v, &now),
            "Computer time is over. Back tomorrow at 8:00 AM."
        );
        assert_eq!(fmt_duration(3900), "1 h 5 min");
        assert_eq!(fmt_duration(61), "2 min");
        assert_eq!(fmt_duration(30), "30 s");
    }
}
