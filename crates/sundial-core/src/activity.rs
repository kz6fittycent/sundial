//! What the account is doing: the focused app and window title (reported by the agent,
//! read from the Sundial GNOME Shell extension), turned into activity names like
//! "Minecraft" or "YouTube", and totaled per day.

use crate::config::ActivityRule;
use crate::state::UserState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Days of activity kept in the state file.
pub const KEEP_DAYS: usize = 14;
/// Distinct titles kept per activity per day; the rest are added to "(other)".
pub const KEEP_DETAILS: usize = 40;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Focus {
    /// Desktop app id, e.g. "firefox_firefox.desktop" (may be empty for unknown windows).
    pub app_id: String,
    /// App display name, e.g. "Firefox".
    pub app_name: String,
    /// Window title, e.g. "Some video - YouTube — Mozilla Firefox".
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub name: String,
    /// Video title, page title or game window title, when useful.
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DayActivity {
    /// activity -> seconds
    pub totals: BTreeMap<String, u64>,
    /// activity -> title -> seconds
    pub details: BTreeMap<String, BTreeMap<String, u64>>,
}

/// Streaming and other sites recognized from a browser tab title.
const SITES: &[(&str, &[&str])] = &[
    ("YouTube", &["youtube"]),
    ("Netflix", &["netflix"]),
    ("Disney+", &["disney+", "disney plus"]),
    ("Twitch", &["twitch"]),
    ("Prime Video", &["prime video"]),
    ("Hulu", &["hulu"]),
    ("Max", &["| max", "- max"]),
    ("Paramount+", &["paramount+"]),
    ("Peacock", &["peacock"]),
    ("Crunchyroll", &["crunchyroll"]),
    ("Pluto TV", &["pluto tv"]),
    ("Tubi", &["tubi"]),
    ("TikTok", &["tiktok"]),
    ("Roblox", &["roblox"]),
    ("Spotify", &["spotify"]),
    ("Discord", &["discord"]),
];

const BROWSERS: &[&str] = &[
    "firefox",
    "chrom",
    "brave",
    "msedge",
    "microsoft edge",
    "vivaldi",
    "opera",
    "epiphany",
    "librewolf",
    "zen",
];

fn is_browser(f: &Focus) -> bool {
    let app = format!("{} {}", f.app_id, f.app_name).to_lowercase();
    BROWSERS.iter().any(|b| app.contains(b))
}

/// "(3) Video - YouTube — Mozilla Firefox" -> "Video - YouTube".
fn page_title(title: &str) -> String {
    let mut t = title.trim();
    // Unread-count prefix: "(3) ".
    if let Some(rest) = t.strip_prefix('(')
        && let Some((n, after)) = rest.split_once(") ")
        && n.chars().all(|c| c.is_ascii_digit())
    {
        t = after;
    }
    for sep in [" — ", " - ", " – "] {
        if let Some((head, tail)) = t.rsplit_once(sep) {
            let tail_l = tail.to_lowercase();
            if BROWSERS.iter().any(|b| tail_l.contains(b)) || tail_l.contains("private browsing") {
                t = head;
                break;
            }
        }
    }
    t.trim().to_string()
}

/// "Video - YouTube" -> Some("Video"); "YouTube" -> None.
fn strip_site(title: &str, site: &str) -> Option<String> {
    let lower = title.to_lowercase();
    let site_l = site.to_lowercase();
    let mut t = title.to_string();
    for sep in [" - ", " | ", " — ", " – ", ": "] {
        let suffix = format!("{sep}{site_l}");
        if lower.ends_with(&suffix) {
            t = title[..title.len() - suffix.len()].to_string();
            break;
        }
    }
    let t = t.trim();
    (!t.is_empty() && !t.eq_ignore_ascii_case(site)).then(|| t.to_string())
}

/// Name the activity. None = nothing in front (no window focused).
pub fn classify(f: &Focus, rules: &[ActivityRule]) -> Option<Classified> {
    if f.app_id.is_empty() && f.app_name.is_empty() && f.title.is_empty() {
        return None;
    }
    let hay = format!("{} {} {}", f.app_id, f.app_name, f.title).to_lowercase();
    let detail = (!f.title.trim().is_empty()).then(|| f.title.trim().to_string());
    for r in rules {
        if r.patterns
            .iter()
            .any(|p| !p.is_empty() && hay.contains(&p.to_lowercase()))
        {
            return Some(Classified {
                name: r.name.clone(),
                detail,
            });
        }
    }
    if hay.contains("minecraft") {
        return Some(Classified {
            name: "Minecraft".into(),
            detail,
        });
    }
    if is_browser(f) {
        let page = page_title(&f.title);
        let page_l = page.to_lowercase();
        for (site, pats) in SITES {
            if pats.iter().any(|p| page_l.contains(p)) {
                return Some(Classified {
                    name: (*site).into(),
                    detail: strip_site(&page, site),
                });
            }
        }
        return Some(Classified {
            name: "Web browsing".into(),
            detail: (!page.is_empty()).then_some(page),
        });
    }
    let name = [&f.app_name, &f.app_id]
        .into_iter()
        .map(|s| s.trim().trim_end_matches(".desktop"))
        .find(|s| !s.is_empty())
        .unwrap_or("Unknown app");
    Some(Classified {
        name: name.to_string(),
        detail: None,
    })
}

/// Add `secs` of `c` to the day `date` (YYYY-MM-DD), dropping days beyond KEEP_DAYS.
pub fn record(s: &mut UserState, date: &str, c: &Classified, secs: u64) {
    if secs == 0 {
        return;
    }
    let day = s.activity.entry(date.to_string()).or_default();
    *day.totals.entry(c.name.clone()).or_default() += secs;
    if let Some(d) = &c.detail {
        let titles = day.details.entry(c.name.clone()).or_default();
        let key = if titles.contains_key(d) || titles.len() < KEEP_DETAILS {
            d.clone()
        } else {
            "(other)".into()
        };
        *titles.entry(key).or_default() += secs;
    }
    while s.activity.len() > KEEP_DAYS {
        let oldest = s.activity.keys().next().cloned().expect("non-empty");
        s.activity.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(app_id: &str, app_name: &str, title: &str) -> Focus {
        Focus {
            app_id: app_id.into(),
            app_name: app_name.into(),
            title: title.into(),
        }
    }

    fn c(focus: &Focus) -> (String, Option<String>) {
        let r = classify(focus, &[]).unwrap();
        (r.name, r.detail)
    }

    #[test]
    fn minecraft() {
        assert_eq!(
            c(&f(
                "",
                "Minecraft* 1.21.4",
                "Minecraft* 1.21.4 - Singleplayer"
            ))
            .0,
            "Minecraft"
        );
        assert_eq!(
            c(&f(
                "org.prismlauncher.PrismLauncher.desktop",
                "Prism Launcher",
                "Prism Launcher 9.4"
            ))
            .0,
            "Prism Launcher"
        );
    }

    #[test]
    fn youtube_in_browsers() {
        assert_eq!(
            c(&f(
                "firefox_firefox.desktop",
                "Firefox",
                "(2) Epic Build - YouTube — Mozilla Firefox"
            )),
            ("YouTube".into(), Some("Epic Build".into()))
        );
        assert_eq!(
            c(&f(
                "brave-browser.desktop",
                "Brave Web Browser",
                "Epic Build - YouTube - Brave"
            )),
            ("YouTube".into(), Some("Epic Build".into()))
        );
        assert_eq!(
            c(&f(
                "firefox_firefox.desktop",
                "Firefox",
                "YouTube — Mozilla Firefox"
            )),
            ("YouTube".into(), None)
        );
        assert_eq!(
            c(&f(
                "google-chrome.desktop",
                "Google Chrome",
                "Netflix - Google Chrome"
            ))
            .0,
            "Netflix"
        );
    }

    #[test]
    fn other_pages_and_apps() {
        assert_eq!(
            c(&f(
                "firefox_firefox.desktop",
                "Firefox",
                "Khan Academy — Mozilla Firefox"
            )),
            ("Web browsing".into(), Some("Khan Academy".into()))
        );
        assert_eq!(
            c(&f("org.gnome.Nautilus.desktop", "Files", "Home")),
            ("Files".into(), None)
        );
        assert_eq!(c(&f("steam.desktop", "", "Steam")), ("steam".into(), None));
        assert!(classify(&f("", "", ""), &[]).is_none());
    }

    #[test]
    fn custom_rules_first() {
        let rules = vec![ActivityRule {
            name: "Roblox".into(),
            patterns: vec!["sober".into()],
        }];
        assert_eq!(
            classify(&f("org.vinegarhq.Sober.desktop", "Sober", "Sober"), &rules)
                .unwrap()
                .name,
            "Roblox"
        );
    }

    #[test]
    fn record_and_prune() {
        let mut s = UserState::default();
        let yt = Classified {
            name: "YouTube".into(),
            detail: Some("A".into()),
        };
        record(&mut s, "2026-11-01", &yt, 5);
        record(&mut s, "2026-11-01", &yt, 5);
        assert_eq!(s.activity["2026-11-01"].totals["YouTube"], 10);
        assert_eq!(s.activity["2026-11-01"].details["YouTube"]["A"], 10);
        for d in 2..=20 {
            record(&mut s, &format!("2026-11-{d:02}"), &yt, 5);
        }
        assert_eq!(s.activity.len(), KEEP_DAYS);
        assert!(!s.activity.contains_key("2026-11-01"));
        for i in 0..KEEP_DETAILS + 5 {
            record(
                &mut s,
                "2026-11-20",
                &Classified {
                    name: "Web browsing".into(),
                    detail: Some(format!("p{i}")),
                },
                1,
            );
        }
        assert_eq!(
            s.activity["2026-11-20"].details["Web browsing"].len(),
            KEEP_DETAILS + 1
        );
        assert_eq!(
            s.activity["2026-11-20"].details["Web browsing"]["(other)"],
            5
        );
    }
}
