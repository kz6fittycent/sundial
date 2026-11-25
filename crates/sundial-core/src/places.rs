//! Places a parent has marked ("Home"), recognized by the Wi-Fi networks around the
//! computer. The networks never leave the computer; only the place's name does.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Access point addresses, lower case.
pub type Networks = BTreeSet<String>;

pub const MAX_PLACES: usize = 20;
pub const MAX_NAME: usize = 30;
/// Enough to recognize a place, however crowded.
const MAX_NETWORKS: usize = 120;
/// Share of the smaller list that must match. Networks come and go between scans.
const NEEDED: f64 = 0.3;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Place {
    pub name: String,
    pub networks: Networks,
}

/// Phone hotspots use made-up ("locally administered") addresses and travel with the
/// child, so they say nothing about the place.
fn made_up(address: &str) -> bool {
    address
        .get(..2)
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_none_or(|b| b & 2 != 0)
}

fn is_address(a: &str) -> bool {
    a.len() == 17
        && a.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The networks worth comparing.
pub fn useful(seen: impl IntoIterator<Item = String>) -> Networks {
    let all: Networks = seen
        .into_iter()
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| is_address(a))
        .collect();
    all.into_iter()
        .filter(|a| !made_up(a))
        .take(MAX_NETWORKS)
        .collect()
}

pub fn check_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME || n.chars().any(char::is_control) {
        return Err(format!("Use a name of 1 to {MAX_NAME} characters."));
    }
    Ok(n.to_string())
}

/// Mark where the computer is now. The same name again adds to what it looks like.
pub fn mark(places: &mut Vec<Place>, name: &str, now: &Networks) -> Result<String, String> {
    let name = check_name(name)?;
    if now.is_empty() {
        return Err("The computer sees no Wi-Fi networks to recognize this place by.".into());
    }
    if let Some(p) = places
        .iter_mut()
        .find(|p| p.name.to_lowercase() == name.to_lowercase())
    {
        for a in now {
            if p.networks.len() < MAX_NETWORKS {
                p.networks.insert(a.clone());
            }
        }
        return Ok(p.name.clone());
    }
    if places.len() >= MAX_PLACES {
        return Err("There are too many places. Remove one first.".into());
    }
    places.push(Place {
        name: name.clone(),
        networks: now.clone(),
    });
    Ok(name)
}

/// Which marked place this looks like.
pub fn recognize<'a>(places: &'a [Place], now: &Networks) -> Option<&'a str> {
    places
        .iter()
        .filter_map(|p| {
            let shared = p.networks.intersection(now).count();
            let smaller = p.networks.len().min(now.len());
            // One shared network may have moved house, unless the place has only one.
            if shared == 0 || shared < p.networks.len().min(2) {
                return None;
            }
            let score = shared as f64 / smaller as f64;
            (score >= NEEDED).then_some((score, shared, p))
        })
        .max_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
        .map(|(_, _, p)| p.name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(range: std::ops::Range<u8>) -> Networks {
        useful(range.map(|i| format!("10:22:33:44:55:{i:02X}")))
    }

    #[test]
    fn home_and_away() {
        let mut p = Vec::new();
        mark(&mut p, " Home ", &nets(0..20)).unwrap();
        mark(&mut p, "School", &nets(40..60)).unwrap();
        // Other scans at home see some of the same networks.
        assert_eq!(recognize(&p, &nets(10..24)), Some("Home"));
        assert_eq!(recognize(&p, &nets(5..8)), Some("Home"));
        assert_eq!(recognize(&p, &nets(45..70)), Some("School"));
        assert_eq!(recognize(&p, &nets(100..120)), None);
        // One network in common with a full scan isn't home.
        assert_eq!(recognize(&p, &nets(19..35)), None);
        assert_eq!(recognize(&p, &nets(19..20)), None);
        assert_eq!(recognize(&p, &Networks::new()), None);
    }

    #[test]
    fn one_network_in_the_country() {
        let mut p = Vec::new();
        mark(&mut p, "Cabin", &nets(0..1)).unwrap();
        assert_eq!(recognize(&p, &nets(0..1)), Some("Cabin"));
        assert_eq!(recognize(&p, &nets(1..2)), None);
    }

    #[test]
    fn hotspots_dont_count() {
        let n = useful(["1E:22:33:44:55:66".into(), "10:22:33:44:55:66".into()]);
        assert_eq!(n.len(), 1);
        assert!(useful(["nonsense".into(), "".into(), "é:".into()]).is_empty());
        assert!(
            mark(
                &mut Vec::new(),
                "Bus",
                &useful(["1e:22:33:44:55:66".into()])
            )
            .is_err()
        );
    }

    #[test]
    fn again_adds_and_limits_hold() {
        let mut p = Vec::new();
        mark(&mut p, "Home", &nets(0..5)).unwrap();
        assert_eq!(mark(&mut p, "home", &nets(5..9)).unwrap(), "Home");
        assert_eq!((p.len(), p[0].networks.len()), (1, 9));
        for n in ["", "  ", "a\nb", &"x".repeat(31)] {
            assert!(mark(&mut p, n, &nets(0..5)).is_err());
        }
        for i in 1..MAX_PLACES {
            mark(&mut p, &format!("p{i}"), &nets(0..5)).unwrap();
        }
        assert!(mark(&mut p, "more", &nets(0..5)).is_err());
    }
}
