//! Where this computer is, from the OS location service (GeoClue). Off until a parent
//! turns it on. Only the latest position is kept, and the child's session says it's on.

use crate::daemon::Shared;
use anyhow::{Context, Result, bail};
use chrono::Local;
use std::path::Path;
use std::time::Duration;
use sundial_core::proto::Fix;
use tokio::process::Command;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};

const CONF_DIR: &str = "/etc/geoclue/conf.d";
const CONF: &str = "/etc/geoclue/conf.d/90-sundial.conf";
const MAIN_CONF: &str = "/etc/geoclue/geoclue.conf";
const DESKTOP_ID: &str = "sundial";
const AGENT_PATH: &str = "/org/freedesktop/GeoClue2/Agent";
const BUS: &str = "org.freedesktop.GeoClue2";
const EVERY: i64 = 300;
const POLL: Duration = Duration::from_secs(5);
/// Wi-Fi positioning can take a while; a rough position often comes first.
const WAIT: Duration = Duration::from_secs(25);
const GOOD_METERS: f64 = 200.0;
const EXACT: u32 = 8;

/// GeoClue answers a user only through that user's agent, normally part of the desktop.
/// Root has none, so Sundial is root's agent, and says yes to nothing but itself.
struct Agent;

#[zbus::interface(name = "org.freedesktop.GeoClue2.Agent")]
impl Agent {
    async fn authorize_app(&self, desktop_id: String, level: u32) -> (bool, u32) {
        (desktop_id == DESKTOP_ID, level)
    }

    #[zbus(property)]
    async fn max_accuracy_level(&self) -> u32 {
        EXACT
    }
}

/// The agents GeoClue accepts, from all its files; the last one to set them wins.
fn agents(files: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for text in files {
        let mut section = "";
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                section = line;
            } else if section == "[agent]"
                && let Some((k, v)) = line.split_once('=')
                && k.trim() == "whitelist"
            {
                found = v
                    .split(';')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty() && a != DESKTOP_ID)
                    .collect();
            }
        }
    }
    found
}

fn conf_text() -> String {
    let mut paths: Vec<_> = std::fs::read_dir(CONF_DIR)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf") && p != Path::new(CONF))
        .collect();
    paths.sort();
    paths.insert(0, MAIN_CONF.into());
    let files: Vec<String> = paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect();
    let mut list = agents(&files);
    list.push(DESKTOP_ID.into());
    format!(
        "# Added by Sundial while a parent has location turned on. The agents are the ones\n\
         # this computer already had, plus Sundial.\n[agent]\nwhitelist={}\n\n\
         [{DESKTOP_ID}]\nallowed=true\nsystem=true\nusers=\n",
        list.join(";")
    )
}

/// Let Sundial ask GeoClue, or stop letting it. GeoClue reads this when it starts.
async fn permit(on: bool) -> Result<()> {
    if on {
        if !Path::new("/etc/geoclue").exists() {
            bail!("this computer has no location service (GeoClue isn't installed)");
        }
        std::fs::create_dir_all(CONF_DIR)?;
        let text = conf_text();
        if std::fs::read_to_string(CONF).is_ok_and(|t| t == text) {
            return Ok(());
        }
        std::fs::write(CONF, text).with_context(|| format!("writing {CONF}"))?;
    } else {
        match std::fs::remove_file(CONF) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            r => r.with_context(|| format!("removing {CONF}"))?,
        }
    }
    let _ = Command::new("systemctl")
        .args(["try-restart", "geoclue.service"])
        .output()
        .await;
    Ok(())
}

async fn read(bus: &Connection, path: &OwnedObjectPath) -> Result<Fix> {
    let l = Proxy::new(bus, BUS, path.as_ref(), "org.freedesktop.GeoClue2.Location").await?;
    let fix = Fix {
        lat: l.get_property("Latitude").await?,
        lon: l.get_property("Longitude").await?,
        accuracy_m: l.get_property("Accuracy").await?,
        at: Local::now().timestamp(),
    };
    if !fix.valid() {
        bail!("the location service gave an impossible position");
    }
    Ok(fix)
}

async fn locate() -> Result<Fix> {
    // Its own connection: closing it also ends the client and the agent.
    let bus = Connection::system().await.context("no system bus")?;
    bus.object_server().at(AGENT_PATH, Agent).await?;
    let manager = Proxy::new(
        &bus,
        BUS,
        "/org/freedesktop/GeoClue2/Manager",
        "org.freedesktop.GeoClue2.Manager",
    )
    .await?;
    manager
        .call::<_, _, ()>("AddAgent", &DESKTOP_ID)
        .await
        .context("the location service didn't accept Sundial")?;
    let path: OwnedObjectPath = manager
        .call("GetClient", &())
        .await
        .context("the location service isn't available")?;
    let client = Proxy::new(&bus, BUS, path.as_ref(), "org.freedesktop.GeoClue2.Client").await?;
    client.set_property("DesktopId", DESKTOP_ID).await?;
    client.set_property("RequestedAccuracyLevel", EXACT).await?;
    client
        .call::<_, _, ()>("Start", &())
        .await
        .context("the location service refused")?;
    let deadline = tokio::time::Instant::now() + WAIT;
    let mut best: Option<Fix> = None;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Read it fresh; the proxy's cache may be behind.
        let props = zbus::fdo::PropertiesProxy::builder(&bus)
            .destination(BUS)?
            .path(path.as_ref())?
            .build()
            .await?;
        let iface = zbus::names::InterfaceName::try_from("org.freedesktop.GeoClue2.Client")?;
        let v = props.get(iface, "Location").await?;
        let Ok(p) = OwnedObjectPath::try_from(v) else {
            continue;
        };
        if p.as_str() == "/" {
            continue;
        }
        let fix = read(&bus, &p).await?;
        let good = fix.accuracy_m <= GOOD_METERS;
        best = Some(fix);
        if good {
            break;
        }
    }
    let _ = client.call::<_, _, ()>("Stop", &()).await;
    best.context("no position found (is Wi-Fi on?)")
}

/// Ask every few minutes while a parent has it on and a server is paired.
pub async fn run(daemon: Shared) {
    let mut next = 0;
    let mut permitted = None;
    loop {
        let on = daemon.lock().unwrap().location_on() && crate::link::paired();
        if permitted != Some(on) {
            let r = permit(on).await;
            if let Err(e) = &r {
                eprintln!("sundial: location: {e:#}");
                daemon.lock().unwrap().set_location(Err(format!("{e:#}")));
            }
            if r.is_ok() || !on {
                permitted = Some(on);
            }
            next = if r.is_ok() {
                0
            } else {
                Local::now().timestamp() + EVERY
            };
            if r.is_err() && on {
                // Look again later: GeoClue may get installed.
                tokio::time::sleep(POLL * 12).await;
                continue;
            }
        }
        // Wall clock, so a resume from sleep asks right away.
        let now = Local::now().timestamp();
        if on && (now >= next || next - now > EVERY) {
            next = now + EVERY;
            let r = tokio::time::timeout(WAIT * 2, locate())
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("the location service didn't answer")));
            daemon
                .lock()
                .unwrap()
                .set_location(r.map_err(|e| format!("{e:#}")));
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_desktops_agents() {
        let main = "[agent]\n# x\nwhitelist=gnome-shell;phosh;\n[wifi]\nwhitelist=no\n".to_string();
        assert_eq!(
            agents(std::slice::from_ref(&main)),
            ["gnome-shell", "phosh"]
        );
        let later = "[agent]\nwhitelist = kde;sundial\n".to_string();
        assert_eq!(agents(&[main, later]), ["kde"]);
        assert!(agents(&[]).is_empty());
    }
}
