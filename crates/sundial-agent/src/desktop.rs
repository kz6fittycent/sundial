//! Per-desktop sources for what the agent reports: the focused window, idle time,
//! whether the screen is locked, and whether media is playing.
//!
//! | Desktop             | Focused window                    | Idle time                      |
//! |---------------------|-----------------------------------|--------------------------------|
//! | GNOME (Wayland/X11) | Sundial GNOME Shell extension     | Mutter IdleMonitor             |
//! | KDE Plasma          | KWin script loaded at sign-in     | org.freedesktop.ScreenSaver    |
//! | Cinnamon/MATE/Xfce  | X11 (_NET_ACTIVE_WINDOW)          | X11 screensaver extension      |
//!
//! Any X11 session falls back to the X11 sources. Media playing (MPRIS) counts as
//! not idle, so watching a video isn't mistaken for walking away.

use gtk::prelude::*;
use gtk::{gio, glib};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sundial_core::activity::Focus;
use sundial_core::proto::AgentReport;
use x11rb::connection::Connection;
use x11rb::protocol::screensaver::ConnectionExt as _;
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, Window};
use x11rb::rust_connection::RustConnection;

// The Sundial GNOME Shell extension (packaging/gnome-extension) answers this.
const EXT_UUID: &str = "sundial@kz6fittycent.github.io";
const EXT_BUS: &str = "io.github.kz6fittycent.Sundial.Focus";
const EXT_PATH: &str = "/io/github/kz6fittycent/Sundial/Focus";

// The agent's own D-Bus object; the KWin script calls SetFocus on it.
const AGENT_BUS: &str = "io.github.kz6fittycent.Sundial.Agent";
const AGENT_PATH: &str = "/io/github/kz6fittycent/Sundial/Agent";
const AGENT_XML: &str = r#"<node>
  <interface name="io.github.kz6fittycent.Sundial.Agent">
    <method name="SetFocus">
      <arg type="s" direction="in" name="app_id"/>
      <arg type="s" direction="in" name="app_name"/>
      <arg type="s" direction="in" name="title"/>
    </method>
  </interface>
</node>"#;

const KWIN_SCRIPT_NAME: &str = "sundial-activity";
const KWIN_SCRIPT: &str = r#"// Sundial: tell the Sundial agent which window is active (Plasma 5 and 6).
// Title changes are hooked per window when it appears; windows are often
// activated before their title is set.
const S = "io.github.kz6fittycent.Sundial.Agent";
const P = "/io/github/kz6fittycent/Sundial/Agent";
function active() {
    return workspace.activeWindow !== undefined ? workspace.activeWindow : workspace.activeClient;
}
function send(w) {
    callDBus(S, P, S, "SetFocus",
        w ? String(w.desktopFileName || "") : "",
        w ? String(w.resourceClass || "") : "",
        w ? String(w.caption || "") : "");
}
function hook(w) {
    if (w && w.captionChanged)
        w.captionChanged.connect(function () { if (active() === w) send(w); });
}
const list = workspace.windowList ? workspace.windowList() : workspace.clientList();
for (let i = 0; i < list.length; i++)
    hook(list[i]);
(workspace.windowAdded || workspace.clientAdded).connect(hook);
(workspace.windowActivated || workspace.clientActivated).connect(send);
send(active());
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gnome,
    Kde,
    /// Cinnamon, MATE, Xfce, or any other X11 session.
    X11,
    /// A Wayland desktop we have no focus source for.
    Unknown,
}

/// True for an X11 session. (Wayland sessions also set DISPLAY for XWayland, but
/// XWayland only sees X11 apps, so its idle time and focus would be wrong.)
fn x11_session() -> bool {
    std::env::var("XDG_SESSION_TYPE")
        .map(|t| t == "x11")
        .unwrap_or(false)
        || (std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_some())
}

pub fn detect() -> Kind {
    let desk = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();
    let x11 = x11_session();
    if desk.split(':').any(|d| d == "GNOME" || d == "UBUNTU") && !desk.contains("CINNAMON") {
        Kind::Gnome
    } else if desk.split(':').any(|d| d == "KDE") {
        Kind::Kde
    } else if x11 {
        Kind::X11
    } else {
        Kind::Unknown
    }
}

/// Focus pushed by the KWin script: (when, focus).
type Pushed = Arc<Mutex<Option<(Instant, Focus)>>>;

pub struct Desktop {
    kind: Kind,
    bus: Option<gio::DBusConnection>,
    x11: Option<X11>,
    pushed: Pushed,
    _registration: Option<gio::RegistrationId>,
}

impl Desktop {
    pub fn new() -> Desktop {
        let kind = detect();
        let bus = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).ok();
        let x11 = if x11_session() { X11::connect() } else { None };
        let pushed: Pushed = Arc::default();
        let mut registration = None;
        if kind == Kind::Kde
            && let Some(bus) = &bus
        {
            registration = export_agent(bus, pushed.clone());
        }
        let mut d = Desktop {
            kind,
            bus,
            x11,
            pushed,
            _registration: registration,
        };
        d.maintain();
        d
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Re-arm the focus source (it may have been turned off). Called every minute.
    pub fn maintain(&mut self) {
        match self.kind {
            Kind::Gnome => ensure_extension(),
            Kind::Kde => {
                if let Some(bus) = &self.bus {
                    ensure_kwin_script(bus);
                }
            }
            Kind::X11 => {
                if self.x11.is_none() {
                    self.x11 = X11::connect();
                }
            }
            Kind::Unknown => {}
        }
    }

    pub fn report(&mut self) -> AgentReport {
        let (focus, source) = self.focus();
        let idle_secs = self.idle_secs();
        AgentReport {
            focus_ok: focus.is_some(),
            focus,
            source: source.into(),
            idle_secs,
            media_playing: self.bus.as_ref().is_some_and(media_playing),
            locked: self.bus.as_ref().and_then(screensaver_active),
        }
    }

    fn focus(&mut self) -> (Option<Focus>, &'static str) {
        match self.kind {
            Kind::Gnome => {
                let f = self.bus.as_ref().and_then(gnome_focus);
                // GNOME on X11 without the extension: X11 still works.
                if f.is_none()
                    && let Some(x) = &self.x11
                {
                    return (x.focus(), "X11");
                }
                (f, "GNOME extension")
            }
            Kind::Kde => {
                let f = self
                    .pushed
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|(t, _)| t.elapsed().as_secs() < 30 * 60)
                    .map(|(_, f)| f.clone());
                match f {
                    Some(f) => (Some(f), "KWin script"),
                    None => (self.x11.as_ref().and_then(X11::focus), "KWin script"),
                }
            }
            Kind::X11 => {
                let f = self.x11.as_ref().and_then(X11::focus);
                if f.is_none() {
                    self.x11 = None; // reconnect on the next maintain()
                }
                (f, "X11")
            }
            Kind::Unknown => (None, "none"),
        }
    }

    fn idle_secs(&self) -> Option<u64> {
        if let Some(x) = &self.x11
            && let Some(ms) = x.idle_ms()
        {
            return Some(ms / 1000);
        }
        let bus = self.bus.as_ref()?;
        match self.kind {
            Kind::Gnome => call::<(u64,)>(
                bus,
                "org.gnome.Mutter.IdleMonitor",
                "/org/gnome/Mutter/IdleMonitor/Core",
                "org.gnome.Mutter.IdleMonitor",
                "GetIdletime",
                "(t)",
            )
            .map(|(ms,)| ms / 1000),
            Kind::Kde => call::<(u32,)>(
                bus,
                "org.freedesktop.ScreenSaver",
                "/ScreenSaver",
                "org.freedesktop.ScreenSaver",
                "GetSessionIdleTime",
                "(u)",
            )
            .map(|(s,)| u64::from(s)),
            _ => None,
        }
    }
}

fn call<T: glib::variant::FromVariant>(
    bus: &gio::DBusConnection,
    dest: &str,
    path: &str,
    iface: &str,
    method: &str,
    reply: &str,
) -> Option<T> {
    bus.call_sync(
        Some(dest),
        path,
        iface,
        method,
        None,
        Some(glib::VariantTy::new(reply).ok()?),
        gio::DBusCallFlags::NO_AUTO_START,
        1000,
        gio::Cancellable::NONE,
    )
    .ok()?
    .get::<T>()
}

fn gnome_focus(bus: &gio::DBusConnection) -> Option<Focus> {
    let (app_id, app_name, title) =
        call::<(String, String, String)>(bus, EXT_BUS, EXT_PATH, EXT_BUS, "GetFocus", "(sss)")?;
    Some(Focus {
        app_id,
        app_name,
        title,
    })
}

/// Keep the GNOME extension enabled for this account (it may have been turned off).
fn ensure_extension() {
    let Some(src) = gio::SettingsSchemaSource::default() else {
        return;
    };
    if src.lookup("org.gnome.shell", true).is_none() {
        return;
    }
    let st = gio::Settings::new("org.gnome.shell");
    if st.boolean("disable-user-extensions") {
        let _ = st.set_boolean("disable-user-extensions", false);
    }
    let list = |k: &str| -> Vec<String> { st.strv(k).iter().map(|s| s.to_string()).collect() };
    let mut enabled = list("enabled-extensions");
    if !enabled.iter().any(|e| e == EXT_UUID) {
        enabled.push(EXT_UUID.into());
        let v: Vec<&str> = enabled.iter().map(String::as_str).collect();
        let _ = st.set_strv("enabled-extensions", v.as_slice());
    }
    let disabled = list("disabled-extensions");
    if disabled.iter().any(|e| e == EXT_UUID) {
        let v: Vec<&str> = disabled
            .iter()
            .map(String::as_str)
            .filter(|e| *e != EXT_UUID)
            .collect();
        let _ = st.set_strv("disabled-extensions", v.as_slice());
    }
    gio::Settings::sync();
}

/// Own the agent's bus name and accept SetFocus from the KWin script.
fn export_agent(bus: &gio::DBusConnection, pushed: Pushed) -> Option<gio::RegistrationId> {
    let node = gio::DBusNodeInfo::for_xml(AGENT_XML).ok()?;
    let iface = node.lookup_interface(AGENT_BUS)?;
    let id = bus
        .register_object(AGENT_PATH, &iface)
        .method_call(
            move |_conn, _sender, _path, _iface, method, params, invocation| {
                if method == "SetFocus"
                    && let Some((app_id, app_name, title)) =
                        params.get::<(String, String, String)>()
                {
                    *pushed.lock().unwrap() = Some((
                        Instant::now(),
                        Focus {
                            app_id,
                            app_name,
                            title,
                        },
                    ));
                }
                invocation.return_value(None);
            },
        )
        .build()
        .ok()?;
    // The name stays owned for the agent's lifetime (OwnerId has no Drop).
    let _owner = gio::bus_own_name_on_connection(
        bus,
        AGENT_BUS,
        gio::BusNameOwnerFlags::REPLACE,
        |_, _| {},
        |_, _| {},
    );
    Some(id)
}

/// Load the activity script into KWin if it isn't running.
fn ensure_kwin_script(bus: &gio::DBusConnection) {
    let loaded = bus
        .call_sync(
            Some("org.kde.KWin"),
            "/Scripting",
            "org.kde.kwin.Scripting",
            "isScriptLoaded",
            Some(&(KWIN_SCRIPT_NAME,).to_variant()),
            Some(glib::VariantTy::new("(b)").expect("type")),
            gio::DBusCallFlags::NO_AUTO_START,
            2000,
            gio::Cancellable::NONE,
        )
        .ok()
        .and_then(|v| v.get::<(bool,)>())
        .map(|(b,)| b);
    if loaded != Some(false) {
        return; // already loaded, or KWin not reachable
    }
    let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    let path = format!("{dir}/sundial-kwin.js");
    if std::fs::write(&path, KWIN_SCRIPT).is_err() {
        return;
    }
    let id = bus
        .call_sync(
            Some("org.kde.KWin"),
            "/Scripting",
            "org.kde.kwin.Scripting",
            "loadScript",
            Some(&(path.as_str(), KWIN_SCRIPT_NAME).to_variant()),
            Some(glib::VariantTy::new("(i)").expect("type")),
            gio::DBusCallFlags::NO_AUTO_START,
            2000,
            gio::Cancellable::NONE,
        )
        .ok()
        .and_then(|v| v.get::<(i32,)>())
        .map(|(i,)| i);
    let Some(id) = id.filter(|i| *i >= 0) else {
        return;
    };
    // Plasma 6 / late Plasma 5 path first, then the older one.
    for obj in [format!("/Scripting/Script{id}"), format!("/{id}")] {
        if bus
            .call_sync(
                Some("org.kde.KWin"),
                &obj,
                "org.kde.kwin.Script",
                "run",
                None,
                None,
                gio::DBusCallFlags::NO_AUTO_START,
                2000,
                gio::Cancellable::NONE,
            )
            .is_ok()
        {
            break;
        }
    }
}

/// Any MPRIS player (browsers included) currently playing.
fn media_playing(bus: &gio::DBusConnection) -> bool {
    let Some((names,)) = call::<(Vec<String>,)>(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ListNames",
        "(as)",
    ) else {
        return false;
    };
    names
        .iter()
        .filter(|n| n.starts_with("org.mpris.MediaPlayer2."))
        .any(|n| {
            bus.call_sync(
                Some(n),
                "/org/mpris/MediaPlayer2",
                "org.freedesktop.DBus.Properties",
                "Get",
                Some(&("org.mpris.MediaPlayer2.Player", "PlaybackStatus").to_variant()),
                Some(glib::VariantTy::new("(v)").expect("type")),
                gio::DBusCallFlags::NO_AUTO_START,
                500,
                gio::Cancellable::NONE,
            )
            .ok()
            .and_then(|v| v.child_value(0).as_variant())
            .and_then(|v| v.get::<String>())
            .is_some_and(|s| s == "Playing")
        })
}

/// Screen locker state from whichever screensaver service this desktop runs.
fn screensaver_active(bus: &gio::DBusConnection) -> Option<bool> {
    const SERVICES: [(&str, &str, &str); 5] = [
        (
            "org.gnome.ScreenSaver",
            "/org/gnome/ScreenSaver",
            "org.gnome.ScreenSaver",
        ),
        (
            "org.freedesktop.ScreenSaver",
            "/ScreenSaver",
            "org.freedesktop.ScreenSaver",
        ),
        (
            "org.cinnamon.ScreenSaver",
            "/org/cinnamon/ScreenSaver",
            "org.cinnamon.ScreenSaver",
        ),
        (
            "org.mate.ScreenSaver",
            "/org/mate/ScreenSaver",
            "org.mate.ScreenSaver",
        ),
        (
            "org.xfce.ScreenSaver",
            "/org/xfce/ScreenSaver",
            "org.xfce.ScreenSaver",
        ),
    ];
    SERVICES
        .iter()
        .find_map(|(d, p, i)| call::<(bool,)>(bus, d, p, i, "GetActive", "(b)").map(|(b,)| b))
}

/// X11: active window via EWMH, idle via the MIT-SCREEN-SAVER extension.
struct X11 {
    conn: RustConnection,
    root: Window,
    active: u32,
    net_name: u32,
    utf8: u32,
    gtk_app_id: u32,
    kde_desktop_file: u32,
}

impl X11 {
    fn connect() -> Option<X11> {
        std::env::var_os("DISPLAY")?;
        let (conn, screen) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        let atom = |name: &str| -> Option<u32> {
            Some(
                conn.intern_atom(false, name.as_bytes())
                    .ok()?
                    .reply()
                    .ok()?
                    .atom,
            )
        };
        Some(X11 {
            active: atom("_NET_ACTIVE_WINDOW")?,
            net_name: atom("_NET_WM_NAME")?,
            utf8: atom("UTF8_STRING")?,
            gtk_app_id: atom("_GTK_APPLICATION_ID")?,
            kde_desktop_file: atom("_KDE_NET_WM_DESKTOP_FILE")?,
            conn,
            root,
        })
    }

    fn prop(&self, win: Window, atom: u32, ty: u32) -> Option<Vec<u8>> {
        let r = self
            .conn
            .get_property(false, win, atom, ty, 0, 4096)
            .ok()?
            .reply()
            .ok()?;
        (!r.value.is_empty()).then_some(r.value)
    }

    fn text(&self, win: Window, atom: u32, ty: u32) -> Option<String> {
        self.prop(win, atom, ty).map(|v| {
            String::from_utf8_lossy(&v)
                .trim_end_matches('\0')
                .to_string()
        })
    }

    fn focus(&self) -> Option<Focus> {
        let v = self.prop(self.root, self.active, AtomEnum::WINDOW.into())?;
        let win = u32::from_ne_bytes(v.get(..4)?.try_into().ok()?);
        if win == 0 {
            return Some(Focus::default());
        }
        let title = self
            .text(win, self.net_name, self.utf8)
            .or_else(|| self.text(win, AtomEnum::WM_NAME.into(), AtomEnum::STRING.into()))
            .unwrap_or_default();
        // WM_CLASS is "instance\0Class\0"; the class is the readable one.
        let class = self
            .prop(win, AtomEnum::WM_CLASS.into(), AtomEnum::STRING.into())
            .map(|v| {
                let parts: Vec<String> = v
                    .split(|b| *b == 0)
                    .filter(|p| !p.is_empty())
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                parts.last().cloned().unwrap_or_default()
            })
            .unwrap_or_default();
        let app_id = self
            .text(win, self.gtk_app_id, self.utf8)
            .or_else(|| self.text(win, self.kde_desktop_file, self.utf8))
            .unwrap_or_default();
        Some(Focus {
            app_id,
            app_name: class,
            title,
        })
    }

    fn idle_ms(&self) -> Option<u64> {
        let r = self
            .conn
            .screensaver_query_info(self.root)
            .ok()?
            .reply()
            .ok()?;
        Some(u64::from(r.ms_since_user_input))
    }
}
