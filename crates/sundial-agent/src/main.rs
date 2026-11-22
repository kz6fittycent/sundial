//! sundial-agent: runs in each desktop session (XDG autostart). It only displays what
//! the root daemon decides: a "time left" notice at sign-in, a 15 minute warning, and
//! a countdown window before the session ends. Killing it changes nothing about the
//! limits; the daemon then falls back to plain notifications.

use gtk::prelude::*;
use gtk::{gio, glib};
use std::cell::RefCell;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sundial_core::activity::Focus;
use sundial_core::config::AGENT_SOCKET;
use sundial_core::proto::{AgentReport, AgentStatus};
use sundial_core::rules::fmt_duration;

const APP_ID: &str = "io.github.kz6fittycent.Sundial";
const EARLY_WARNING: i64 = 15 * 60;

// The Sundial GNOME Shell extension (packaging/gnome-extension) answers this.
const EXT_UUID: &str = "sundial@kz6fittycent.github.io";
const EXT_BUS: &str = "io.github.kz6fittycent.Sundial.Focus";
const EXT_PATH: &str = "/io/github/kz6fittycent/Sundial/Focus";
const EXT_IFACE: &str = "io.github.kz6fittycent.Sundial.Focus";

/// Write side of the daemon connection, set by the reader thread.
type Writer = Arc<Mutex<Option<UnixStream>>>;

/// The focused window, from the extension. None if it doesn't answer.
fn focus(conn: &gio::DBusConnection) -> Option<Focus> {
    let v = conn
        .call_sync(
            Some(EXT_BUS),
            EXT_PATH,
            EXT_IFACE,
            "GetFocus",
            None,
            Some(glib::VariantTy::new("(sss)").expect("valid type")),
            gio::DBusCallFlags::NO_AUTO_START,
            1000,
            gio::Cancellable::NONE,
        )
        .ok()?;
    let (app_id, app_name, title) = v.get::<(String, String, String)>()?;
    Some(Focus {
        app_id,
        app_name,
        title,
    })
}

/// Keep the extension enabled for this account (it may have been turned off).
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

fn send_report(writer: &Writer, report: &AgentReport) {
    let mut guard = writer.lock().unwrap();
    if let Some(s) = guard.as_mut() {
        let mut line = serde_json::to_string(report).unwrap_or_default();
        line.push('\n');
        if s.write_all(line.as_bytes()).is_err() {
            *guard = None;
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Background thread: keep a connection to the daemon and forward each status line.
fn reader(tx: mpsc::Sender<AgentStatus>, writer: Writer) {
    loop {
        if let Ok(s) = UnixStream::connect(AGENT_SOCKET) {
            *writer.lock().unwrap() = s.try_clone().ok();
            for line in BufReader::new(s).lines() {
                let Ok(line) = line else { break };
                if let Ok(st) = serde_json::from_str::<AgentStatus>(&line)
                    && tx.send(st).is_err()
                {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

struct Ui {
    app: gtk::Application,
    window: gtk::ApplicationWindow,
    big: gtk::Label,
    small: gtk::Label,
    status: Option<AgentStatus>,
    greeted: bool,
    warned_early: bool,
    /// Deadline the current countdown is for.
    countdown_for: Option<i64>,
    dismissed: bool,
    last_minute_shown: bool,
}

impl Ui {
    fn notify(&self, title: &str, body: &str, urgent: bool) {
        let n = gio::Notification::new(title);
        n.set_body(Some(body));
        n.set_priority(if urgent {
            gio::NotificationPriority::Urgent
        } else {
            gio::NotificationPriority::Normal
        });
        self.app.send_notification(Some("sundial"), &n);
    }

    fn show(&mut self) {
        self.dismissed = false;
        self.window.present();
    }

    fn update(&mut self) {
        let Some(st) = self.status.clone() else {
            return;
        };
        if !st.managed {
            self.app.quit();
            return;
        }
        let now = unix_now();
        if !self.greeted {
            self.greeted = true;
            if st.remaining_secs.is_some() {
                self.notify("Sundial", &st.message, false);
            }
        }
        if let Some(r) = st.remaining_secs {
            if r > EARLY_WARNING + 60 {
                self.warned_early = false;
            } else if r > 6 * 60 && !self.warned_early && st.allowed {
                self.warned_early = true;
                self.notify("15 minutes left", &st.message, false);
            }
        }

        let verb = if st.action == "lock" {
            "Locking the screen"
        } else {
            "Logging out"
        };
        match st.deadline {
            Some(d) => {
                if self.countdown_for.is_none_or(|c| (c - d).abs() > 15) {
                    self.countdown_for = Some(d);
                    self.last_minute_shown = false;
                    self.notify(
                        "Time's almost up",
                        &format!("{} Save your game now.", st.message),
                        true,
                    );
                    self.show();
                }
                let left = (d - now).max(0);
                self.big.set_markup(&format!(
                    "<span size='xx-large' weight='bold'>{}:{:02}</span>",
                    left / 60,
                    left % 60
                ));
                self.small.set_text(&format!(
                    "{verb} soon. Save your game or work now.\n{}",
                    st.message
                ));
                if self.dismissed && left <= 60 && !self.last_minute_shown {
                    self.last_minute_shown = true;
                    self.show();
                }
            }
            None => {
                if self.countdown_for.take().is_some() {
                    self.window.set_visible(false);
                }
                let big = match st.remaining_secs {
                    Some(r) if st.allowed => format!("{} left", fmt_duration(r)),
                    Some(_) => "Time's up".into(),
                    None => "No limit right now".into(),
                };
                self.big.set_markup(&format!(
                    "<span size='x-large' weight='bold'>{}</span>",
                    glib::markup_escape_text(&big)
                ));
                self.small.set_text(&st.message);
            }
        }
    }
}

fn build(app: &gtk::Application) {
    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Sundial")
        .default_width(420)
        .resizable(false)
        .hide_on_close(true)
        .build();
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 12);
    vbox.set_margin_top(24);
    vbox.set_margin_bottom(20);
    vbox.set_margin_start(24);
    vbox.set_margin_end(24);
    let big = gtk::Label::new(None);
    let small = gtk::Label::new(None);
    small.set_wrap(true);
    small.set_justify(gtk::Justification::Center);
    let ok = gtk::Button::with_label("OK");
    ok.set_halign(gtk::Align::Center);
    vbox.append(&big);
    vbox.append(&small);
    vbox.append(&ok);
    window.set_child(Some(&vbox));

    let (tx, rx) = mpsc::channel();
    let writer: Writer = Arc::new(Mutex::new(None));
    {
        let writer = writer.clone();
        std::thread::spawn(move || reader(tx, writer));
    }

    let ui = Rc::new(RefCell::new(Ui {
        app: app.clone(),
        window: window.clone(),
        big,
        small,
        status: None,
        greeted: false,
        warned_early: false,
        countdown_for: None,
        dismissed: false,
        last_minute_shown: false,
    }));
    {
        let ui = ui.clone();
        ok.connect_clicked(move |_| {
            let mut u = ui.borrow_mut();
            u.dismissed = true;
            u.window.set_visible(false);
        });
    }
    {
        let ui = ui.clone();
        window.connect_close_request(move |_| {
            ui.borrow_mut().dismissed = true;
            glib::Propagation::Proceed
        });
    }
    {
        // Clicking a notification (or launching the app again) shows the window.
        let ui = ui.clone();
        app.connect_activate(move |_| {
            let mut u = ui.borrow_mut();
            if u.status.is_some() {
                u.update();
                u.show();
            }
        });
    }
    // Activity: report the focused window every 5 s; re-enable the extension every minute.
    let bus = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).ok();
    {
        let ui = ui.clone();
        let mut ticks = 0u32;
        glib::timeout_add_local(Duration::from_secs(5), move || {
            if !ui.borrow().status.as_ref().is_some_and(|s| s.managed) {
                return glib::ControlFlow::Continue;
            }
            if ticks.is_multiple_of(12) {
                ensure_extension();
            }
            ticks = ticks.wrapping_add(1);
            let focus = bus.as_ref().and_then(focus);
            let report = AgentReport {
                extension: focus.is_some(),
                focus,
            };
            send_report(&writer, &report);
            glib::ControlFlow::Continue
        });
    }
    glib::timeout_add_local(Duration::from_secs(1), move || {
        let mut u = ui.borrow_mut();
        while let Ok(st) = rx.try_recv() {
            u.status = Some(st);
        }
        u.update();
        glib::ControlFlow::Continue
    });
}

fn main() -> glib::ExitCode {
    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|app| {
        // No window most of the time; stay running anyway.
        std::mem::forget(app.hold());
        build(app);
    });
    app.run_with_args::<&str>(&[])
}
