//! Fitting in: the desktop's own window borders, theme, accent color and dark mode.
//!
//! Colors come only from the theme's named colors. GTK picks up the theme, fonts and
//! icons by itself (XSettings on X11, the settings portal on Wayland).

use gtk::prelude::*;
use gtk::{gdk, gio, glib};

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const SETTINGS: &str = "org.freedesktop.portal.Settings";
const APPEARANCE: &str = "org.freedesktop.appearance";

const CSS: &str = "
.s-card{background-color:@theme_base_color;color:@theme_text_color;border:1px solid alpha(@theme_fg_color,.15);border-radius:8px;padding:16px;}
.s-title{font-weight:bold;font-size:115%;}
.s-big{font-weight:bold;font-size:130%;}
.s-muted{opacity:.7;}
.s-pill{border:1px solid currentColor;border-radius:99px;padding:0 10px;font-weight:bold;font-size:90%;}
.s-ok{color:@success_color;}
.s-wait{color:@warning_color;}
.s-step{border:1px solid alpha(@theme_fg_color,.25);border-radius:99px;padding:2px 12px;}
.s-step.on{background-color:@theme_selected_bg_color;color:@theme_selected_fg_color;border-color:@theme_selected_bg_color;font-weight:bold;}
progressbar.s-bar>trough,progressbar.s-bar>trough>progress{min-height:8px;}
";

/// GNOME windows draw their own title bar with buttons in it. Everywhere else the
/// window manager draws it, so it matches the other windows.
pub fn own_title_bar() -> bool {
    let d = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    wants_own_title_bar(&d)
}

fn wants_own_title_bar(desktop: &str) -> bool {
    desktop
        .split(':')
        .any(|d| d.eq_ignore_ascii_case("gnome") || d.eq_ignore_ascii_case("unity"))
}

pub fn init() {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let css = gtk::CssProvider::new();
    css.load_from_data(CSS);
    gtk::style_context_add_provider_for_display(
        &display,
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    let accent = gtk::CssProvider::new();
    // Above the theme, so it replaces the theme's accent where that is only a default.
    gtk::style_context_add_provider_for_display(
        &display,
        &accent,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
    );
    follow_portal(accent);
}

/// The stock theme knows nothing of the desktop's accent color; a desktop's own theme
/// already has it.
fn stock_theme() -> bool {
    gtk::Settings::default()
        .and_then(|s| s.gtk_theme_name())
        .is_none_or(|t| {
            let t = t.to_lowercase();
            t.starts_with("adwaita") || t.starts_with("default") || t == "empty"
        })
}

fn apply(accent: &gtk::CssProvider, key: &str, v: &glib::Variant) {
    match key {
        "color-scheme" => {
            if let (Some(n), Some(s)) = (v.get::<u32>(), gtk::Settings::default())
                && n > 0
            {
                s.set_gtk_application_prefer_dark_theme(n == 1);
            }
        }
        "accent-color" => {
            if let Some((r, g, b)) = v.get::<(f64, f64, f64)>()
                && [r, g, b].iter().all(|c| (0.0..=1.0).contains(c))
                && stock_theme()
            {
                accent.load_from_data(&accent_css(r, g, b));
            }
        }
        _ => {}
    }
}

fn accent_css(r: f64, g: f64, b: f64) -> String {
    let c = |x: f64| (x * 255.0).round() as u8;
    // Black or white text, whichever reads better on it.
    let light = 0.299 * r + 0.587 * g + 0.114 * b > 0.6;
    let fg = if light { "#000" } else { "#fff" };
    format!(
        "@define-color theme_selected_bg_color rgb({0},{1},{2});@define-color theme_selected_fg_color {fg};\
         button.suggested-action,button.suggested-action:hover{{background-image:none;background-color:rgb({0},{1},{2});color:{fg};}}\
         progressbar>trough>progress{{background-color:rgb({0},{1},{2});border-color:rgb({0},{1},{2});}}",
        c(r),
        c(g),
        c(b)
    )
}

fn follow_portal(accent: gtk::CssProvider) {
    glib::spawn_future_local(async move {
        let Ok(bus) = gio::bus_get_future(gio::BusType::Session).await else {
            return;
        };
        for key in ["color-scheme", "accent-color"] {
            let r = bus
                .call_future(
                    Some(PORTAL),
                    PORTAL_PATH,
                    SETTINGS,
                    "ReadOne",
                    Some(&(APPEARANCE, key).to_variant()),
                    None,
                    gio::DBusCallFlags::NONE,
                    3000,
                )
                .await;
            if let Ok(v) = r
                && let Some(inner) = v.child_value(0).as_variant()
            {
                apply(&accent, key, &inner);
            }
        }
        #[allow(deprecated)]
        let id = bus.signal_subscribe(
            Some(PORTAL),
            Some(SETTINGS),
            Some("SettingChanged"),
            Some(PORTAL_PATH),
            Some(APPEARANCE),
            gio::DBusSignalFlags::NONE,
            move |_, _, _, _, _, v| {
                if v.n_children() == 3
                    && let (Some(key), Some(inner)) =
                        (v.child_value(1).str(), v.child_value(2).as_variant())
                {
                    apply(&accent, key, &inner);
                }
            },
        );
        // For as long as the app runs.
        std::mem::forget((bus, id));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_bars() {
        for d in ["GNOME", "ubuntu:GNOME", "Unity"] {
            assert!(wants_own_title_bar(d), "{d}");
        }
        for d in ["KDE", "X-Cinnamon", "MATE", "XFCE", ""] {
            assert!(!wants_own_title_bar(d), "{d}");
        }
    }

    #[test]
    fn readable_accent() {
        assert!(accent_css(1.0, 0.9, 0.2).contains("#000"));
        assert!(accent_css(0.1, 0.2, 0.6).contains("#fff"));
    }
}
