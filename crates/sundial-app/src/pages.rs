//! The window's pages, built from Sundial's status.

use gtk::prelude::*;
use sundial_core::config::{Action, Window};
use sundial_core::proto::{ActivityLine, UsageBar, UserStatus};
use sundial_core::rules::fmt_duration;

const DAYS: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

pub fn label(text: &str, classes: &[&str]) -> gtk::Label {
    let l = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .wrap(true)
        .build();
    l.set_css_classes(classes);
    l
}

pub fn column(gap: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Vertical, gap)
}

pub fn row(gap: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, gap)
}

pub fn card(title: &str) -> gtk::Box {
    let c = column(10);
    c.add_css_class("s-card");
    if !title.is_empty() {
        c.append(&label(title, &["s-title"]));
    }
    c
}

pub fn button(text: &str, class: Option<&str>) -> gtk::Button {
    let b = gtk::Button::with_label(text);
    if let Some(c) = class {
        b.add_css_class(c);
    }
    b.set_halign(gtk::Align::Start);
    b
}

/// A scrolling page with the same margins everywhere.
pub fn page(parts: &[gtk::Widget]) -> gtk::ScrolledWindow {
    let c = column(14);
    c.set_margin_top(16);
    c.set_margin_bottom(16);
    c.set_margin_start(16);
    c.set_margin_end(16);
    for p in parts {
        c.append(p);
    }
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .hexpand(true)
        .vexpand(true)
        .child(&c)
        .build()
}

fn bar(fraction: f64) -> gtk::ProgressBar {
    gtk::ProgressBar::builder()
        .fraction(fraction.clamp(0.0, 1.0))
        .css_classes(["s-bar"])
        .build()
}

fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

pub fn today(u: &UserStatus) -> gtk::Widget {
    let main = card("");
    let head = row(10);
    head.append(&label(&u.name, &["s-title"]));
    let (text, class) = if u.verdict.is_allowed() {
        ("Allowed", "s-ok")
    } else {
        ("Not now", "s-wait")
    };
    let pill = label(text, &["s-pill", class]);
    pill.set_valign(gtk::Align::Center);
    head.append(&pill);
    let left = column(8);
    left.set_hexpand(true);
    left.append(&head);
    left.append(&label(&u.summary, &["s-big"]));
    left.append(&bar(share(u.used_secs, u.session_secs)));
    left.append(&label(
        &format!(
            "Session {} of {}. Today {}, allowed {}.",
            fmt_duration(u.used_secs as i64),
            fmt_duration(u.session_secs as i64),
            fmt_duration(u.today_active_secs as i64),
            u.schedule_today
        ),
        &["s-muted"],
    ));
    if let Some(now) = &u.now_doing {
        left.append(&label(&format!("Now: {now}"), &["s-muted"]));
    }
    let top = row(24);
    top.append(&left);
    top.append(&chart(&u.usage_days));
    main.append(&top);
    let buttons = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .column_spacing(6)
        .row_spacing(6)
        .max_children_per_line(8)
        .build();
    for (text, class) in [
        ("+15 min", Some("suggested-action")),
        ("+30 min", None),
        ("+1 hour", None),
        ("\u{2212}15 min", None),
        ("End break", None),
        ("Lock in 5 min", None),
        ("Lock now", Some("destructive-action")),
    ] {
        buttons.insert(&button(text, class), -1);
    }
    main.append(&buttons);

    let list = card("Today's activity");
    let total: u64 = u.activity_today.iter().map(|a| a.secs).sum();
    if u.activity_today.is_empty() {
        list.append(&label("Nothing yet.", &["s-muted"]));
    }
    for a in &u.activity_today {
        list.append(&activity(a, total));
    }
    page(&[main.upcast(), list.upcast()]).upcast()
}

fn activity(a: &ActivityLine, total: u64) -> gtk::Box {
    let c = column(4);
    let line = row(8);
    let name = label(&a.name, &[]);
    name.set_hexpand(true);
    line.append(&name);
    line.append(&label(&fmt_duration(a.secs as i64), &["s-muted"]));
    c.append(&line);
    c.append(&bar(share(a.secs, total)));
    c
}

fn chart(days: &[UsageBar]) -> gtk::DrawingArea {
    let week: Vec<UsageBar> = days[days.len().saturating_sub(7)..].to_vec();
    let max = week.iter().map(|d| d.secs).max().unwrap_or(0).max(3600) as f64;
    let d = gtk::DrawingArea::builder()
        .content_width(260)
        .content_height(130)
        .accessible_role(gtk::AccessibleRole::Img)
        .build();
    let said: Vec<String> = week
        .iter()
        .map(|b| format!("{} {}", b.date, fmt_duration(b.secs as i64)))
        .collect();
    d.update_property(&[gtk::accessible::Property::Label(&format!(
        "Usage this week: {}",
        said.join(", ")
    ))]);
    d.set_draw_func(move |a, c, w, h| {
        #[allow(deprecated)]
        let style = a.style_context();
        #[allow(deprecated)]
        let fg = style.color();
        #[allow(deprecated)]
        let accent = style.lookup_color("theme_selected_bg_color").unwrap_or(fg);
        let slot = f64::from(w) / week.len().max(1) as f64;
        let floor = f64::from(h) - 20.0;
        for (i, day) in week.iter().enumerate() {
            let today = i + 1 == week.len();
            let tall = (floor - 4.0) * day.secs as f64 / max;
            c.set_source_rgba(
                accent.red().into(),
                accent.green().into(),
                accent.blue().into(),
                if today { 1.0 } else { 0.5 },
            );
            c.rectangle(
                i as f64 * slot + slot * 0.18,
                floor - tall,
                slot * 0.64,
                tall,
            );
            let _ = c.fill();
            // The theme's font, so the chart matches the rest.
            let text = a.create_pango_layout(Some(day.date.rsplit('-').next().unwrap_or("")));
            c.set_source_rgba(fg.red().into(), fg.green().into(), fg.blue().into(), 0.7);
            let tw = f64::from(text.pixel_size().0);
            c.move_to(i as f64 * slot + (slot - tw) / 2.0, floor + 1.0);
            pangocairo::functions::show_layout(c, &text);
        }
    });
    d
}

fn clock(m: u32) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

pub fn limits(u: &UserStatus) -> gtk::Widget {
    let p = &u.policy;
    let grid = || {
        gtk::Grid::builder()
            .column_spacing(12)
            .row_spacing(8)
            .build()
    };
    let first = card(&format!("Limits for {}", u.name));
    let g = grid();
    for (i, (text, n)) in [
        ("Session (minutes)", p.session_minutes),
        ("Break (minutes)", p.break_minutes),
        ("Warning (minutes)", p.warn_minutes),
    ]
    .iter()
    .enumerate()
    {
        let spin = gtk::SpinButton::with_range(0.0, 1440.0, 5.0);
        spin.set_value(f64::from(*n));
        g.attach(&label(text, &[]), 0, i as i32, 1, 1);
        g.attach(&spin, 1, i as i32, 1, 1);
    }
    let what = gtk::DropDown::from_strings(&["Sign out", "Lock the screen"]);
    what.set_selected(u32::from(p.action == Action::Lock));
    g.attach(&label("When time is up", &[]), 0, 3, 1, 1);
    g.attach(&what, 1, 3, 1, 1);
    first.append(&g);

    let second = card("Allowed hours");
    let g = grid();
    for (i, name) in DAYS.iter().enumerate() {
        let on = gtk::CheckButton::with_label(name);
        on.set_active(p.days[i].is_some());
        let w = p.days[i].unwrap_or(Window {
            start: 480,
            end: 1200,
        });
        let time = |m: u32| {
            gtk::Entry::builder()
                .text(clock(m))
                .width_chars(6)
                .max_width_chars(6)
                .build()
        };
        g.attach(&on, 0, i as i32, 1, 1);
        g.attach(&time(w.start), 1, i as i32, 1, 1);
        g.attach(&label("to", &["s-muted"]), 2, i as i32, 1, 1);
        g.attach(&time(w.end), 3, i as i32, 1, 1);
    }
    second.append(&g);
    let save = button("Save", Some("suggested-action"));
    page(&[first.upcast(), second.upcast(), save.upcast()]).upcast()
}

pub fn parents() -> gtk::Widget {
    let c = card("Parents");
    let me = row(10);
    me.append(&label("mom", &[]));
    me.append(&label("you", &["s-pill"]));
    c.append(&me);
    c.append(&label("dad", &[]));
    let b = row(8);
    b.append(&button("Add a parent...", Some("suggested-action")));
    b.append(&button("Change my password...", None));
    c.append(&b);
    page(&[c.upcast()]).upcast()
}

fn field(c: &gtk::Box, name: &str, hint: &str) {
    c.append(&label(name, &[]));
    c.append(&gtk::Entry::builder().placeholder_text(hint).build());
}

pub fn server() -> gtk::Widget {
    let c = card("Sundial Server");
    c.append(&label(
        "Optional. See and change things from anywhere, through your own server.",
        &["s-muted"],
    ));
    field(&c, "Server address", "sundial.example.com");
    field(&c, "Pairing code", "AB12-CD34");
    c.append(&button("Connect", Some("suggested-action")));
    page(&[c.upcast()]).upcast()
}
