//! First-run setup.

use crate::pages::{button, card, column, label, row};
use crate::{Step, chrome, steps};
use gtk::prelude::*;
use std::rc::Rc;

const STEPS: [&str; 4] = ["Parent login", "Child", "Hours and limits", "Server"];

fn entry(hint: &str) -> gtk::Entry {
    gtk::Entry::builder().placeholder_text(hint).build()
}

fn password(hint: &str) -> gtk::PasswordEntry {
    gtk::PasswordEntry::builder()
        .placeholder_text(hint)
        .show_peek_icon(true)
        .build()
}

fn bodies() -> [gtk::Box; 4] {
    let a = card("Make your parent login");
    a.append(&label(
        "It's only for Sundial. You don't need an account on this computer.",
        &["s-muted"],
    ));
    a.append(&entry("Name"));
    a.append(&password("Password (at least 8 characters)"));
    a.append(&password("Password again"));
    let b = card("Whose time is limited?");
    for n in ["alex", "sam"] {
        b.append(&gtk::CheckButton::with_label(n));
    }
    b.append(&label("Administrators aren't listed.", &["s-muted"]));
    let c = card("Starting limits");
    c.append(&label("You can change these any time.", &["s-muted"]));
    let r = row(10);
    r.append(&label("Session", &[]));
    r.append(&gtk::DropDown::from_strings(&["1 h", "1 h 30 min", "2 h"]));
    r.append(&label("then a break of", &[]));
    r.append(&gtk::DropDown::from_strings(&["1 h", "2 h"]));
    c.append(&r);
    let d = card("Connect a server? (optional)");
    d.append(&entry("Server address"));
    d.append(&entry("Pairing code"));
    d.append(&label(
        "Skip this to use Sundial on this computer only.",
        &["s-muted"],
    ));
    [a, b, c, d]
}

pub fn window(app: &gtk::Application) -> gtk::ApplicationWindow {
    let win = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Set up Sundial")
        .default_width(640)
        .default_height(440)
        .build();
    let (pills, mark) = steps(&STEPS);
    let stack = gtk::Stack::builder().vexpand(true).build();
    for (i, b) in bodies().iter().enumerate() {
        stack.add_named(b, Some(&i.to_string()));
    }
    let (back, next) = (
        button("Back", None),
        button("Next", Some("suggested-action")),
    );
    let at: Step = Step::default();
    let show = {
        let (at, back, next, stack) = (at.clone(), back.clone(), next.clone(), stack.clone());
        Rc::new(move || {
            let i = at.get();
            mark(i);
            stack.set_visible_child_name(&i.to_string());
            back.set_sensitive(i > 0);
            next.set_label(if i + 1 == STEPS.len() {
                "Finish"
            } else {
                "Next"
            });
        })
    };
    show();
    let body = column(14);
    body.set_margin_top(16);
    body.set_margin_bottom(16);
    body.set_margin_start(16);
    body.set_margin_end(16);
    body.append(&pills);
    body.append(&stack);
    let nav = row(8);
    nav.set_halign(gtk::Align::End);
    nav.append(&back);
    nav.append(&next);
    {
        let (at, show) = (at.clone(), show.clone());
        back.connect_clicked(move |_| {
            at.set(at.get().saturating_sub(1));
            show();
        });
    }
    let w = win.downgrade();
    next.connect_clicked(move |_| {
        if at.get() + 1 < STEPS.len() {
            at.set(at.get() + 1);
            show();
        } else if let Some(w) = w.upgrade() {
            w.close();
        }
    });
    body.append(&nav);
    chrome(&win, body.upcast_ref(), &[], &[]);
    win
}
