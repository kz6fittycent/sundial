//! Sundial's window for parents. Work in progress: the look and the pages. It shows
//! made-up data (`--demo`) and changes nothing yet.

use gtk::prelude::*;
use gtk::{gio, glib};
use pages::{button, column, label, row};
use std::cell::Cell;
use std::rc::Rc;
use sundial_core::proto::AdminResponse;

mod demo;
mod pages;
mod style;
mod wizard;

const APP_ID: &str = "io.github.kz6fittycent.Sundial.Parent";

fn main() -> glib::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "--demo") {
        eprintln!("sundial-app: not finished; run it with --demo to see it");
        return glib::ExitCode::FAILURE;
    }
    let setup = args.iter().any(|a| a == "--setup");
    glib::set_application_name("Sundial");
    let app = gtk::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.connect_startup(|_| style::init());
    app.connect_activate(move |app| {
        if setup {
            wizard::window(app).present();
        } else {
            window(app, demo::status()).present();
        }
    });
    app.run_with_args::<&str>(&[])
}

/// The child chooser and Lock button, in the title bar on GNOME and in a toolbar under
/// the window manager's title bar elsewhere.
pub fn chrome(
    win: &gtk::ApplicationWindow,
    body: &gtk::Widget,
    start: &[gtk::Widget],
    end: &[gtk::Widget],
) {
    if style::own_title_bar() {
        let bar = gtk::HeaderBar::new();
        start.iter().for_each(|w| bar.pack_start(w));
        end.iter().for_each(|w| bar.pack_end(w));
        win.set_titlebar(Some(&bar));
        win.set_child(Some(body));
        return;
    }
    let all = column(0);
    if !start.is_empty() || !end.is_empty() {
        let bar = row(8);
        bar.add_css_class("toolbar");
        bar.set_margin_top(6);
        bar.set_margin_bottom(6);
        bar.set_margin_start(8);
        bar.set_margin_end(8);
        start.iter().for_each(|w| bar.append(w));
        let gap = gtk::Box::builder().hexpand(true).build();
        bar.append(&gap);
        end.iter().for_each(|w| bar.append(w));
        all.append(&bar);
        all.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    }
    all.append(body);
    win.set_child(Some(&all));
}

fn window(app: &gtk::Application, st: AdminResponse) -> gtk::ApplicationWindow {
    let win = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Sundial")
        .default_width(980)
        .default_height(620)
        .build();
    let stack = gtk::Stack::new();
    let today = gtk::Stack::new();
    let limits = gtk::Stack::new();
    for u in &st.users {
        today.add_named(&pages::today(u), Some(&u.name));
        limits.add_named(&pages::limits(u), Some(&u.name));
    }
    stack.add_titled(&today, Some("today"), "Today");
    stack.add_titled(&limits, Some("limits"), "Hours and limits");
    stack.add_titled(&pages::parents(), Some("parents"), "Parents");
    stack.add_titled(&pages::server(), Some("server"), "Server");
    let names: Vec<String> = st.users.iter().map(|u| u.name.clone()).collect();
    let strs: Vec<&str> = names.iter().map(String::as_str).collect();
    let who = gtk::DropDown::from_strings(&strs);
    who.set_tooltip_text(Some("Child"));
    who.connect_selected_notify(move |d| {
        if let Some(n) = names.get(d.selected() as usize) {
            today.set_visible_child_name(n);
            limits.set_visible_child_name(n);
        }
    });
    let side = gtk::StackSidebar::builder()
        .stack(&stack)
        .width_request(170)
        .build();
    let body = row(0);
    body.append(&side);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));
    body.append(&stack);
    let lock = button("Lock", None);
    lock.set_tooltip_text(Some("Sign out of Sundial"));
    chrome(&win, body.upcast_ref(), &[who.upcast()], &[lock.upcast()]);
    win
}

/// Step names with the current one highlighted.
pub fn steps(names: &[&str]) -> (gtk::FlowBox, Rc<dyn Fn(usize)>) {
    let f = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .column_spacing(6)
        .row_spacing(6)
        .max_children_per_line(6)
        .build();
    let labels: Vec<gtk::Label> = names
        .iter()
        .enumerate()
        .map(|(i, n)| label(&format!("{}. {n}", i + 1), &["s-step"]))
        .collect();
    labels.iter().for_each(|l| f.insert(l, -1));
    let set = move |on: usize| {
        for (i, l) in labels.iter().enumerate() {
            if i == on {
                l.add_css_class("on");
            } else {
                l.remove_css_class("on");
            }
        }
    };
    (f, Rc::new(set))
}

pub type Step = Rc<Cell<usize>>;
