# Sundial

Screen time limits for Linux desktop accounts. Sundial is aimed at a family computer: a child's account gets
a set amount of active use, then a break, inside allowed hours. A countdown gives them time to save a game
before the session ends. Parents can change things from a phone on the home network.

- **Session and break cycle**: for example 1 hour of use, then a 2 hour break. Only *active* time counts:
  unlocked, in front, and not idle. Locking the screen or walking away pauses the clock, and being away for
  a full break's length refills the session.
- **Allowed hours** per weekday, for example 08:00–20:00 Sunday to Thursday and 08:00–22:00 Friday and Saturday.
- **Countdown**: a window and an urgent notification 5 minutes before time runs out (configurable), shown
  again at the last minute. There's a heads-up at 15 minutes and a "time left" notice at sign-in.
- **Enforced by a root daemon**, not by the child's session. When time is up the session is logged out
  (or locked, if you prefer). Signing in during a break or outside allowed hours is refused at the login
  screen, with the reason and the time they can come back.
- **Parent web page** over HTTPS on the LAN, with Sundial's own parent logins. From it you can give
  +15/+30/+60 minutes, end a break, allow use until a set time, or lock now or in 5 minutes (until a time
  or tomorrow morning). It also shows recent activity.
- **CLI** for the same overrides over SSH: `sudo sundial grant kid 30`.

Tested on Ubuntu 26.04 with GNOME 50 (Wayland). It relies only on systemd-logind and PAM, so other
desktops should work. The countdown window needs GTK 4.

## How it works

```
 child's desktop session                       root
┌────────────────────────┐   status    ┌──────────────────────────┐   loginctl
│ sundial-agent (GTK 4)  │◀────────────│ sundial daemon           │──────────▶ systemd-logind
│ notices + countdown    │ agent.sock  │ counts active time,      │  sessions, idle/lock hints,
└────────────────────────┘             │ enforces, keeps state    │  terminate / lock
                                       │                          │
 login screen (PAM)                    │  /etc/sundial/config.toml│
┌────────────────────────┐ reads files │  /var/lib/sundial/state  │
│ sundial check-login    │────────────▶│                          │◀── https://host:8461 (parents)
└────────────────────────┘             └──────────────────────────┘◀── sudo sundial … (admin.sock)
```

- Every 5 seconds the daemon asks logind for the managed accounts' sessions. Time counts while a session is
  active (in the foreground), not locked, and not idle. GNOME reports idle after its blank-screen delay,
  5 minutes by default.
- The agent only displays what the daemon sends. Killing it doesn't lift any limit; the daemon falls back to
  plain desktop notifications for the countdown.
- The login check runs only for accounts in the `sundial-managed` group (the daemon adds configured accounts
  to it). It reads the config and state files directly, so it still works if the daemon is down. Every
  other account skips it, so a broken Sundial can't lock a parent out.
- Suspend doesn't count as use (the daemon measures with the monotonic clock). Standard accounts can't change
  the system clock.

## Install

Build (Rust 1.85+, GTK 4 development files):

```sh
sudo apt install libgtk-4-dev
cargo build --release
```

Install on the child's computer as root:

```sh
mkdir dist && cp target/release/sundial target/release/sundial-agent packaging/* dist/
sudo dist/install.sh
sudoedit /etc/sundial/config.toml      # set the account name and hours
sudo sundial check-config              # prints each day's window
sudo systemctl restart sundial
sudo sundial passwd mom                # parent login for the web page
sudo sundial passwd dad
```

`install.sh` puts the binaries in `/usr/local/bin`, then installs the systemd unit, the agent autostart entry,
and a `pam-auth-update` profile (Debian/Ubuntu). `uninstall.sh` removes them; `PURGE=1` also removes the
config, state and group.

A snap is planned.

## Configuration

`/etc/sundial/config.toml`, reloaded automatically when it changes:

```toml
[web]
enabled = true
listen = "0.0.0.0:8461"

[[user]]
name = "kid"
session_minutes = 60     # active minutes before a break; 0 = no session limit
break_minutes = 120
warn_minutes = 5         # countdown length
action = "logout"        # or "lock"

[user.schedule]          # mon..sun, or default; "none" = no access that day
default = "08:00-20:00"
fri = "08:00-22:00"
sat = "08:00-22:00"
```

Add more `[[user]]` blocks for more accounts. Windows can't cross midnight; use `24:00` for the end of a day.

## Parent web page

Open `https://<computer>:8461/` and bookmark it. The certificate is self-signed, so the browser warns
once. To check you've reached the right machine, compare the fingerprint with the one in
`journalctl -u sundial`. Sign-ins last 30 days. After 5 wrong passwords from one address, that address waits
15 minutes. Remove a login with `sudo sundial passwd NAME --delete`; this also signs it out.

If the computer runs a firewall, allow the port from your LAN, for example
`sudo ufw allow from 192.168.1.0/24 to any port 8461 proto tcp`.

## Command line

```
sudo sundial status                     # time left, breaks, sessions, recent events
sudo sundial grant kid 30               # +30 min on top of what's left (beats breaks and hours)
sudo sundial end-break kid              # fresh session now
sudo sundial allow-until kid 21:30
sudo sundial lock kid                   # 5 min countdown, locked until tomorrow's start
sudo sundial lock kid --now --until 18:00
sudo sundial clear kid                  # drop parent overrides
```

## Rules in detail

- Extra time from a parent is added to whatever is left, and it overrides breaks and allowed hours until it
  runs out. Time used during it still counts. If the session is used up by the end, the break starts then.
- A break that would end after the day's allowed hours lasts until the next morning's start.
- If a session appears while the account is blocked (an SSH login, or a parent's "lock now"), it gets a
  1 minute notice before it is ended.
- Parent actions and enforcement are logged to the journal (`journalctl -u sundial`) and shown on the page.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
