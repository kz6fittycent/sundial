# Design: Sundial and Sundial Server

Status: draft, 2026-11-24. Nothing here is built. "Proposed" items await a decision.

## Requirements (from the owner)

- **Sundial**: standalone on the child's computer. A GUI there for the parent to sign in and manage everything; no web UI. The parent needs no account on the machine.
- **Sundial Server**: an optional, separate snap (`sundial-server`) on another host, with the web UI, for use on the LAN or from anywhere.
- Let's Encrypt certificates when the server is reachable from outside; self-signed otherwise.
- A setup wizard for each.

## Connection: the host dials out

The child's computer keeps an outbound TLS connection (WebSocket) to the server. Nothing listens on the child's computer, so it works behind a grandparent's router with no port opened there. Only the server's network needs a forwarded port.

- The host stays in charge. Rules, counting, enforcement and the login check are local and work with no server.
- The server relays commands and shows the last status it received, with its age.
- Commands given while the host is offline are queued with an id and an expiry, and applied once on reconnect. Example: a "+30 min" that expires must not turn up the next day.
- Commands are a fixed list (today's overrides and limits). The server can't run anything else on the host.
- One server can hold several hosts.

### Pairing

1. The parent picks "Add a computer" on the server; it shows a short-lived one-time code, server address and certificate fingerprint.
2. The parent enters them in the host's GUI while signed in as a parent.
3. The host creates a key pair; the server stores the public key. The host pins a self-signed certificate's fingerprint, or verifies Let's Encrypt normally.
4. Either side can revoke.

A reinstalled server with a new self-signed certificate means pairing again.

### Two kinds of access

Parent logins on the host and on the server are separate. A hacked server could still give time or change limits for paired hosts, so the host logs every remote command and shows it in its GUI. Activity titles go to the server only if the parent turns that on (proposed default: off).

## Sundial (host, classic snap)

- `sundial-gui` runs in whatever session is open, unprivileged, and talks to the root daemon over a Unix socket.
- Signing in checks Sundial's own argon2 logins in the daemon. The daemon gives that connection a short session (proposed: 10 minutes idle) and throttles failures. The GUI holds no privilege itself.
- The web server, TLS and port 8461 come out; the GUI takes over status, overrides, hours and limits, charts, activity and parent logins.
- First-run wizard: pick the child's account(s), set limits, create the first parent login, optionally pair a server. Creating the first parent must need administrator rights (polkit or sudo), or a child could claim the machine.

### The hard part: a blocked child can't sign in, so where does the parent's GUI run?

During a break the login screen refuses the only account. A parent with no account then can't open the GUI.

| Option | Notes |
|---|---|
| A. Parent unlock at the login screen: after refusal, PAM asks for a parent name and password, then grants time | Fits "no account". Needs a PAM module (a .so in the host's PAM directory) and per-display-manager testing |
| B. A locked-down "Sundial Parent" kiosk session | Full GUI, but adds a system account and a session entry |
| C. Server, SSH or an administrator account only | No work, but fails the standalone requirement |
| D. Let the child's session open into a Sundial-only lock screen | Must be unescapable on each desktop; hard on Wayland |

Proposed: A, after a spike on GDM, SDDM and LightDM. B is the fallback.

Limit to state plainly: a GUI inside the child's session could be imitated or key-logged by a program running as the child. Option A avoids that for granting time.

## Sundial Server (strict snap)

- Rust, axum, SQLite; reuses sundial-core and the current page's HTML.
- Plugs: `network` AND `network-bind`. `network` alone doesn't allow listening for connections. Both connect automatically, with no manual review for them.
- State in `$SNAP_COMMON`. Admin by `sundial-server` CLI and the web UI.
- First run: a one-time setup code (`sundial-server setup-code`) opens the web wizard, so nobody else on the network can claim it.

### Certificates (wizard)

| Choice | Needs |
|---|---|
| Let's Encrypt, TLS-ALPN-01 | A public name and outside port 443 reaching the server |
| Let's Encrypt, HTTP-01 | A public name and outside port 80 reaching the server |
| Behind a reverse proxy (Traefik, Caddy) | Proxy holds the certificate; trusted proxy address set explicitly |
| Self-signed | Nothing. LAN, or any address with the fingerprint pinned |

Let's Encrypt renews by itself. The wizard tests with the staging service first. Dynamic home addresses need a dynamic DNS name; Sundial won't provide one.

A public server needs more than the LAN page: login lockout that works behind a proxy, TOTP two-factor (proposed: required when remote access is on), sign-out everywhere, and an audit log.

## Repository

One workspace: `sundial-core`, `sundial-link` (protocol), `sundial` (daemon, CLI, PAM), `sundial-agent`, `sundial-gui`, `sundial-server`. Two snapcraft projects; snaps may update at different times, so the protocol is versioned.

## Order of work

1. Spikes: PAM parent unlock; a strict snap binding 80/443; TLS-ALPN-01 against Let's Encrypt staging.
2. Protocol and pairing.
3. Host GUI and wizard, beside the existing web UI.
4. Server, its wizard and certificates.
5. Remove the web UI from the host; migrate the first real install; docs and wiki.

Step 5 is last so a working install never loses its web page before the replacement exists. `web-retry` (095880c) becomes obsolete for the host, but its restart logic carries to the server.
