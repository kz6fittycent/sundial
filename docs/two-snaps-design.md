# Design: Sundial and Sundial Server

Status: 2026-11-24. The link and pairing are built and tested; the GUI, wizards, server web page and certificates are not.

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

1. "Add a computer" on the server shows a one-time code (15 minutes, 5 tries).
2. The parent types the server's address and the code on the host, which needs root there.
3. The host gets a random token; the server keeps only its SHA-256. The code of a self-signed server starts with 80 bits of its certificate's fingerprint, which the host pins; with a public certificate the code is just the secret and normal verification applies.
4. Either side can unpair. A server with a new self-signed certificate means pairing again.

### Parity

The server shows and does everything the host does, activity included. Remote changes are logged on the host as "by NAME via server". Only parent overrides and limits are accepted from the server.

## Sundial (host, classic snap)

- `sundial-gui` runs in whatever session is open, unprivileged, and talks to the root daemon over a Unix socket.
- Signing in checks Sundial's own argon2 logins in the daemon. The daemon gives that connection a short session (proposed: 10 minutes idle) and throttles failures. The GUI holds no privilege itself.
- The web server, TLS and port 8461 come out; the GUI takes over status, overrides, hours and limits, charts, activity and parent logins.
- First-run wizard: pick the child's account(s), set limits, create the first parent login, optionally pair a server. Creating the first parent must need administrator rights (polkit or sudo), or a child could claim the machine.

### While the child is blocked

Decided: no unlock at the login screen. With no session to open the GUI in, the break runs its course. A paired server (or SSH) still works.

A GUI in the child's session could be imitated or key-logged by a program running as the child.

## Sundial Server (strict snap)

- Rust, axum, JSON state; reuses sundial-core and the current page's HTML.
- Plugs: `network` AND `network-bind`. `network` alone doesn't allow listening for connections. Both connect automatically, with no manual review for them.
- State in `$SNAP_COMMON`. Admin by `sundial-server` CLI and the web UI.
- First run: a one-time setup code (`sundial-server setup-code`) opens the web wizard, so nobody else on the network can claim it.

### Certificates and the wizard

- **Let's Encrypt**: TLS-ALPN-01 only. One router rule, outside port 443 to the server's port 8461, so no low port is needed on the server.
- **Self-signed**: the backup, and the LAN-only choice.
- No reverse-proxy mode. The wizard gives the technical steps only: simple pictures of port forwarding, a short note on dynamic DNS and a link to a provider's own instructions.
- Two-factor sign-in is optional. Wrong-password lockout applies either way.

## Repositories

- `sundial`: core, link protocol, daemon, agent, GUI.
- `sundial-server`: its own repository (name registered in the store); takes `sundial-core` and `sundial-link` from this one. The protocol is versioned, since the snaps update separately.

## Order of work

1. Done: protocol, pairing, host client, server core.
2. Server web page, sign-in, wizard, certificates; strict snap.
3. Host GUI and wizard, beside the existing web UI.
4. Test snaps locally in LXD.
5. Remove the web UI from the host; migrate the first install; docs and wiki.

Step 5 is last so a working install never loses its web page before the replacement exists. `web-retry` (095880c) becomes obsolete for the host, but its restart logic carries to the server.
