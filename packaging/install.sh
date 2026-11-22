#!/bin/sh
# Install Sundial from a release tarball or a source build. Run as root from the
# directory holding the binaries (or pass BIN=path/to/dir).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-$HERE}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
for b in sundial sundial-agent; do
	[ -x "$BIN/$b" ] || { echo "missing $BIN/$b" >&2; exit 1; }
done

install -m 0755 "$BIN/sundial" "$BIN/sundial-agent" /usr/local/bin/
install -m 0644 "$HERE/sundial.service" /etc/systemd/system/sundial.service
install -m 0644 "$HERE/sundial-agent.desktop" /etc/xdg/autostart/sundial-agent.desktop
install -m 0644 "$HERE/io.github.kz6fittycent.Sundial.desktop" /usr/share/applications/
install -d -m 0755 /etc/sundial
if [ ! -e /etc/sundial/config.toml ]; then
	install -m 0644 "$HERE/config.example.toml" /etc/sundial/config.toml
	echo "Wrote /etc/sundial/config.toml from the example: edit it, then: systemctl restart sundial"
fi
getent group sundial-managed >/dev/null || groupadd --system sundial-managed

# Login check through pam-auth-update (Debian/Ubuntu). It only applies to accounts in
# the sundial-managed group; everyone else skips it.
if command -v pam-auth-update >/dev/null; then
	install -m 0644 "$HERE/pam-config" /usr/share/pam-configs/sundial
	pam-auth-update --enable sundial
else
	echo "No pam-auth-update: add the Account lines from pam-config to your PAM stack by hand." >&2
fi

/usr/local/bin/sundial check-config /etc/sundial/config.toml >/dev/null
systemctl daemon-reload
systemctl enable --now sundial.service
systemctl restart sundial.service
echo "Sundial installed. Add a parent login: sudo sundial passwd NAME"
