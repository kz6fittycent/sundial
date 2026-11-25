#!/bin/sh
# Remove Sundial. Keeps /etc/sundial and /var/lib/sundial unless PURGE=1.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
if [ -e /usr/share/pam-configs/sundial ]; then
	pam-auth-update --remove sundial || true
	rm -f /usr/share/pam-configs/sundial
fi
systemctl disable --now sundial.service 2>/dev/null || true
rm -f /etc/systemd/system/sundial.service /etc/geoclue/conf.d/90-sundial.conf /etc/xdg/autostart/sundial-agent.desktop \
	/usr/share/applications/io.github.kz6fittycent.Sundial.desktop \
	/usr/local/bin/sundial /usr/local/bin/sundial-agent
rm -rf /usr/share/gnome-shell/extensions/sundial@kz6fittycent.github.io
systemctl daemon-reload
if [ "${PURGE:-0}" = 1 ]; then
	rm -rf /etc/sundial /var/lib/sundial
	groupdel sundial-managed 2>/dev/null || true
fi
echo "Sundial removed."
