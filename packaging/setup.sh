# Shared by the snap's install, post-refresh and remove hooks (sourced, POSIX sh).
# Files outside the snap point at /snap/sundial/current, which follows updates.
BIN=/snap/sundial/current/bin/sundial
EXT=sundial@kz6fittycent.github.io

install_files() {
	sed "s|^Exec=.*|Exec=/snap/bin/sundial.agent|" "$SNAP/share/sundial-agent.desktop" \
		> /etc/xdg/autostart/sundial-agent.desktop
	sed "s|^Exec=.*|Exec=/snap/bin/sundial.agent|" "$SNAP/share/io.github.kz6fittycent.Sundial.desktop" \
		> /usr/share/applications/io.github.kz6fittycent.Sundial.desktop
	chmod 0644 /etc/xdg/autostart/sundial-agent.desktop \
		/usr/share/applications/io.github.kz6fittycent.Sundial.desktop
	install -d -m 0755 "/usr/share/gnome-shell/extensions/$EXT"
	install -m 0644 "$SNAP/share/gnome-shell-extension/$EXT/metadata.json" \
		"$SNAP/share/gnome-shell-extension/$EXT/extension.js" "/usr/share/gnome-shell/extensions/$EXT/"
}

remove_files() {
	rm -f /etc/xdg/autostart/sundial-agent.desktop /usr/share/applications/io.github.kz6fittycent.Sundial.desktop
	rm -rf "/usr/share/gnome-shell/extensions/$EXT"
}

# Login check through pam-auth-update (Debian/Ubuntu and derivatives). Elsewhere the
# daemon still enforces limits; it just can't refuse the sign-in itself.
install_pam() {
	if command -v pam-auth-update >/dev/null 2>&1; then
		sed "s|/usr/local/bin/sundial|$BIN|" "$SNAP/share/pam-config" > /usr/share/pam-configs/sundial
		chmod 0644 /usr/share/pam-configs/sundial
		pam-auth-update --package --enable sundial
	else
		echo "sundial: no pam-auth-update; sign-ins during breaks are ended by the daemon instead of refused" >&2
	fi
}

remove_pam() {
	if [ -e /usr/share/pam-configs/sundial ]; then
		rm -f /usr/share/pam-configs/sundial
		command -v pam-auth-update >/dev/null 2>&1 && pam-auth-update --package --remove sundial || true
	fi
}
