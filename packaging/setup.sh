# Shared by the snap's install, post-refresh and remove hooks (sourced, POSIX sh).
# Files outside the snap point at /snap/sundial/current, which follows updates.
# The login check is a static copy on the host: see install_files.
BIN=/usr/local/sbin/sundial-check-login
EXT=sundial@kz6fittycent.github.io

install_files() {
	install -d -m 0755 /usr/local/sbin
	install -m 0755 "$SNAP/bin/sundial-static" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	if command -v restorecon >/dev/null 2>&1; then restorecon "$BIN" || true; fi
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
	rm -f "$BIN" /etc/xdg/autostart/sundial-agent.desktop /usr/share/applications/io.github.kz6fittycent.Sundial.desktop
	rm -rf "/usr/share/gnome-shell/extensions/$EXT"
}

# Login check. Debian/Ubuntu family: a pam-auth-update profile, which covers every
# login. Elsewhere (Fedora, openSUSE, Arch, ...): two lines added to each display
# manager's own PAM file, between marker comments, so graphical sign-ins are refused;
# other logins are still ended by the daemon after a 1 minute notice.
DM_PAM="gdm-password gdm-autologin gdm-fingerprint gdm-smartcard sddm sddm-autologin lightdm lightdm-autologin"
MARK_BEGIN="# sundial begin (added by the sundial snap; removed with it)"
MARK_END="# sundial end"
# First line of a file Sundial copied from /usr/lib/pam.d (Fedora 45+, openSUSE keep
# their PAM files there; /etc/pam.d overrides them). Such a copy is deleted on removal.
MARK_COPY="# sundial: copy of /usr/lib/pam.d with the Sundial login check; removed with the snap"

install_pam() {
	if command -v pam-auth-update >/dev/null 2>&1; then
		sed "s|/usr/local/bin/sundial|$BIN|" "$SNAP/share/pam-config" > /usr/share/pam-configs/sundial
		chmod 0644 /usr/share/pam-configs/sundial
		pam-auth-update --package --enable sundial
		return
	fi
	remove_dm_pam
	for f in $DM_PAM; do
		p=/etc/pam.d/$f
		src=$p
		copy=""
		if [ ! -f "$p" ]; then
			[ -f "/usr/lib/pam.d/$f" ] || continue
			src=/usr/lib/pam.d/$f
			copy=$MARK_COPY
		fi
		# Insert before the first "account" line so the check runs before any
		# "sufficient" account module can end the stack early.
		if awk -v c="$copy" -v b="$MARK_BEGIN" -v e="$MARK_END" -v bin="$BIN" '
			NR == 1 && c != "" { print c }
			!done && /^[ \t]*-?account[ \t]/ {
				print b
				print "account    [success=1 default=ignore] pam_succeed_if.so quiet user notingroup sundial-managed"
				print "account    required     pam_exec.so quiet stdout " bin " check-login"
				print e
				done = 1
			}
			{ print }
			END { if (!done) exit 3 }
		' "$src" > "$p.sundial-new"; then
			if [ -f "$p" ]; then
				# cat keeps the file's owner, mode and SELinux label.
				cat "$p.sundial-new" > "$p"
			else
				install -m 0644 "$p.sundial-new" "$p"
				if command -v restorecon >/dev/null 2>&1; then restorecon "$p" || true; fi
			fi
			echo "sundial: login check added to $p"
		else
			echo "sundial: no account section in $p; left alone" >&2
		fi
		rm -f "$p.sundial-new"
	done
}

remove_dm_pam() {
	for f in $DM_PAM; do
		p=/etc/pam.d/$f
		if [ ! -f "$p" ] || ! grep -qF "$MARK_BEGIN" "$p"; then
			continue
		fi
		if [ "$(head -n 1 "$p")" = "$MARK_COPY" ]; then
			rm -f "$p"
			continue
		fi
		sed "\|^$MARK_BEGIN\$|,\|^$MARK_END\$|d" "$p" > "$p.sundial-new" && cat "$p.sundial-new" > "$p"
		rm -f "$p.sundial-new"
	done
}

remove_pam() {
	if [ -e /usr/share/pam-configs/sundial ]; then
		rm -f /usr/share/pam-configs/sundial
		command -v pam-auth-update >/dev/null 2>&1 && pam-auth-update --package --remove sundial || true
	fi
	remove_dm_pam
}
