// Sundial activity: answers GetFocus() on the session bus with the focused window's
// app id, app name and title. The Sundial agent (running in the same session) polls it
// and passes the answer to the Sundial daemon. Nothing is drawn or changed.

import Gio from 'gi://Gio';
import Shell from 'gi://Shell';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const BUS_NAME = 'io.github.kz6fittycent.Sundial.Focus';
const OBJECT_PATH = '/io/github/kz6fittycent/Sundial/Focus';
const IFACE = `
<node>
  <interface name="io.github.kz6fittycent.Sundial.Focus">
    <method name="GetFocus">
      <arg type="s" direction="out" name="app_id"/>
      <arg type="s" direction="out" name="app_name"/>
      <arg type="s" direction="out" name="title"/>
    </method>
  </interface>
</node>`;

class FocusService {
    GetFocus() {
        const win = global.display.focus_window;
        if (!win)
            return ['', '', ''];
        const app = Shell.WindowTracker.get_default().get_window_app(win);
        // Windows without a matching .desktop file get a fake "window:N" app; use the
        // WM class as the name then (Minecraft's window class is "Minecraft* 1.21.4").
        const appId = app && !app.is_window_backed() ? (app.get_id() ?? '') : '';
        const appName = appId ? (app.get_name() ?? '') : (win.get_wm_class() ?? '');
        return [appId, appName, win.get_title() ?? ''];
    }
}

export default class SundialExtension extends Extension {
    enable() {
        this._dbus = Gio.DBusExportedObject.wrapJSObject(IFACE, new FocusService());
        this._dbus.export(Gio.DBus.session, OBJECT_PATH);
        this._owner = Gio.bus_own_name(Gio.BusType.SESSION, BUS_NAME,
            Gio.BusNameOwnerFlags.NONE, null, null, null);
    }

    disable() {
        if (this._owner) {
            Gio.bus_unown_name(this._owner);
            this._owner = 0;
        }
        this._dbus?.unexport();
        this._dbus = null;
    }
}
