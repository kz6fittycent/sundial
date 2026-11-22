//! Small OS helpers: account lookups, group membership, desktop notifications from root.

use std::ffi::CStr;
use sundial_core::config::MANAGED_GROUP;
use tokio::process::Command;

/// (name, uid) for a uid, via getpwuid_r.
pub fn user_by_uid(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc =
        unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if rc != 0 || res.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// uid for a user name.
pub fn uid_by_name(name: &str) -> Option<u32> {
    ids_by_name(name).map(|(u, _)| u)
}

/// (uid, primary gid) for a user name, via getpwnam_r.
pub fn ids_by_name(name: &str) -> Option<(u32, u32)> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut res,
        )
    };
    if rc != 0 || res.is_null() {
        return None;
    }
    Some((pwd.pw_uid, pwd.pw_gid))
}

/// Make sure each managed account is in the `sundial-managed` group, which the PAM
/// check keys on. Returns log lines.
pub async fn ensure_group_members(users: &[String]) -> Vec<String> {
    let mut ev = Vec::new();
    let has_group = Command::new("getent")
        .args(["group", MANAGED_GROUP])
        .output()
        .await;
    if !has_group.map(|o| o.status.success()).unwrap_or(false) {
        match Command::new("groupadd")
            .args(["--system", MANAGED_GROUP])
            .status()
            .await
        {
            Ok(s) if s.success() => ev.push(format!("created group {MANAGED_GROUP}")),
            _ => {
                ev.push(format!(
                    "could not create group {MANAGED_GROUP}; the login check won't apply"
                ));
                return ev;
            }
        }
    }
    for u in users {
        if uid_by_name(u).is_none() {
            ev.push(format!("account {u} does not exist on this machine"));
            continue;
        }
        let groups = Command::new("id").args(["-nG", u]).output().await;
        let in_group = groups
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|g| g == MANAGED_GROUP)
            })
            .unwrap_or(false);
        if !in_group {
            match Command::new("gpasswd")
                .args(["-a", u, MANAGED_GROUP])
                .output()
                .await
            {
                Ok(o) if o.status.success() => ev.push(format!("added {u} to {MANAGED_GROUP}")),
                _ => ev.push(format!("could not add {u} to {MANAGED_GROUP}")),
            }
        }
    }
    ev
}

/// Desktop notification in the user's session, sent from root. Used when the user's
/// agent isn't running (killed, or not installed), so the countdown still reaches them.
pub fn notify_user(user: &str, title: &str, body: &str) {
    let Some((uid, gid)) = ids_by_name(user) else {
        return;
    };
    let bus = format!("unix:path=/run/user/{uid}/bus");
    // setpriv, not runuser/su: those go through PAM, where Sundial's own login check
    // would refuse a blocked account.
    let mut cmd = Command::new("setpriv");
    cmd.arg(format!("--reuid={uid}"))
        .arg(format!("--regid={gid}"))
        .args(["--clear-groups", "--reset-env", "--", "env"])
        .arg(format!("DBUS_SESSION_BUS_ADDRESS={bus}"))
        .args([
            "gdbus",
            "call",
            "--session",
            "--dest",
            "org.freedesktop.Notifications",
            "--object-path",
            "/org/freedesktop/Notifications",
            "--method",
            "org.freedesktop.Notifications.Notify",
            "Sundial",
            "0",
            "alarm-symbolic",
            title,
            body,
            "[]",
            "{'urgency': <byte 2>}",
            "0",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Ok(mut child) = cmd.spawn() {
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// This machine's IPv4/IPv6 addresses (from `hostname -I`).
pub fn addresses() -> Vec<String> {
    std::process::Command::new("hostname")
        .arg("-I")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}
