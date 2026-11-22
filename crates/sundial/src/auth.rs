//! Parent logins for the web page: `/etc/sundial/admins` holds `name:argon2-hash` lines.

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use rand::RngCore;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SESSION_DAYS: i64 = 30;
const MAX_FAILURES: u32 = 5;
const FAILURE_WINDOW: i64 = 15 * 60;

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing: {e}"))
}

pub fn read_admins(path: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            l.split_once(':')
                .map(|(u, h)| (u.to_string(), h.to_string()))
        })
        .collect()
}

pub fn write_admins(path: &Path, admins: &HashMap<String, String>) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut names: Vec<_> = admins.keys().collect();
    names.sort();
    let mut text =
        String::from("# Sundial parent logins (name:argon2 hash). Edit with `sundial passwd`.\n");
    for n in names {
        text.push_str(&format!("{n}:{}\n", admins[n]));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub struct Auth {
    admins_path: PathBuf,
    /// token -> (parent name, expiry)
    sessions: Mutex<HashMap<String, (String, i64)>>,
    /// ip -> (failures, first failure time)
    failures: Mutex<HashMap<IpAddr, (u32, i64)>>,
    /// Hash checked for unknown names, so timing doesn't reveal which names exist.
    dummy: String,
}

impl Auth {
    pub fn new(admins_path: PathBuf) -> Auth {
        Auth {
            admins_path,
            sessions: Mutex::default(),
            failures: Mutex::default(),
            dummy: hash_password("sundial-dummy").unwrap_or_default(),
        }
    }

    pub fn has_admins(&self) -> bool {
        !read_admins(&self.admins_path).is_empty()
    }

    /// True if this address has failed too often recently.
    pub fn throttled(&self, ip: IpAddr, now: i64) -> bool {
        let mut f = self.failures.lock().unwrap();
        f.retain(|_, (_, first)| now - *first < FAILURE_WINDOW);
        f.get(&ip).is_some_and(|(n, _)| *n >= MAX_FAILURES)
    }

    /// Check a login; on success returns a new session token.
    pub fn login(&self, ip: IpAddr, user: &str, pw: &str, now: i64) -> Option<String> {
        let admins = read_admins(&self.admins_path);
        let stored = admins.get(user).map(String::as_str).unwrap_or(&self.dummy);
        let ok = PasswordHash::new(stored)
            .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
            .unwrap_or(false)
            && admins.contains_key(user);
        if !ok {
            let mut f = self.failures.lock().unwrap();
            let e = f.entry(ip).or_insert((0, now));
            e.0 += 1;
            return None;
        }
        self.failures.lock().unwrap().remove(&ip);
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, (_, exp)| *exp > now);
        s.insert(
            token.clone(),
            (user.to_string(), now + SESSION_DAYS * 86_400),
        );
        Some(token)
    }

    /// The parent signed in with this token, if it is valid and that login still exists.
    pub fn check(&self, token: &str, now: i64) -> Option<String> {
        let user = {
            let s = self.sessions.lock().unwrap();
            let (user, exp) = s.get(token)?;
            if *exp <= now {
                return None;
            }
            user.clone()
        };
        // Removing a login with `sundial passwd --delete` signs it out everywhere.
        read_admins(&self.admins_path)
            .contains_key(&user)
            .then_some(user)
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_flow() {
        let dir = std::env::temp_dir().join(format!("sundial-auth-{}", std::process::id()));
        let path = dir.join("admins");
        let mut admins = HashMap::new();
        admins.insert("mom".to_string(), hash_password("pw1").unwrap());
        write_admins(&path, &admins).unwrap();
        let auth = Auth::new(path.clone());
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(auth.login(ip, "mom", "wrong", 0).is_none());
        assert!(auth.login(ip, "nobody", "pw1", 0).is_none());
        let tok = auth.login(ip, "mom", "pw1", 0).unwrap();
        assert_eq!(auth.check(&tok, 10).as_deref(), Some("mom"));
        assert!(auth.check(&tok, SESSION_DAYS * 86_400 + 1).is_none());
        for _ in 0..5 {
            auth.login(ip, "mom", "bad", 100);
        }
        assert!(auth.throttled(ip, 101));
        assert!(!auth.throttled(ip, 100 + FAILURE_WINDOW));
        write_admins(&path, &HashMap::new()).unwrap();
        assert!(
            auth.check(&tok, 10).is_none(),
            "deleted login is signed out"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
