//! Parent logins for the web page: `/etc/sundial/admins` holds `name:argon2-hash` lines.

use crate::two_factor;
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
/// Wrong two-factor codes per login in that time, from any address.
const MAX_BAD_CODES: u32 = 10;
/// Seconds to type the code.
const CODE_WAIT: i64 = 5 * 60;

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
    let mut names: Vec<_> = admins.keys().collect();
    names.sort();
    let mut text =
        String::from("# Sundial parent logins (name:argon2 hash). Edit with `sundial passwd`.\n");
    for n in names {
        text.push_str(&format!("{n}:{}\n", admins[n]));
    }
    write_private(path, text.as_bytes())
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
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
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

struct Session {
    user: String,
    /// The password hash at sign-in; a changed password ends the session.
    hash: String,
    until: i64,
}

struct Pending {
    user: String,
    hash: String,
    until: i64,
}

pub enum Login {
    In(String),
    /// Needs a code: pass this to `finish`.
    Code(String),
    Bad,
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Auth {
    admins_path: PathBuf,
    sessions: Mutex<HashMap<String, Session>>,
    /// Right password, code still to come.
    pending: Mutex<HashMap<String, Pending>>,
    /// parent name -> (wrong codes, first one's time)
    bad_codes: Mutex<HashMap<String, (u32, i64)>>,
    /// Held while two-factor.json is read and changed.
    factors: Mutex<()>,
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
            pending: Mutex::default(),
            bad_codes: Mutex::default(),
            factors: Mutex::default(),
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

    fn failed(&self, ip: IpAddr, now: i64) {
        let mut f = self.failures.lock().unwrap();
        f.entry(ip).or_insert((0, now)).0 += 1;
    }

    /// The stored hash if the password is right. Wrong ones count toward the lockout.
    fn verified(&self, ip: IpAddr, user: &str, pw: &str, now: i64) -> Option<String> {
        let admins = read_admins(&self.admins_path);
        let stored = admins.get(user).unwrap_or(&self.dummy);
        let ok = PasswordHash::new(stored)
            .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
            .unwrap_or(false);
        let hash = admins.get(user).filter(|_| ok).cloned();
        if hash.is_none() {
            self.failed(ip, now);
        }
        hash
    }

    pub fn verify(&self, ip: IpAddr, user: &str, pw: &str, now: i64) -> bool {
        self.verified(ip, user, pw, now).is_some()
    }

    fn open(&self, user: &str, hash: String, now: i64) -> String {
        let token = random_token();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, x| x.until > now);
        s.insert(
            token.clone(),
            Session {
                user: user.to_string(),
                hash,
                until: now + SESSION_DAYS * 86_400,
            },
        );
        token
    }

    /// A new session for someone already checked, such as after changing the password.
    pub fn reopen(&self, user: &str, now: i64) -> Option<String> {
        let hash = read_admins(&self.admins_path).remove(user)?;
        Some(self.open(user, hash, now))
    }

    pub fn login(&self, ip: IpAddr, user: &str, pw: &str, now: i64) -> Login {
        let Some(hash) = self.verified(ip, user, pw, now) else {
            return Login::Bad;
        };
        match two_factor::read(&self.admins_path) {
            Ok(f) if !f.contains_key(user) => {
                self.failures.lock().unwrap().remove(&ip);
                Login::In(self.open(user, hash, now))
            }
            Ok(_) => {
                let t = random_token();
                let mut p = self.pending.lock().unwrap();
                p.retain(|_, x| x.until > now);
                p.insert(
                    t.clone(),
                    Pending {
                        user: user.to_string(),
                        hash,
                        until: now + CODE_WAIT,
                    },
                );
                Login::Code(t)
            }
            Err(e) => {
                eprintln!("sundial: two-factor file: {e:#}");
                Login::Bad
            }
        }
    }

    /// The second step. Wrong codes count against the address and the login.
    pub fn finish(&self, ip: IpAddr, pending: &str, code: &str, now: i64) -> Option<String> {
        let (user, hash) = {
            let p = self.pending.lock().unwrap();
            let x = p.get(pending).filter(|x| x.until > now)?;
            (x.user.clone(), x.hash.clone())
        };
        if !self.check_code(ip, &user, code, now) {
            return None;
        }
        self.pending.lock().unwrap().remove(pending)?;
        self.failures.lock().unwrap().remove(&ip);
        Some(self.open(&user, hash, now))
    }

    fn check_code(&self, ip: IpAddr, user: &str, code: &str, now: i64) -> bool {
        let mut bad = self.bad_codes.lock().unwrap();
        bad.retain(|_, (_, first)| now - *first < FAILURE_WINDOW);
        if bad.get(user).is_some_and(|(n, _)| *n >= MAX_BAD_CODES) {
            return false;
        }
        let _one = self.factors.lock().unwrap();
        let ok = match two_factor::read(&self.admins_path) {
            Ok(mut f) => {
                f.get_mut(user).is_some_and(|x| x.accept(code, now))
                    && two_factor::write(&self.admins_path, &f).is_ok()
            }
            Err(_) => false,
        };
        if ok {
            bad.remove(user);
        } else {
            bad.entry(user.to_string()).or_insert((0, now)).0 += 1;
            self.failed(ip, now);
        }
        ok
    }

    pub fn has_two_factor(&self, user: &str) -> bool {
        two_factor::read(&self.admins_path).is_ok_and(|f| f.contains_key(user))
    }

    /// Turn it on if the code from the app is right. Returns the recovery codes.
    pub fn enable_two_factor(
        &self,
        user: &str,
        secret: &str,
        code: &str,
        now: i64,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let (show, recovery) = two_factor::new_recovery();
        let mut x = two_factor::Factor {
            secret: secret.to_string(),
            last_step: 0,
            recovery: Vec::new(),
        };
        if !x.accept(code, now) {
            return Ok(None);
        }
        x.recovery = recovery;
        let _one = self.factors.lock().unwrap();
        let mut f = two_factor::read(&self.admins_path)?;
        f.insert(user.to_string(), x);
        two_factor::write(&self.admins_path, &f)?;
        Ok(Some(show))
    }

    pub fn disable_two_factor(&self, user: &str) -> anyhow::Result<bool> {
        let _one = self.factors.lock().unwrap();
        two_factor::clear(&self.admins_path, user)
    }

    /// The parent signed in with this token. Ends when the login is removed or its
    /// password changes, here or with `passwd`.
    pub fn check(&self, token: &str, now: i64) -> Option<String> {
        let (user, hash) = {
            let s = self.sessions.lock().unwrap();
            let x = s.get(token).filter(|x| x.until > now)?;
            (x.user.clone(), x.hash.clone())
        };
        (read_admins(&self.admins_path).get(&user) == Some(&hash)).then_some(user)
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> (PathBuf, Auth, IpAddr) {
        let dir = std::env::temp_dir().join(format!("sundial-auth-{tag}-{}", std::process::id()));
        let path = dir.join("admins");
        set(&path, "pw1");
        (path.clone(), Auth::new(path), "10.0.0.5".parse().unwrap())
    }

    fn set(path: &Path, pw: &str) {
        let admins = HashMap::from([("mom".to_string(), hash_password(pw).unwrap())]);
        write_admins(path, &admins).unwrap();
    }

    fn token(l: Login) -> Option<String> {
        match l {
            Login::In(t) => Some(t),
            _ => None,
        }
    }

    #[test]
    fn login_flow() {
        let (path, auth, ip) = fixture("flow");
        assert!(matches!(auth.login(ip, "mom", "wrong", 0), Login::Bad));
        assert!(matches!(auth.login(ip, "nobody", "pw1", 0), Login::Bad));
        assert!(matches!(
            auth.login(ip, "nobody", "sundial-dummy", 0),
            Login::Bad
        ));
        let tok = token(auth.login(ip, "mom", "pw1", 0)).unwrap();
        assert_eq!(auth.check(&tok, 10).as_deref(), Some("mom"));
        assert!(auth.check(&tok, SESSION_DAYS * 86_400 + 1).is_none());
        for _ in 0..5 {
            auth.login(ip, "mom", "bad", 100);
        }
        assert!(auth.throttled(ip, 101));
        assert!(!auth.throttled(ip, 100 + FAILURE_WINDOW));
        set(&path, "pw2");
        assert!(auth.check(&tok, 10).is_none(), "changed password signs out");
        let tok = auth.reopen("mom", 10).unwrap();
        assert!(auth.check(&tok, 11).is_some());
        write_admins(&path, &HashMap::new()).unwrap();
        assert!(
            auth.check(&tok, 11).is_none(),
            "deleted login is signed out"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn two_factor_flow() {
        let (path, auth, ip) = fixture("2fa");
        let now = 1_800_000_000;
        let secret = two_factor::new_secret();
        assert!(
            auth.enable_two_factor("mom", &secret, "abc", now)
                .unwrap()
                .is_none()
        );
        assert!(!auth.has_two_factor("mom"));
        let code = two_factor::tests::now_code(&secret, now);
        let rec = auth
            .enable_two_factor("mom", &secret, &code, now)
            .unwrap()
            .unwrap();
        let Login::Code(p) = auth.login(ip, "mom", "pw1", now) else {
            panic!("password alone must not be enough");
        };
        assert!(auth.check(&p, now).is_none());
        assert!(
            auth.finish(ip, &p, &code, now).is_none(),
            "used while turning on"
        );
        assert!(
            auth.finish(ip, &p, &rec[0], now + CODE_WAIT).is_none(),
            "too late"
        );
        let t = auth.finish(ip, &p, &rec[0], now).unwrap();
        assert!(auth.check(&t, now).is_some());
        assert!(
            auth.finish(ip, &p, &rec[1], now).is_none(),
            "one sign-in each"
        );
        // The right password again doesn't reset the count of wrong codes.
        for _ in 0..MAX_BAD_CODES {
            let Login::Code(p) = auth.login(ip, "mom", "pw1", now) else {
                panic!()
            };
            auth.finish(ip, &p, "not-it", now);
        }
        assert!(auth.throttled(ip, now));
        let other: IpAddr = "10.0.0.6".parse().unwrap();
        let Login::Code(p) = auth.login(other, "mom", "pw1", now) else {
            panic!()
        };
        assert!(
            auth.finish(other, &p, &rec[2], now).is_none(),
            "login locked"
        );
        assert!(auth.disable_two_factor("mom").unwrap());
        assert!(token(auth.login(other, "mom", "pw1", now)).is_some());
        std::fs::write(two_factor::path(&path), "junk").unwrap();
        assert!(
            matches!(auth.login(other, "mom", "pw1", now), Login::Bad),
            "fails closed"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
