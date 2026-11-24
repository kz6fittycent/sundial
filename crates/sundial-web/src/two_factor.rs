//! Optional two-factor sign-in: time-based codes (RFC 6238) and one-time recovery codes.
//! `two-factor.json` sits next to the logins file.

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const STEP: i64 = 30;
pub const RECOVERY_CODES: usize = 8;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Serialize, Deserialize)]
pub struct Factor {
    /// Base32.
    pub secret: String,
    /// The last time step used, so a code can't be used twice.
    #[serde(default)]
    pub last_step: i64,
    /// SHA-256 of the unused recovery codes.
    #[serde(default)]
    pub recovery: Vec<String>,
}

pub type Factors = HashMap<String, Factor>;

pub fn path(admins: &Path) -> PathBuf {
    admins.with_file_name("two-factor.json")
}

/// A damaged file is an error, never "nobody uses two-factor".
pub fn read(admins: &Path) -> anyhow::Result<Factors> {
    match std::fs::read(path(admins)) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Factors::new()),
        Err(e) => Err(e.into()),
    }
}

pub fn write(admins: &Path, f: &Factors) -> anyhow::Result<()> {
    crate::auth::write_private(&path(admins), &serde_json::to_vec_pretty(f)?)
}

/// Turn it off for a login. True if it was on.
pub fn clear(admins: &Path, name: &str) -> anyhow::Result<bool> {
    let mut f = read(admins)?;
    let had = f.remove(name).is_some();
    if had {
        write(admins, &f)?;
    }
    Ok(had)
}

pub fn new_secret() -> String {
    let mut b = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base32(&b)
}

/// New recovery codes: what to show, and what to store.
pub fn new_recovery() -> (Vec<String>, Vec<String>) {
    let show: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| {
            let mut b = [0u8; 10];
            rand::rngs::OsRng.fill_bytes(&mut b);
            let s = base32(&b).to_lowercase();
            format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..16])
        })
        .collect();
    let store = show.iter().map(|c| recovery_hash(c)).collect();
    (show, store)
}

fn recovery_hash(code: &str) -> String {
    let plain: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    Sha256::digest(plain.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn base32(b: &[u8]) -> String {
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for x in b {
        acc = (acc << 8) | u32::from(*x);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[(acc >> bits) as usize & 31] as char);
        }
        acc &= (1 << bits) - 1;
    }
    out
}

fn unbase32(s: &str) -> Vec<u8> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for v in s
        .bytes()
        .filter_map(|c| BASE32.iter().position(|b| *b == c))
    {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut m = Hmac::<Sha1>::new_from_slice(secret).expect("any length");
    m.update(&step.to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 15) as usize;
    (u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff) % 1_000_000
}

/// The time step this code belongs to, one step of clock drift either way.
fn matching_step(secret: &str, code: u32, after: i64, now: i64) -> Option<i64> {
    let key = unbase32(secret);
    let t = now / STEP;
    (t - 1..=t + 1).find(|s| *s > after && code_at(&key, *s) == code)
}

impl Factor {
    /// Check a code and use it up; save afterwards if true.
    pub fn accept(&mut self, code: &str, now: i64) -> bool {
        let plain: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if plain.len() == 6 && plain.bytes().all(|c| c.is_ascii_digit()) {
            let Ok(n) = plain.parse() else { return false };
            return match matching_step(&self.secret, n, self.last_step, now) {
                Some(s) => {
                    self.last_step = s;
                    true
                }
                None => false,
            };
        }
        let h = recovery_hash(&plain);
        match self.recovery.iter().position(|r| *r == h) {
            Some(i) => {
                self.recovery.remove(i);
                true
            }
            None => false,
        }
    }
}

/// For the authenticator app.
pub fn uri(secret: &str, name: &str) -> String {
    format!(
        "otpauth://totp/Sundial:{}?secret={secret}&issuer=Sundial",
        crate::enc(name)
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The right code now, for tests.
    pub fn now_code(secret: &str, now: i64) -> String {
        format!("{:06}", code_at(&unbase32(secret), now / STEP))
    }

    #[test]
    fn rfc_vectors() {
        let key = b"12345678901234567890";
        for (t, want) in [(59, 287082), (1111111109, 81804), (20000000000, 353130)] {
            assert_eq!(code_at(key, t / STEP), want);
        }
        assert_eq!(base32(key), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(unbase32(&base32(key)), key);
    }

    #[test]
    fn codes_work_once() {
        let (show, store) = new_recovery();
        let mut f = Factor {
            secret: new_secret(),
            last_step: 0,
            recovery: store,
        };
        let now = 1_800_000_000;
        let c = now_code(&f.secret, now);
        assert!(f.accept(&c, now));
        assert!(!f.accept(&c, now), "replayed");
        assert!(!f.accept(&now_code(&f.secret, now - 300), now), "old");
        assert!(f.accept(&now_code(&f.secret, now + 30), now), "drift");
        assert!(f.accept(&show[0].to_uppercase(), now));
        assert!(!f.accept(&show[0], now));
        assert!(!f.accept("", now));
        assert_eq!(f.recovery.len(), RECOVERY_CODES - 1);
    }
}
