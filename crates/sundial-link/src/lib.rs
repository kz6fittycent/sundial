//! Protocol between Sundial (dials out) and Sundial Server: JSON messages over a TLS
//! WebSocket at `/link`, and the pairing code.

pub mod tls;

use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_core::rules::Override;

pub const PROTO: u32 = 1;
pub const DEFAULT_PORT: u16 = 8461;
pub const MAX_MESSAGE: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    Pair { secret: String },
    Token { host_id: String, token: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMsg {
    Hello {
        proto: u32,
        name: String,
        version: String,
        auth: Auth,
        /// The same for every pairing of this computer, so pairing again replaces
        /// its entry. Absent from older hosts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        machine: Option<String>,
    },
    /// Everything the host knows about its accounts.
    Status { status: Box<AdminResponse> },
    /// The command was handled (or refused) and must not be sent again.
    Ack {
        id: String,
        ok: bool,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Welcome {
        host_id: String,
        /// Only after pairing.
        token: Option<String>,
    },
    Refused {
        reason: String,
    },
    Command(Command),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    /// Unix time after which the host must not apply it.
    pub expires: i64,
    pub req: AdminRequest,
}

const HOUR: i64 = 3600;

/// How long a command may wait for a host that is offline. Extra time goes stale
/// quickly; limits and locks are still wanted later.
pub fn expiry(req: &AdminRequest, now: i64) -> i64 {
    match req {
        AdminRequest::SetPolicy { .. } | AdminRequest::SetLocation { .. } => now + 7 * 24 * HOUR,
        AdminRequest::Act { action, .. } => match action {
            Override::AllowUntil { at } => *at,
            Override::Lock { until: Some(u), .. } => *u,
            Override::Lock { until: None, .. } | Override::Clear => now + 12 * HOUR,
            _ => now + HOUR / 2,
        },
        // "Here" must still be here.
        AdminRequest::AddPlace { .. } => now + 120,
        AdminRequest::RemovePlace { .. } => now + 7 * 24 * HOUR,
        AdminRequest::Status => now,
    }
}

// No I, L, O or U: easy to read aloud and type.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_LEN: usize = 8;
const PIN_LEN: usize = 16;

/// What a parent types on the host: the start of the server certificate's fingerprint
/// (80 bits; absent when the certificate is publicly trusted) and a one-time secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCode {
    pub pin: Option<String>,
    pub secret: String,
}

impl PairCode {
    pub fn new(self_signed_der: Option<&[u8]>) -> PairCode {
        PairCode {
            pin: self_signed_der.map(short_fingerprint),
            secret: (0..SECRET_LEN)
                .map(|_| ALPHABET[OsRng.gen_range(0..32)] as char)
                .collect(),
        }
    }

    pub fn parse(s: &str) -> Result<PairCode, String> {
        let c: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            })
            .collect();
        if !c.bytes().all(|b| ALPHABET.contains(&b)) {
            return Err("the code has a character that is never used".into());
        }
        match c.len() {
            SECRET_LEN => Ok(PairCode {
                pin: None,
                secret: c,
            }),
            n if n == PIN_LEN + SECRET_LEN => Ok(PairCode {
                pin: Some(c[..PIN_LEN].to_string()),
                secret: c[PIN_LEN..].to_string(),
            }),
            _ => Err("the code should have 8 or 24 characters".into()),
        }
    }
}

impl std::fmt::Display for PairCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let all = format!("{}{}", self.pin.as_deref().unwrap_or(""), self.secret);
        for (i, c) in all.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                f.write_str("-")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// First 80 bits of the certificate's SHA-256, in the code alphabet.
pub fn short_fingerprint(der: &[u8]) -> String {
    let sum = Sha256::digest(der);
    let mut n = 0u128;
    for b in &sum[..10] {
        n = (n << 8) | u128::from(*b);
    }
    (0..PIN_LEN)
        .rev()
        .map(|i| ALPHABET[((n >> (5 * i)) & 31) as usize] as char)
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trip() {
        for der in [None, Some(b"cert".as_slice())] {
            let c = PairCode::new(der);
            let shown = c.to_string();
            assert_eq!(PairCode::parse(&shown).unwrap(), c);
            assert_eq!(PairCode::parse(&shown.to_lowercase()).unwrap(), c);
        }
        assert!(PairCode::parse("ABCD").is_err());
        assert!(PairCode::parse("ABCD-EFG!").is_err());
        assert_ne!(short_fingerprint(b"a"), short_fingerprint(b"b"));
    }

    #[test]
    fn stale_grants_expire_before_locks() {
        let act = |action| AdminRequest::Act {
            user: "kid".into(),
            by: "mom".into(),
            action,
        };
        assert_eq!(expiry(&act(Override::Grant { minutes: 30 }), 0), 1800);
        assert_eq!(expiry(&act(Override::AllowUntil { at: 99 }), 0), 99);
        let lock = Override::Lock {
            in_secs: 0,
            until: None,
        };
        assert_eq!(expiry(&act(lock), 0), 12 * HOUR);
    }
}
