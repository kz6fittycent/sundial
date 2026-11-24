//! Self-signed certificate, created on first start.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub struct CertFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

/// Reuse the existing cert or make one for these names and addresses.
pub fn ensure_cert(dir: &Path, host: &str, addresses: Vec<String>) -> Result<CertFiles> {
    let files = CertFiles {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    };
    if files.cert.exists() && files.key.exists() {
        return Ok(files);
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut names = vec![
        host.to_string(),
        format!("{host}.local"),
        "localhost".to_string(),
    ];
    names.extend(addresses);
    let ck = rcgen::generate_simple_self_signed(names).context("generating certificate")?;
    write_private(&files.key, ck.key_pair.serialize_pem().as_bytes())?;
    write_private(&files.cert, ck.cert.pem().as_bytes())?;
    Ok(files)
}

/// Certificate (DER) from a PEM file.
pub fn cert_der(cert_pem: &Path) -> Option<Vec<u8>> {
    let pem = std::fs::read_to_string(cert_pem).ok()?;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&b64)
}

/// SHA-256 fingerprint of the certificate, as browsers show it (AB:CD:...).
pub fn fingerprint(cert_pem: &Path) -> Option<String> {
    let pem = std::fs::read_to_string(cert_pem).ok()?;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64_decode(&b64)?;
    let sum = Sha256::digest(der);
    Some(
        sum.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|&c| c != b'=') {
        let v = T.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn b64() {
        assert_eq!(super::base64_decode("aGVsbG8=").unwrap(), b"hello");
    }
}
