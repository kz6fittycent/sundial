//! Optional connection to a Sundial Server. This computer dials out, sends its status
//! and applies a parent's commands; nothing listens here, and every rule keeps working
//! without the server.

use crate::daemon::Shared;
use anyhow::{Context, Result, bail};
use chrono::Local;
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_link::{Auth, Command, DEFAULT_PORT, HostMsg, MAX_MESSAGE, PROTO, PairCode, ServerMsg};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

const LINK_PATH: &str = "/etc/sundial/link.json";
const APPLIED_PATH: &str = "/var/lib/sundial/link-applied.json";
const APPLIED_KEEP: usize = 200;
const STATUS_EVERY: Duration = Duration::from_secs(15);
/// The server pings more often than this; silence means the connection is dead
/// (the laptop slept, changed networks, ...).
const DEAD_AFTER: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Link {
    /// host:port
    server: String,
    host_id: String,
    token: String,
    /// Start of the self-signed certificate's fingerprint; None = publicly trusted.
    pin: Option<String>,
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Accepts exactly one certificate. Handshake signatures are still checked, so the
/// peer must hold that certificate's key.
#[derive(Debug)]
struct Pinned {
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sundial_link::short_fingerprint(cert) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "this is not the server that was paired (its certificate is different)".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// "example.com" -> "example.com:PORT". A self-signed server defaults to Sundial's own
/// port, a publicly trusted one to 443.
fn with_port(server: &str, pinned: bool) -> String {
    let s = server
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let has_port = match s.rfind(']') {
        Some(i) => s[i..].contains(':'),
        None => s.contains(':'),
    };
    if has_port {
        s.to_string()
    } else {
        format!("{s}:{}", if pinned { DEFAULT_PORT } else { 443 })
    }
}

async fn connect(server: &str, pin: Option<&str>) -> Result<Ws> {
    let connector = match pin {
        None => None,
        Some(pin) => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Pinned {
                    pin: pin.to_string(),
                    provider,
                }))
                .with_no_client_auth();
            Some(Connector::Rustls(Arc::new(cfg)))
        }
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let limits = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (ws, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(
            format!("wss://{server}/link"),
            Some(limits),
            false,
            connector,
        ),
    )
    .await
    .context("the server didn't answer")?
    .with_context(|| format!("connecting to {server}"))?;
    Ok(ws)
}

async fn send(ws: &mut Ws, m: &HostMsg) -> Result<()> {
    ws.send(Message::Text(serde_json::to_string(m)?.into()))
        .await?;
    Ok(())
}

/// Next message from the server, answering nothing itself (pings are handled below us).
async fn recv(ws: &mut Ws) -> Result<ServerMsg> {
    loop {
        match ws.next().await.context("connection closed")?? {
            Message::Text(t) => return serde_json::from_str(&t).context("bad message"),
            Message::Close(_) => bail!("the server closed the connection"),
            _ => continue,
        }
    }
}

async fn hello(ws: &mut Ws, auth: Auth) -> Result<(String, Option<String>)> {
    send(
        ws,
        &HostMsg::Hello {
            proto: PROTO,
            name: crate::sys::hostname(),
            version: env!("CARGO_PKG_VERSION").into(),
            auth,
        },
    )
    .await?;
    match tokio::time::timeout(CONNECT_TIMEOUT, recv(ws))
        .await
        .context("no answer")??
    {
        ServerMsg::Welcome { host_id, token } => Ok((host_id, token)),
        ServerMsg::Refused { reason } => bail!("the server refused: {reason}"),
        ServerMsg::Command(_) => bail!("unexpected message"),
    }
}

fn write_private(path: &str, text: &str) -> Result<()> {
    use std::io::Write;
    let tmp = format!("{path}.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {path} (run as root)"))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn load() -> Option<Link> {
    serde_json::from_str(&std::fs::read_to_string(LINK_PATH).ok()?).ok()
}

/// `sundial pair SERVER CODE`
pub async fn pair(server: &str, code: &str) -> Result<()> {
    if Path::new(LINK_PATH).exists() {
        bail!("already paired; run `sundial unpair` first");
    }
    // Fail before using up the code if we couldn't save the result.
    write_private(LINK_PATH, "")?;
    let paired = pair_inner(server, code).await;
    match paired {
        Ok(link) => {
            write_private(LINK_PATH, &serde_json::to_string(&link)?)?;
            println!("Paired with {}.", link.server);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(LINK_PATH);
            Err(e)
        }
    }
}

async fn pair_inner(server: &str, code: &str) -> Result<Link> {
    let code = PairCode::parse(code).map_err(anyhow::Error::msg)?;
    let server = with_port(server, code.pin.is_some());
    let mut ws = connect(&server, code.pin.as_deref()).await?;
    let auth = Auth::Pair {
        secret: code.secret,
    };
    let (host_id, token) = hello(&mut ws, auth).await?;
    let token = token.context("the server sent no token")?;
    let _ = ws.close(None).await;
    Ok(Link {
        server,
        host_id,
        token,
        pin: code.pin,
    })
}

/// `sundial unpair`
pub fn unpair() -> Result<()> {
    std::fs::remove_file(LINK_PATH).context("not paired (or not root)")?;
    println!("Unpaired. Also remove this computer on the server.");
    Ok(())
}

/// Commands already handled, so one that is sent twice is applied once.
struct Applied(Vec<String>);

impl Applied {
    fn load() -> Applied {
        Applied(
            std::fs::read_to_string(APPLIED_PATH)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default(),
        )
    }

    /// True the first time. Saved before the command runs: after a crash it may be lost
    /// but never repeated.
    fn claim(&mut self, id: &str) -> Result<bool> {
        if self.0.iter().any(|x| x == id) {
            return Ok(false);
        }
        self.0.push(id.to_string());
        let extra = self.0.len().saturating_sub(APPLIED_KEEP);
        self.0.drain(..extra);
        write_private(APPLIED_PATH, &serde_json::to_string(&self.0)?)?;
        Ok(true)
    }
}

/// Only a parent's overrides and limits are accepted from the server.
fn remote(req: AdminRequest) -> Option<AdminRequest> {
    let via = |by: String| format!("{by} via server");
    match req {
        AdminRequest::Act { user, by, action } => Some(AdminRequest::Act {
            user,
            by: via(by),
            action,
        }),
        AdminRequest::SetPolicy { user, by, policy } => Some(AdminRequest::SetPolicy {
            user,
            by: via(by),
            policy,
        }),
        AdminRequest::Status => None,
    }
}

fn apply(daemon: &Shared, applied: &mut Applied, c: Command) -> HostMsg {
    let ack = |ok, message: String| HostMsg::Ack {
        id: c.id.clone(),
        ok,
        message,
    };
    if c.expires <= Local::now().timestamp() {
        return ack(false, "expired before this computer was online".into());
    }
    let Some(req) = remote(c.req.clone()) else {
        return ack(false, "not allowed from the server".into());
    };
    match applied.claim(&c.id) {
        Ok(true) => {}
        Ok(false) => return ack(true, "already applied".into()),
        Err(e) => return ack(false, format!("{e:#}")),
    }
    let r = daemon.lock().unwrap().handle(req);
    ack(r.ok, r.message.or(r.error).unwrap_or_default())
}

fn status(daemon: &Shared) -> HostMsg {
    let s: AdminResponse = daemon.lock().unwrap().handle(AdminRequest::Status);
    HostMsg::Status {
        status: Box::new(s),
    }
}

async fn session(daemon: &Shared, link: &Link, applied: &mut Applied) -> Result<()> {
    let mut ws = connect(&link.server, link.pin.as_deref()).await?;
    hello(
        &mut ws,
        Auth::Token {
            host_id: link.host_id.clone(),
            token: link.token.clone(),
        },
    )
    .await?;
    println!("sundial: connected to server {}", link.server);
    let mut tick = tokio::time::interval(STATUS_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heard = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if load().as_ref() != Some(link) {
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                if heard.elapsed() > DEAD_AFTER {
                    bail!("connection lost");
                }
                send(&mut ws, &status(daemon)).await?;
            }
            m = ws.next() => {
                let m = m.context("connection closed")??;
                heard = tokio::time::Instant::now();
                match m {
                    Message::Text(t) => match serde_json::from_str(&t).context("bad message")? {
                        ServerMsg::Command(c) => {
                            let ack = apply(daemon, applied, c);
                            send(&mut ws, &ack).await?;
                            send(&mut ws, &status(daemon)).await?;
                        }
                        ServerMsg::Refused { reason } => bail!("the server refused: {reason}"),
                        ServerMsg::Welcome { .. } => {}
                    },
                    Message::Close(_) => bail!("the server closed the connection"),
                    _ => {}
                }
            }
        }
    }
}

/// Stay connected while paired.
pub async fn run(daemon: Shared) {
    let mut applied = Applied::load();
    let mut last_err = String::new();
    let mut wait = 5;
    loop {
        if let Some(link) = load() {
            let started = tokio::time::Instant::now();
            match session(&daemon, &link, &mut applied).await {
                Ok(()) => last_err.clear(),
                Err(e) => {
                    let e = format!("{e:#}");
                    // Offline for hours is normal; say it once.
                    if e != last_err {
                        eprintln!("sundial: server link: {e}");
                        last_err = e;
                    }
                }
            }
            wait = if started.elapsed() > DEAD_AFTER {
                5
            } else {
                (wait * 2).min(60)
            };
        } else {
            wait = 5;
        }
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports() {
        assert_eq!(with_port("https://a.example/", false), "a.example:443");
        assert_eq!(with_port("192.168.1.5", true), "192.168.1.5:8461");
        assert_eq!(with_port("a:9000", true), "a:9000");
        assert_eq!(with_port("[fd00::1]", true), "[fd00::1]:8461");
        assert_eq!(with_port("[fd00::1]:9", true), "[fd00::1]:9");
    }

    #[test]
    fn server_cannot_send_anything_else() {
        assert!(remote(AdminRequest::Status).is_none());
    }
}
