//! This computer's parent page (see sundial-web), over HTTPS on the LAN.

use crate::daemon::Shared;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sundial_core::config::DEFAULT_ADMINS_PATH;
use sundial_core::proto::AdminRequest;
use sundial_web::auth::Auth;
use sundial_web::{App, Backend, Section};

struct Local(Shared);

impl Backend for Local {
    fn subtitle(&self) -> String {
        format!("on {}", crate::sys::hostname())
    }

    fn sections(&self) -> Vec<Section> {
        vec![Section {
            key: String::new(),
            title: None,
            note: None,
            status: self.0.lock().unwrap().handle(AdminRequest::Status),
        }]
    }

    fn handle(&self, _: &str, req: AdminRequest) -> Result<String, String> {
        let r = self.0.lock().unwrap().handle(req);
        if r.ok {
            Ok(r.message.unwrap_or_default())
        } else {
            Err(r.error.unwrap_or_else(|| "failed".into()))
        }
    }

    fn passwd_command(&self) -> &'static str {
        "sudo sundial passwd NAME"
    }
}

pub async fn serve(daemon: Shared, listen: &str) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("bad web listen address {listen:?}"))?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let files = sundial_link::tls::ensure_cert(
        Path::new("/var/lib/sundial/tls"),
        &crate::sys::hostname(),
        crate::sys::addresses(),
    )?;
    if let Some(fp) = sundial_link::tls::fingerprint(&files.cert) {
        println!(
            "sundial: web page on https://{}:{} (certificate SHA-256 {fp})",
            crate::sys::hostname(),
            addr.port()
        );
    }
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key)
        .await
        .context("loading TLS certificate")?;
    let app = App {
        backend: Arc::new(Local(daemon)),
        auth: Arc::new(Auth::new(PathBuf::from(DEFAULT_ADMINS_PATH))),
    };
    axum_server::bind_rustls(addr, tls)
        .serve(sundial_web::router(app).into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("web server")?;
    Ok(())
}
