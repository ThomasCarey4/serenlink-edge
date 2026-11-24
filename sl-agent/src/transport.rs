//! TLS 1.3 to the gateway, the RFC 9266 `tls-exporter` channel binding the session signs, and
//! the WebSocket over it (agent spec 3.6). Frames are binary messages of one `Envelope`.
use std::path::Path;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;

pub type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

pub const BINDING_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

pub fn tls_config(ca_pem: &Path) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_file_iter(ca_pem).map_err(|e| format!("{}: {e}", ca_pem.display()))? {
        let der = der.map_err(|e| format!("{}: {e}", ca_pem.display()))?;
        roots.add(der).map_err(|e| format!("{}: {e}", ca_pem.display()))?;
    }
    if roots.is_empty() {
        return Err(format!("{}: no certificate", ca_pem.display()));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub async fn connect(addr: &str, hostname: &str, tls: Arc<rustls::ClientConfig>) -> Result<(Ws, [u8; 32]), String> {
    let name = ServerName::try_from(hostname.to_string()).map_err(|e| format!("{hostname}: {e}"))?;
    let tcp = TcpStream::connect(addr).await.map_err(|e| format!("{addr}: {e}"))?;
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS: {e}"))?;
    let mut binding = [0u8; 32];
    tls.get_ref()
        .1
        .export_keying_material(&mut binding[..], BINDING_LABEL, None)
        .map_err(|e| format!("no channel binding: {e}"))?;
    let (ws, _) = tokio_tungstenite::client_async(format!("wss://{hostname}/"), tls)
        .await
        .map_err(|e| format!("WebSocket: {e}"))?;
    Ok((ws, binding))
}
