//! Process-local ephemeral TLS identities. Nothing in this module reads or writes disk.
use anyhow::Result;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::{Arc, Mutex};
pub struct Identity {
    pub id: String,
    pub name: String,
    pub cert: Vec<u8>,
    key: Vec<u8>,
}
pub fn fingerprint(cert: &[u8]) -> String {
    blake3::hash(cert).to_hex().to_string()
}
impl Identity {
    pub fn ephemeral() -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(vec!["clipx.local".into()])?;
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "clipx-device".into()),
            cert: generated.cert.der().to_vec(),
            key: generated.signing_key.serialize_der(),
        })
    }
    pub fn fp(&self) -> String {
        fingerprint(&self.cert)
    }
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key.clone()).into()
    }
    pub fn client_config(
        &self,
        observed: Arc<Mutex<Option<String>>>,
    ) -> Result<rustls::ClientConfig> {
        let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProvisionalServer { observed }))
        .with_client_auth_cert(vec![CertificateDer::from(self.cert.clone())], self.key())?;
        c.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        c.enable_early_data = false;
        Ok(c)
    }
    pub fn server_config(&self) -> Result<rustls::ServerConfig> {
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(ProvisionalClient))
        .with_single_cert(vec![CertificateDer::from(self.cert.clone())], self.key())?;
        c.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        c.max_early_data_size = 0;
        Ok(c)
    }
}
fn signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}
fn schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}
fn reject() -> rustls::Error {
    rustls::Error::General("certificate verification failed".into())
}
#[derive(Debug)]
struct ProvisionalServer {
    observed: Arc<Mutex<Option<String>>>,
}
impl ServerCertVerifier for ProvisionalServer {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end.as_ref());
        // TLS proves key possession; application authorization binds the session exporter.
        *self.observed.lock().map_err(|_| reject())? = Some(fp);
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(reject())
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}
#[derive(Debug)]
struct ProvisionalClient;
impl ClientCertVerifier for ProvisionalClient {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let _ = end; // Only key possession here; application SAS approval is mandatory before payload.
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(reject())
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn identities_are_one_time() {
        let a = super::Identity::ephemeral().unwrap();
        let b = super::Identity::ephemeral().unwrap();
        assert_ne!(a.fp(), b.fp());
        assert_ne!(a.id, b.id);
    }
}
