use anyhow::{Context, Result, bail};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub cert: Vec<u8>,
    key: Vec<u8>,
}
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Trust {
    pub hosts: BTreeMap<String, String>,
    pub fingerprints: BTreeSet<String>,
    pub aliases: BTreeMap<String, String>,
}
pub fn config_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    explicit
        .or_else(|| dirs::config_dir().map(|p| p.join("clipx")))
        .context("cannot locate config directory; use --config-dir")
}
pub fn fingerprint(cert: &[u8]) -> String {
    blake3::hash(cert).to_hex().to_string()
}
pub fn valid_fingerprint(fp: &str) -> Result<String> {
    let fp = fp.replace(':', "").to_lowercase();
    if fp.len() != 64 || hex::decode(&fp).is_err() {
        bail!("fingerprint must contain 64 hexadecimal characters");
    }
    Ok(fp)
}
impl Identity {
    pub fn load(dir: &Path) -> Result<Self> {
        crate::paths::private_dir(dir)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("config.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let path = dir.join("identity.json");
        if path.exists() {
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                bail!("identity symlink refused");
            }
            let value: Self = serde_json::from_reader(fs::File::open(path)?)?;
            return Ok(value);
        }
        let generated = rcgen::generate_simple_self_signed(vec!["clipx.local".into()])?;
        let identity = Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "clipx-device".into()),
            cert: generated.cert.der().to_vec(),
            key: generated.signing_key.serialize_der(),
        };
        crate::paths::atomic_json(&path, &identity)?;
        Ok(identity)
    }
    pub fn fp(&self) -> String {
        fingerprint(&self.cert)
    }
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key.clone()).into()
    }
    pub fn client_config(
        &self,
        expected: Option<String>,
        observed: Arc<Mutex<Option<String>>>,
    ) -> Result<rustls::ClientConfig> {
        let verifier = PinServer { expected, observed };
        let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![CertificateDer::from(self.cert.clone())], self.key())?;
        c.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        c.enable_early_data = false;
        Ok(c)
    }
    pub fn server_config(
        &self,
        trust: BTreeSet<String>,
        pairing: bool,
    ) -> Result<rustls::ServerConfig> {
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PinClient { trust, pairing }))
        .with_single_cert(vec![CertificateDer::from(self.cert.clone())], self.key())?;
        c.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        c.max_early_data_size = 0;
        Ok(c)
    }
}
impl Trust {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("peers.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_reader(fs::File::open(path)?)?)
    }
    pub fn edit(dir: &Path, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        crate::paths::private_dir(dir)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("config.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let mut t = Self::load(dir)?;
        f(&mut t)?;
        crate::paths::atomic_json(&dir.join("peers.json"), &t)
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
    rustls::Error::General("untrusted or changed certificate fingerprint; pair explicitly".into())
}
#[derive(Debug)]
struct PinServer {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}
impl ServerCertVerifier for PinServer {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end.as_ref());
        if let Some(expected) = &self.expected
            && &fp != expected
        {
            return Err(reject());
        }
        // None is used ONLY by the explicit pair probe, never by send. TLS still verifies key possession below.
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
struct PinClient {
    trust: BTreeSet<String>,
    pairing: bool,
}
impl ClientCertVerifier for PinClient {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if !self.pairing && !self.trust.contains(&fingerprint(end.as_ref())) {
            return Err(reject());
        }
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
    fn identity_is_persistent_and_private() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let a = super::Identity::load(dir.path())?;
        let b = super::Identity::load(dir.path())?;
        assert_eq!(a.fp(), b.fp());
        assert_eq!(a.id, b.id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.path().join("identity.json"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }
}
