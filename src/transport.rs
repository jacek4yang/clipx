use crate::{
    identity::Identity,
    protocol::{self, Msg},
};
use anyhow::{Context, Result, bail};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Wire {
    pub r: Box<dyn AsyncRead + Unpin + Send>,
    pub w: Box<dyn AsyncWrite + Unpin + Send>,
}
impl Wire {
    pub async fn send(&mut self, m: &Msg) -> Result<()> {
        Ok(
            tokio::time::timeout(Duration::from_secs(120), protocol::write(&mut *self.w, m))
                .await??,
        )
    }
    pub async fn recv(&mut self) -> Result<Msg> {
        loop {
            let m: Msg =
                tokio::time::timeout(Duration::from_secs(120), protocol::read(&mut *self.r))
                    .await??;
            if matches!(m, Msg::Busy) {
                continue;
            }
            if let Msg::Error { message } = &m {
                return Err(PeerRejected(message.chars().take(512).collect()).into());
            }
            return Ok(m);
        }
    }
}
pub struct Session {
    pub ctrl: Wire,
    pub conn: Option<quinn::Connection>,
    pub endpoint: Option<quinn::Endpoint>,
    pub fingerprint: String,
    pub transport: &'static str,
    pub peer_device: String,
    pub peer_name: String,
    pub pairing_confirmation: bool,
    pub session_nonce: String,
    pub authorized: bool,
    pub binding: [u8; 32],
}
impl Session {
    pub async fn data(&mut self) -> Result<Wire> {
        let c = self.conn.as_ref().context("no QUIC connection")?;
        let (w, r) = c.open_bi().await?;
        Ok(Wire {
            r: Box::new(r),
            w: Box::new(w),
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(c) = &self.conn {
            c.close(0u32.into(), b"session ended");
        }
    }
}
pub fn tuning() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.max_idle_timeout(Some(
        Duration::from_secs(45)
            .try_into()
            .expect("constant duration"),
    ));
    t.max_concurrent_bidi_streams(5u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    // Retain Quinn's CUBIC, conservative initial MTU, PMTU discovery and flow-control defaults.
    Arc::new(t)
}
async fn ready(mut s: Session, id: &Identity, pair: bool) -> Result<Session> {
    s.ctrl
        .send(&Msg::Hello {
            version: 2,
            device: id.id.clone(),
            name: id.name.clone(),
            pair,
            chunk: protocol::CHUNK,
        })
        .await?;
    match s.ctrl.recv().await? {
        Msg::Ready {
            version,
            chunk,
            device,
            name,
            pairing_confirmation,
            session_nonce,
        } => {
            protocol::check_version(version, chunk)?;
            if device.len() > 128
                || name.len() > 128
                || uuid::Uuid::parse_str(&session_nonce).is_err()
            {
                bail!("invalid session greeting");
            }
            s.peer_device = device;
            s.peer_name = name;
            s.pairing_confirmation = pairing_confirmation;
            s.session_nonce = session_nonce;
        }
        _ => bail!("expected SessionReady"),
    }
    Ok(s)
}
async fn one(addr: SocketAddr, mode: &str, id: &Identity, pair: bool) -> Result<Session> {
    let observed = Arc::new(Mutex::new(None));
    let cfg = id.client_config(observed.clone())?;
    let (ctrl, conn, endpoint, transport, binding) = if mode == "quic" {
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let mut endpoint = quinn::Endpoint::client(bind)?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)?;
        let mut qc = quinn::ClientConfig::new(Arc::new(crypto));
        qc.transport_config(tuning());
        endpoint.set_default_client_config(qc);
        let conn = endpoint.connect(addr, "clipx.local")?.await?;
        let mut binding = [0; 32];
        conn.export_keying_material(&mut binding, b"EXPORTER-clipx-session", b"")
            .map_err(|_| anyhow::anyhow!("TLS exporter failed"))?;
        let (w, r) = conn.open_bi().await?;
        (
            Wire {
                r: Box::new(r),
                w: Box::new(w),
            },
            Some(conn),
            Some(endpoint),
            "quic",
            binding,
        )
    } else {
        let socket = tokio::net::TcpStream::connect(addr).await?;
        socket.set_nodelay(true)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                rustls::pki_types::ServerName::try_from("clipx.local")?,
                socket,
            )
            .await?;
        if tls.get_ref().1.alpn_protocol() != Some(protocol::ALPN)
            || tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            bail!("ALPN mismatch");
        }
        let binding =
            tls.get_ref()
                .1
                .export_keying_material([0u8; 32], b"EXPORTER-clipx-session", None)?;
        let (r, w) = tokio::io::split(tls);
        (
            Wire {
                r: Box::new(r),
                w: Box::new(w),
            },
            None,
            None,
            "tcp",
            binding,
        )
    };
    let fp = observed
        .lock()
        .map_err(|_| anyhow::anyhow!("certificate state poisoned"))?
        .clone()
        .context("no peer certificate")?;
    ready(
        Session {
            ctrl,
            conn,
            endpoint,
            fingerprint: fp,
            transport,
            peer_device: String::new(),
            peer_name: String::new(),
            pairing_confirmation: false,
            session_nonce: String::new(),
            authorized: false,
            binding,
        },
        id,
        pair,
    )
    .await
}
async fn family(host: &str, port: u16, mode: &str, id: &Identity, pair: bool) -> Result<Session> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await?
        .take(16)
        .collect();
    let mut last = anyhow::anyhow!("hostname has no addresses");
    for addr in addresses {
        match tokio::time::timeout(Duration::from_secs(5), one(addr, mode, id, pair)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(e) => last = e.into(),
        }
    }
    Err(last)
}
pub async fn connect(
    host: &str,
    port: u16,
    mode: &str,
    id: &Identity,

    pair: bool,
) -> Result<Session> {
    if mode != "auto" {
        return family(host, port, mode, id, pair).await;
    }
    let q = family(host, port, "quic", id, pair);
    let t = async {
        tokio::time::sleep(Duration::from_millis(350)).await;
        family(host, port, "tcp", id, pair).await
    };
    tokio::pin!(q);
    tokio::pin!(t);
    tokio::select! {
        r=&mut q=>match r {Ok(s)=>Ok(s),Err(qerr)=>t.await.with_context(||format!("QUIC failed: {qerr}"))},
        r=&mut t=>match r {Ok(s)=>Ok(s),Err(terr)=>q.await.with_context(||format!("TCP fallback failed: {terr}"))},
    }
    // Dropping the losing future closes its session before caller can send any payload.
}
pub fn server_endpoint(addr: SocketAddr, id: &Identity) -> Result<quinn::Endpoint> {
    let tls = id.server_config()?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = tuning();
    Ok(quinn::Endpoint::server(config, addr)?)
}
pub async fn accept_quic(incoming: quinn::Incoming) -> Result<Session> {
    let c = incoming.await?;
    let certs = c
        .peer_identity()
        .context("missing client identity")?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("bad client identity"))?;
    let fp = crate::identity::fingerprint(certs.first().context("missing certificate")?.as_ref());
    let mut binding = [0; 32];
    c.export_keying_material(&mut binding, b"EXPORTER-clipx-session", b"")
        .map_err(|_| anyhow::anyhow!("TLS exporter failed"))?;
    let (w, r) = c.accept_bi().await?;
    Ok(Session {
        ctrl: Wire {
            r: Box::new(r),
            w: Box::new(w),
        },
        conn: Some(c),
        endpoint: None,
        fingerprint: fp,
        transport: "quic",
        peer_device: String::new(),
        peer_name: String::new(),
        pairing_confirmation: false,
        session_nonce: String::new(),
        authorized: false,
        binding,
    })
}
pub async fn accept_tcp(
    socket: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Result<Session> {
    socket.set_nodelay(true)?;
    let tls = tokio_rustls::TlsAcceptor::from(config)
        .accept(socket)
        .await?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .context("missing client certificate")?;
    let fp = crate::identity::fingerprint(cert.as_ref());
    if tls.get_ref().1.alpn_protocol() != Some(protocol::ALPN)
        || tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        bail!("ALPN mismatch");
    }
    let binding =
        tls.get_ref()
            .1
            .export_keying_material([0u8; 32], b"EXPORTER-clipx-session", None)?;
    let (r, w) = tokio::io::split(tls);
    Ok(Session {
        ctrl: Wire {
            r: Box::new(r),
            w: Box::new(w),
        },
        conn: None,
        endpoint: None,
        fingerprint: fp,
        transport: "tcp",
        peer_device: String::new(),
        peer_name: String::new(),
        pairing_confirmation: false,
        session_nonce: String::new(),
        authorized: false,
        binding,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("peer rejected request: {0}")]
pub struct PeerRejected(pub String);
pub fn retryable(e: &anyhow::Error) -> bool {
    if e.downcast_ref::<PeerRejected>().is_some() {
        return false;
    }
    if e.chain().any(|c| {
        matches!(
            c.downcast_ref::<quinn::ConnectionError>(),
            Some(
                quinn::ConnectionError::VersionMismatch | quinn::ConnectionError::TransportError(_)
            )
        )
    }) {
        return false;
    }

    e.chain().any(|c| {
        c.is::<tokio::time::error::Elapsed>()
            || c.is::<quinn::ConnectionError>()
            || c.is::<quinn::ReadError>()
            || c.is::<quinn::WriteError>()
            || c.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    })
}
