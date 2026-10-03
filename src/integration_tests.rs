use crate::{
    identity::Identity,
    protocol::{CHUNK, Kind, Msg},
    transfer::{self, Plan, Receiver},
    transport,
};
use anyhow::Result;
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct Fixture {
    _root: tempfile::TempDir,
    sender: Arc<Identity>,
    receiver: Arc<Identity>,
    options: Arc<Receiver>,
    input: PathBuf,
    port: u16,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let sender = Arc::new(Identity::ephemeral()?);
        let receiver = Arc::new(Identity::ephemeral()?);
        let input = root.path().join("input");
        fs::create_dir(&input)?;
        let dl = root.path().join("downloads");
        fs::create_dir(&dl)?;
        // TCP availability does not imply UDP availability on Windows.
        // Probe both protocols, keeping both sockets alive until a pair succeeds.
        let port = (0..100)
            .find_map(|_| {
                let udp = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
                let port = udp.local_addr().ok()?.port();
                let _tcp = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
                Some(port)
            })
            .ok_or_else(|| anyhow::anyhow!("no available UDP/TCP test port"))?;
        let options = Arc::new(Receiver {
            downloads: dl,
            headless: true,
            clipboard: crate::clipboard::writer(),
            concurrency: 4,
            approval: crate::pairing::Approval::testing(true),
        });
        Ok(Self {
            _root: root,
            sender,
            receiver,
            options,
            input,
            port,
        })
    }
    fn plan(&self) -> Result<Arc<Plan>> {
        Ok(Arc::new(Plan::scan(
            std::slice::from_ref(&self.input),
            Kind::Files,
        )?))
    }
    async fn server(&self, mode: &str) -> Result<tokio::task::JoinHandle<()>> {
        let id = self.receiver.clone();
        let options = self.options.clone();
        let addr = ([127, 0, 0, 1], self.port).into();
        if mode == "quic" {
            let endpoint = transport::server_endpoint(addr, &id)?;
            Ok(tokio::spawn(async move {
                while let Some(i) = endpoint.accept().await {
                    let id = id.clone();
                    let options = options.clone();
                    tokio::spawn(async move {
                        if let Ok(mut s) = transport::accept_quic(i).await
                            && let Err(e) = transfer::receive(&mut s, &id, options).await
                        {
                            let _ = s
                                .ctrl
                                .send(&Msg::Error {
                                    message: e.to_string(),
                                })
                                .await;
                        }
                    });
                }
            }))
        } else {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let tls = Arc::new(id.server_config()?);
            Ok(tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let id = id.clone();
                    let options = options.clone();
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        if let Ok(mut s) = transport::accept_tcp(socket, tls).await
                            && let Err(e) = transfer::receive(&mut s, &id, options).await
                        {
                            let _ = s
                                .ctrl
                                .send(&Msg::Error {
                                    message: e.to_string(),
                                })
                                .await;
                        }
                    });
                }
            }))
        }
    }
    async fn connect(&self, mode: &str) -> Result<transport::Session> {
        let mut s = transport::connect("127.0.0.1", self.port, mode, &self.sender, true).await?;
        crate::pairing::authorize(
            &mut s,
            &self.sender,
            &crate::pairing::Approval::testing(true),
        )
        .await?;
        Ok(s)
    }
}
#[tokio::test]
async fn quic_tree_collision_and_dedup() -> Result<()> {
    run_tree("quic", "quic").await
}
#[tokio::test]
async fn tcp_tree_collision_and_dedup() -> Result<()> {
    run_tree("tcp", "tcp").await
}
#[tokio::test]
async fn automatic_fallback() -> Result<()> {
    run_tree("tcp", "auto").await
}
async fn run_tree(server: &str, client: &str) -> Result<()> {
    let f = Fixture::new()?;
    fs::write(f.input.join("empty"), b"")?;
    fs::create_dir(f.input.join("nested"))?;
    for i in 0..32 {
        fs::write(
            f.input.join("nested").join(format!("你好{i}.txt")),
            format!("hello {i}"),
        )?;
    }
    let big = vec![9; CHUNK * 3 + 133];
    fs::write(f.input.join("large.bin"), &big)?;
    let task = f.server(server).await?;
    let plan = f.plan()?;
    let mut s = f.connect(client).await?;
    assert_eq!(s.transport, server);
    let paths = transfer::send_session(&mut s, plan.clone(), "auto").await?;
    drop(s);
    assert_eq!(fs::read(PathBuf::from(&paths[0]).join("large.bin"))?, big);
    assert_eq!(
        fs::read_dir(PathBuf::from(&paths[0]).join("nested"))?.count(),
        32
    );
    let mut s = f.connect(client).await?;
    let second = transfer::send_session(&mut s, f.plan()?, "off").await?;
    assert!(second[0].ends_with("input (1)"));
    assert!(PathBuf::from(&paths[0]).is_dir());
    task.abort();
    Ok(())
}
#[tokio::test]
async fn interrupted_tcp_resumes_on_quic() -> Result<()> {
    let mut f = Fixture::new()?;
    fs::write(f.input.join("big"), vec![71; CHUNK * 3 + 55])?;
    let plan = f.plan()?;
    let task = f.server("tcp").await?;
    let mut s = f.connect("tcp").await?;
    s.ctrl.send(&Msg::Offer(plan.offer.clone())).await?;
    for e in &plan.entries {
        s.ctrl.send(&Msg::Entry(e.clone())).await?;
    }
    assert!(matches!(s.ctrl.recv().await?, Msg::Accept { .. }));
    s.ctrl.send(&Msg::File { index: 1 }).await?;
    assert!(matches!(
        s.ctrl.recv().await?,
        Msg::Resume { offset: 0, .. }
    ));
    let data = vec![71; CHUNK];
    s.ctrl
        .send(&Msg::Chunk {
            offset: 0,
            logical: CHUNK,
            encoded: CHUNK,
            compressed: false,
            hash: blake3::hash(&data).to_hex().to_string(),
        })
        .await?;
    use tokio::io::AsyncWriteExt;
    s.ctrl.w.write_all(&data).await?;
    s.ctrl.w.flush().await?;
    assert!(matches!(s.ctrl.recv().await?, Msg::Ack));
    drop(s);
    task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stage = f
        .options
        .downloads
        .join(format!(".clipx-part-{}", plan.offer.id));
    assert_eq!(fs::metadata(stage.join("file-1"))?.len(), CHUNK as u64);
    f.sender = Arc::new(Identity::ephemeral()?);
    f.receiver = Arc::new(Identity::ephemeral()?);
    let plan = f.plan()?;
    let task = f.server("quic").await?;
    let mut s = f.connect("quic").await?;
    let progress = Arc::new(transfer::Progress::default());
    let paths = transfer::send_session_progress(&mut s, plan, "zstd", progress.clone()).await?;
    assert_eq!(
        progress.resumed.load(std::sync::atomic::Ordering::Relaxed),
        CHUNK as u64
    );
    assert_eq!(
        fs::read(PathBuf::from(&paths[0]).join("big"))?,
        vec![71; CHUNK * 3 + 55]
    );
    assert!(!stage.exists());
    task.abort();
    Ok(())
}
#[tokio::test]
async fn same_metadata_different_content_restarts_file() -> Result<()> {
    let mut f = Fixture::new()?;
    fs::write(f.input.join("big"), vec![71; CHUNK * 3 + 55])?;
    let plan = f.plan()?;
    let task = f.server("tcp").await?;
    let mut s = f.connect("tcp").await?;
    s.ctrl.send(&Msg::Offer(plan.offer.clone())).await?;
    for e in &plan.entries {
        s.ctrl.send(&Msg::Entry(e.clone())).await?;
    }
    assert!(matches!(s.ctrl.recv().await?, Msg::Accept { .. }));
    s.ctrl.send(&Msg::File { index: 1 }).await?;
    assert!(matches!(
        s.ctrl.recv().await?,
        Msg::Resume { offset: 0, .. }
    ));
    let data = vec![71; CHUNK];
    s.ctrl
        .send(&Msg::Chunk {
            offset: 0,
            logical: CHUNK,
            encoded: CHUNK,
            compressed: false,
            hash: blake3::hash(&data).to_hex().to_string(),
        })
        .await?;
    use tokio::io::AsyncWriteExt;
    s.ctrl.w.write_all(&data).await?;
    s.ctrl.w.flush().await?;
    assert!(matches!(s.ctrl.recv().await?, Msg::Ack));
    drop(s);
    task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stage = f
        .options
        .downloads
        .join(format!(".clipx-part-{}", plan.offer.id));
    assert_eq!(fs::metadata(stage.join("file-1"))?.len(), CHUNK as u64);
    let e = &plan.entries[1];
    fs::write(f.input.join("big"), vec![72; CHUNK * 3 + 55])?;
    filetime::set_file_mtime(
        f.input.join("big"),
        filetime::FileTime::from_unix_time(e.modified, e.modified_ns),
    )?;
    f.sender = Arc::new(Identity::ephemeral()?);
    f.receiver = Arc::new(Identity::ephemeral()?);
    let plan = f.plan()?;
    let task = f.server("quic").await?;
    let mut s = f.connect("quic").await?;
    let progress = Arc::new(transfer::Progress::default());
    let paths = transfer::send_session_progress(&mut s, plan, "zstd", progress.clone()).await?;
    assert_eq!(
        progress.resumed.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        fs::read(PathBuf::from(&paths[0]).join("big"))?,
        vec![72; CHUNK * 3 + 55]
    );
    assert!(!stage.exists());
    task.abort();
    Ok(())
}
#[tokio::test]
async fn payload_without_confirmation_is_rejected() -> Result<()> {
    let f = Fixture::new()?;
    let task = f.server("tcp").await?;
    let mut s = transport::connect("127.0.0.1", f.port, "tcp", &f.sender, true).await?;
    s.ctrl
        .send(&Msg::Offer(crate::protocol::Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: 0,
        }))
        .await?;
    assert!(s.ctrl.recv().await.is_err());
    assert_eq!(fs::read_dir(&f.options.downloads)?.count(), 0);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn declined_session_does_not_write_state() -> Result<()> {
    let f = Fixture::new()?;
    let task = f.server("tcp").await?;
    let mut s = transport::connect("127.0.0.1", f.port, "tcp", &f.sender, true).await?;
    assert!(
        crate::pairing::authorize(&mut s, &f.sender, &crate::pairing::Approval::testing(false))
            .await
            .is_err()
    );
    assert_eq!(fs::read_dir(&f.options.downloads)?.count(), 0);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn headless_text_and_image_bytes() -> Result<()> {
    for kind in [Kind::Text, Kind::Image] {
        let f = Fixture::new()?;
        let name = if kind == Kind::Text {
            "clipboard.txt"
        } else {
            "clipboard.png"
        };
        let p = f.input.join(name);
        let bytes = if kind == Kind::Text {
            b"hello UTF-8 \xe4\xbd\xa0\xe5\xa5\xbd".to_vec()
        } else {
            vec![137, 80, 78, 71, 13, 10, 26, 10]
        };
        fs::write(&p, &bytes)?;
        let plan = Arc::new(Plan::scan(&[p], kind)?);
        let task = f.server("tcp").await?;
        let mut s = f.connect("tcp").await?;
        let result = transfer::send_session(&mut s, plan, "auto").await?;
        assert_eq!(fs::read(&result[0])?, bytes);
        task.abort();
    }
    Ok(())
}
#[tokio::test]
async fn malicious_path_rejected() -> Result<()> {
    let f = Fixture::new()?;
    let task = f.server("tcp").await?;
    let mut s = f.connect("tcp").await?;
    s.ctrl
        .send(&Msg::Offer(crate::protocol::Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: 0,
        }))
        .await?;
    s.ctrl
        .send(&Msg::Entry(crate::protocol::Entry {
            path: "../../escaped".into(),
            size: 0,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }))
        .await?;
    assert!(s.ctrl.recv().await.is_err());
    assert!(!f._root.path().join("escaped").exists());
    task.abort();
    Ok(())
}

#[tokio::test]
async fn incomplete_clipboard_never_commits() -> Result<()> {
    let f = Fixture::new()?;
    let task = f.server("tcp").await?;
    let mut s = f.connect("tcp").await?;
    s.ctrl
        .send(&Msg::Offer(crate::protocol::Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Text,
            count: 1,
            total: 4,
        }))
        .await?;
    s.ctrl
        .send(&Msg::Entry(crate::protocol::Entry {
            path: "clipboard.txt".into(),
            size: 4,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }))
        .await?;
    assert!(matches!(s.ctrl.recv().await?, Msg::Accept { .. }));
    s.ctrl.send(&Msg::WorkerDone).await?;
    s.ctrl.send(&Msg::Finish).await?;
    assert!(s.ctrl.recv().await.is_err());
    assert!(!f.options.downloads.join("clipboard.txt").exists());
    task.abort();
    Ok(())
}
#[tokio::test]
async fn corrupted_chunk_never_commits() -> Result<()> {
    let f = Fixture::new()?;
    let task = f.server("tcp").await?;
    let mut s = f.connect("tcp").await?;
    s.ctrl
        .send(&Msg::Offer(crate::protocol::Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: 4,
        }))
        .await?;
    s.ctrl
        .send(&Msg::Entry(crate::protocol::Entry {
            path: "bad".into(),
            size: 4,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }))
        .await?;
    assert!(matches!(s.ctrl.recv().await?, Msg::Accept { .. }));
    s.ctrl.send(&Msg::File { index: 0 }).await?;
    assert!(matches!(s.ctrl.recv().await?, Msg::Resume { .. }));
    s.ctrl
        .send(&Msg::Chunk {
            offset: 0,
            logical: 4,
            encoded: 4,
            compressed: false,
            hash: "0".repeat(64),
        })
        .await?;
    use tokio::io::AsyncWriteExt;
    s.ctrl.w.write_all(b"oops").await?;
    s.ctrl.w.flush().await?;
    assert!(s.ctrl.recv().await.is_err());
    assert!(!f.options.downloads.join("bad").exists());
    task.abort();
    Ok(())
}
#[tokio::test]
async fn concurrent_atomic_collision() -> Result<()> {
    let f = Arc::new(Fixture::new()?);
    fs::write(f.input.join("item"), b"concurrent")?;
    let task = f.server("quic").await?;
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let f = f.clone();
        jobs.spawn(async move {
            let mut s = f.connect("quic").await?;
            transfer::send_session(&mut s, f.plan()?, "auto").await
        });
    }
    let mut paths = std::collections::HashSet::new();
    while let Some(result) = jobs.join_next().await {
        for p in result?? {
            assert_eq!(fs::read(PathBuf::from(&p).join("item"))?, b"concurrent");
            assert!(paths.insert(p));
        }
    }
    assert_eq!(paths.len(), 4);
    task.abort();
    Ok(())
}

#[tokio::test]
async fn explicit_pair_probe_both_transports() -> Result<()> {
    for mode in ["quic", "tcp"] {
        let f = Fixture::new()?;
        let task = f.server(mode).await?;
        let s = transport::connect("127.0.0.1", f.port, mode, &f.sender, true).await?;
        assert_eq!(s.fingerprint, f.receiver.fp());
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn ram_pins_allow_reconnect_but_not_new_identity() -> Result<()> {
    let mut f = Fixture::new()?;
    let approval = crate::pairing::Approval::new(false);
    approval.remember(&f.receiver.fp());
    let incoming = crate::pairing::Approval::new(false);
    incoming.remember(&f.sender.fp());
    f.options = Arc::new(Receiver {
        downloads: f.options.downloads.clone(),
        headless: true,
        clipboard: crate::clipboard::writer(),
        concurrency: 4,
        approval: incoming,
    });
    let task = f.server("tcp").await?;
    for _ in 0..2 {
        let mut s = transport::connect("127.0.0.1", f.port, "tcp", &f.sender, true).await?;
        crate::pairing::authorize(&mut s, &f.sender, &approval).await?;
        assert!(s.authorized);
    }
    let stranger = Identity::ephemeral()?;
    let mut s = transport::connect("127.0.0.1", f.port, "tcp", &stranger, true).await?;
    assert!(
        crate::pairing::authorize(&mut s, &stranger, &approval)
            .await
            .is_err()
    );
    task.abort();
    Ok(())
}
