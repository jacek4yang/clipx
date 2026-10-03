use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use clipx::{
    identity::{self, Identity, Trust},
    paths,
    protocol::{Kind, Msg},
    transfer::{Plan, Receiver},
    transport,
};
use std::{
    io::{IsTerminal, Read, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
#[derive(Clone, Debug, ValueEnum)]
enum Transport {
    Auto,
    Quic,
    Tcp,
}
impl Transport {
    fn name(&self) -> &str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
    }
}
#[derive(Clone, Debug, ValueEnum)]
enum Compression {
    Auto,
    Zstd,
    Off,
}
impl Compression {
    fn name(&self) -> &str {
        match self {
            Self::Auto => "auto",
            Self::Zstd => "zstd",
            Self::Off => "off",
        }
    }
}
#[derive(Parser)]
#[command(
    version,
    about = "Explicit encrypted clipboard and file transfer over your tailnet"
)]
struct Cli {
    #[arg(long, global = true, env = "CLIPX_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
    #[arg(long, global = true, env = "CLIPX_DOWNLOADS")]
    downloads: Option<PathBuf>,
    #[arg(long, global = true, default_value_t = 45817)]
    port: u16,
    #[arg(long, global = true, value_enum, default_value = "auto")]
    transport: Transport,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Receive from explicitly trusted devices. Bind to a tailnet IP to limit exposure.
    Recv {
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(long)]
        headless: bool,
        #[arg(long)]
        pairing: bool,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=4))]
        concurrency: u8,
    },
    Send {
        host: String,
        #[arg(long,num_args=1,action=clap::ArgAction::Append,conflicts_with_all=["text","stdin","resume"])]
        path: Vec<PathBuf>,
        #[arg(long,conflicts_with_all=["stdin","resume"])]
        text: Option<String>,
        #[arg(long, conflicts_with = "resume")]
        stdin: bool,
        #[arg(long)]
        resume: Option<uuid::Uuid>,
        #[arg(long, value_enum, default_value = "auto")]
        compression: Compression,
        #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u8).range(0..=12))]
        retries: u8,
    },
    /// Discover and explicitly pin receiver identity; receiver must trust your fingerprint too.
    Pair {
        host: String,
        #[arg(long)]
        fingerprint: Option<String>,
    },
    Fingerprint,
    /// Display embedded third-party license notices (no external file needed).
    Licenses,
    Peer {
        #[command(subcommand)]
        action: Peer,
    },
    Cleanup {
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    Doctor,
}
#[derive(Subcommand)]
enum Peer {
    Add {
        name: String,
        host: String,
    },
    Remove {
        name: String,
    },
    List,
    Trust {
        fingerprint: String,
        #[arg(long)]
        host: Option<String>,
    },
    Forget {
        fingerprint: String,
    },
}
fn emit(cli: &Cli, event: &str, value: serde_json::Value) {
    if cli.json {
        println!("{}", serde_json::json!({"event":event,"data":value}));
    } else if !cli.quiet {
        match event {
            "fingerprint" => println!(
                "Device: {}\nFingerprint (BLAKE3): {}",
                value["name"].as_str().unwrap_or(""),
                value["blake3_cert"].as_str().unwrap_or("")
            ),
            "transfer" => println!(
                "Transfer {}: {} entries, {} bytes",
                value["id"].as_str().unwrap_or(""),
                value["entries"],
                value["bytes"]
            ),
            "connected" => println!(
                "Connected via {}",
                if value["transport"] == "quic" {
                    "QUIC / TLS 1.3"
                } else {
                    "TCP / TLS 1.3"
                }
            ),
            "progress" => {
                let done = value["verified_bytes"].as_u64().unwrap_or(0);
                let total = value["total_bytes"].as_u64().unwrap_or(0);
                let percent = if total == 0 {
                    100.0
                } else {
                    100.0 * done as f64 / total as f64
                };
                println!(
                    "{percent:5.1}%  {done}/{total} bytes  {:.1} MiB/s",
                    value["bytes_per_second"].as_f64().unwrap_or(0.0) / 1048576.0
                );
            }
            "verified" => {
                println!("Verified.");
                if let Some(paths) = value["paths"].as_array() {
                    for p in paths {
                        println!("  -> {}", p.as_str().unwrap_or(""));
                    }
                }
            }
            _ => println!("{event}: {value}"),
        }
    }
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("clipx: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Licenses) {
        print!("{}", include_str!("../THIRD_PARTY_NOTICES.md"));
        return Ok(());
    }
    let config = identity::config_dir(cli.config_dir.clone())?;
    let id = Arc::new(Identity::load(&config)?);
    match &cli.command {
        Command::Licenses => {}
        Command::Fingerprint => emit(
            &cli,
            "fingerprint",
            serde_json::json!({"device":id.id,"name":id.name,"blake3_cert":id.fp()}),
        ),
        Command::Peer { action } => match action {
            Peer::List => emit(&cli, "peers", serde_json::to_value(Trust::load(&config)?)?),
            Peer::Add { name, host } => Trust::edit(&config, |t| {
                t.aliases.insert(name.clone(), host.clone());
                Ok(())
            })?,
            Peer::Remove { name } => Trust::edit(&config, |t| {
                t.aliases.remove(name);
                Ok(())
            })?,
            Peer::Trust { fingerprint, host } => {
                let fp = identity::valid_fingerprint(fingerprint)?;
                Trust::edit(&config, |t| {
                    if let Some(host) = host {
                        if let Some(old) = t.hosts.get(host)
                            && old != &fp
                        {
                            bail!(
                                "known fingerprint changed; explicitly forget old fingerprint first"
                            );
                        }
                        t.hosts.insert(host.clone(), fp.clone());
                    }
                    t.fingerprints.insert(fp);
                    Ok(())
                })?;
            }
            Peer::Forget { fingerprint } => {
                let fp = identity::valid_fingerprint(fingerprint)?;
                Trust::edit(&config, |t| {
                    t.fingerprints.remove(&fp);
                    t.hosts.retain(|_, v| v != &fp);
                    Ok(())
                })?;
            }
        },
        Command::Pair { host, fingerprint } => {
            let trust = Trust::load(&config)?;
            let host = trust.aliases.get(host).unwrap_or(host);
            let explicit = fingerprint
                .as_deref()
                .map(identity::valid_fingerprint)
                .transpose()?;
            let expected = trust.hosts.get(host).cloned().or(explicit.clone());
            let s = transport::connect(host, cli.port, cli.transport.name(), &id, expected, true)
                .await?;
            emit(
                &cli,
                "peer fingerprint",
                serde_json::json!({"host":host,"fingerprint":s.fingerprint,"your_fingerprint":id.fp()}),
            );
            if let Some(fp) = explicit {
                if fp != s.fingerprint {
                    bail!("fingerprint mismatch");
                }
            } else if trust.hosts.get(host) != Some(&s.fingerprint) {
                if !std::io::stdin().is_terminal() {
                    bail!(
                        "noninteractive pairing requires --fingerprint, independently verified on receiver"
                    );
                }
                eprint!("Verify the fingerprint on the receiver. Trust this device? [yes/no] ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim() != "yes" {
                    bail!("pairing cancelled");
                }
            }
            Trust::edit(&config, |t| {
                t.hosts.insert(host.clone(), s.fingerprint.clone());
                t.fingerprints.insert(s.fingerprint.clone());
                Ok(())
            })?;
            emit(
                &cli,
                "paired",
                serde_json::json!(
                    "Receiver must separately trust your fingerprint; restart recv after trust changes."
                ),
            );
        }
        Command::Send {
            host,
            path,
            text,
            stdin,
            resume,
            compression,
            retries,
        } => {
            let trust = Trust::load(&config)?;
            let host = trust.aliases.get(host).unwrap_or(host).clone();
            let expected = trust
                .hosts
                .get(&host)
                .cloned()
                .context("unknown peer: run clipx pair HOST first")?;
            let outgoing = config.join("outgoing");
            paths::private_dir(&outgoing)?;
            let plan = if let Some(resume) = resume {
                serde_json::from_reader(std::fs::File::open(
                    outgoing.join(format!("{resume}.json")),
                )?)?
            } else {
                let content = if !path.is_empty() {
                    clipx::clipboard::Content::Paths(path.clone())
                } else if let Some(text) = text {
                    clipx::clipboard::Content::Bytes(Kind::Text, text.as_bytes().to_vec())
                } else if *stdin {
                    let mut data = Vec::new();
                    std::io::stdin().read_to_end(&mut data)?;
                    std::str::from_utf8(&data).context("stdin text must be UTF-8")?;
                    clipx::clipboard::Content::Bytes(Kind::Text, data)
                } else {
                    clipx::clipboard::read()?
                };
                match content {
                    clipx::clipboard::Content::Paths(p) => {
                        tokio::task::spawn_blocking(move || Plan::scan(&p, Kind::Files)).await??
                    }
                    clipx::clipboard::Content::Bytes(kind, data) => {
                        let spool = outgoing.join(uuid::Uuid::new_v4().to_string());
                        paths::private_dir(&spool)?;
                        let p = spool.join(if kind == Kind::Text {
                            "clipboard.txt"
                        } else {
                            "clipboard.png"
                        });
                        std::fs::write(&p, data)?;
                        Plan::scan(&[p], kind)?
                    }
                }
            };
            let plan: Arc<Plan> = Arc::new(plan);
            let planfile = outgoing.join(format!("{}.json", plan.offer.id));
            let outgoing_lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(outgoing.join(format!("{}.lock", plan.offer.id)))?;
            fs2::FileExt::try_lock_exclusive(&outgoing_lock)
                .context("this outgoing transfer is already running")?;
            paths::atomic_json(&planfile, &*plan)?;
            emit(
                &cli,
                "transfer",
                serde_json::json!({"id":plan.offer.id,"entries":plan.entries.len(),"bytes":plan.offer.total}),
            );
            let progress = Arc::new(clipx::transfer::Progress::default());
            let task = async {
                let mut last = anyhow::anyhow!("transfer not attempted");
                for attempt in 0..=*retries {
                    if attempt > 0 {
                        let delay = (1u64 << attempt.min(5))
                            + u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 3;
                        emit(
                            &cli,
                            "reconnecting",
                            serde_json::json!({"attempt":attempt,"delay_seconds":delay}),
                        );
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                    let mode = if attempt > 0 && cli.transport.name() == "auto" {
                        "tcp"
                    } else {
                        cli.transport.name()
                    };
                    progress
                        .verified
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    progress
                        .resumed
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    let result = async {
                        let mut s = transport::connect(
                            &host,
                            cli.port,
                            mode,
                            &id,
                            Some(expected.clone()),
                            false,
                        )
                        .await?;
                        emit(
                            &cli,
                            "connected",
                            serde_json::json!({"transport":s.transport}),
                        );
                        clipx::transfer::send_session_progress(
                            &mut s,
                            plan.clone(),
                            compression.name(),
                            progress.clone(),
                        )
                        .await
                    }
                    .await;
                    match result {
                        Ok(paths) => return Ok(paths),
                        Err(e) => {
                            if cli.verbose {
                                eprintln!("attempt failed: {e:#}");
                            }
                            if !transport::retryable(&e) {
                                return Err(e);
                            }
                            last = e;
                        }
                    }
                }
                Err(last)
            };
            tokio::pin!(task);
            let started = std::time::Instant::now();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            let result = loop {
                tokio::select! {
                    r=&mut task=>break r,
                    _=tokio::signal::ctrl_c()=>break Err(anyhow::anyhow!("cancelled")),
                    _=tick.tick()=>{let verified=progress.verified.load(std::sync::atomic::Ordering::Relaxed);let resumed=progress.resumed.load(std::sync::atomic::Ordering::Relaxed);emit(&cli,"progress",serde_json::json!({"verified_bytes":verified,"resumed_bytes":resumed,"total_bytes":plan.offer.total,"elapsed_seconds":started.elapsed().as_secs(),"bytes_per_second":verified.saturating_sub(resumed) as f64/started.elapsed().as_secs_f64().max(0.001)}));}
                }
            };
            match result {
                Ok(paths) => {
                    std::fs::remove_file(planfile)?;
                    if plan.offer.kind != Kind::Files
                        && let Some(parent) = plan.sources[0].parent()
                    {
                        std::fs::remove_dir_all(parent)?;
                    }
                    emit(
                        &cli,
                        "verified",
                        serde_json::json!({"paths":paths,"id":plan.offer.id,"resumed_bytes":progress.resumed.load(std::sync::atomic::Ordering::Relaxed),"total_bytes":plan.offer.total}),
                    );
                }
                Err(e) => bail!(
                    "{e:#}. Partial data retained. Resume: clipx send {host} --resume {}",
                    plan.offer.id
                ),
            }
        }
        Command::Recv {
            bind,
            headless,
            pairing,
            concurrency,
        } => {
            let downloads = cli
                .downloads
                .clone()
                .map(Ok)
                .unwrap_or_else(paths::downloads)?;
            std::fs::create_dir_all(&downloads)?;
            let downloads = std::fs::canonicalize(downloads)?;
            let options = Arc::new(Receiver {
                downloads,
                headless: *headless,
                pairing: *pairing,
                config: config.clone(),
                clipboard: clipx::clipboard::writer(),
                concurrency: *concurrency as usize,
            });
            let address = std::net::SocketAddr::new(bind.parse()?, cli.port);
            let trust = Trust::load(&config)?;
            let tcp = if cli.transport.name() != "quic" {
                Some(tokio::net::TcpListener::bind(address).await?)
            } else {
                None
            };
            let quic = if cli.transport.name() != "tcp" {
                Some(transport::server_endpoint(address, &id, &trust, *pairing)?)
            } else {
                None
            };
            let tls = Arc::new(id.server_config(trust.fingerprints, *pairing)?);
            emit(
                &cli,
                "listening",
                serde_json::json!({"address":address.to_string(),"transport":cli.transport.name(),"fingerprint":id.fp(),"downloads":options.downloads,"pairing":pairing}),
            );
            let permits = Arc::new(tokio::sync::Semaphore::new(8));
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=tokio::signal::ctrl_c()=>break,
                    Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},
                    socket=async{match &tcp{Some(t)=>t.accept().await,None=>std::future::pending().await}}=>{
                        let (socket,_)=socket?;let Ok(permit)=permits.clone().try_acquire_owned()else{continue;};let tls=tls.clone();let id=id.clone();let options=options.clone();
                        jobs.spawn(async move{let _permit=permit;let result=tokio::time::timeout(Duration::from_secs(10),transport::accept_tcp(socket,tls)).await;serve(result,id,options).await;});
                    },
                    incoming=async{match &quic{Some(q)=>q.accept().await,None=>std::future::pending().await}}=>{
                        let Some(incoming)=incoming else{break;};let Ok(permit)=permits.clone().try_acquire_owned()else{incoming.refuse();continue;};let id=id.clone();let options=options.clone();
                        jobs.spawn(async move{let _permit=permit;let result=tokio::time::timeout(Duration::from_secs(10),transport::accept_quic(incoming)).await;serve(result,id,options).await;});
                    }
                }
            }
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        }
        Command::Cleanup { days } => {
            let downloads = cli
                .downloads
                .clone()
                .map(Ok)
                .unwrap_or_else(paths::downloads)?;
            emit(
                &cli,
                "cleaned",
                serde_json::json!({"incoming":clipx::transfer::cleanup(&downloads,*days)?,"outgoing":clipx::transfer::cleanup_outgoing(&config,*days)?}),
            );
        }
        Command::Doctor => {
            let downloads = cli
                .downloads
                .clone()
                .map(Ok)
                .unwrap_or_else(paths::downloads)?;
            let clipboard = clipboard_rs::ClipboardContext::new().is_ok();
            emit(
                &cli,
                "doctor",
                serde_json::json!({"config":config,"downloads":downloads,"clipboard_available":clipboard,"display":std::env::var("DISPLAY").ok(),"wayland":std::env::var("WAYLAND_DISPLAY").ok(),"fingerprint":id.fp(),"tls":"1.3","transports":["quic","tcp"],"tcp_port_available":std::net::TcpListener::bind(("0.0.0.0",cli.port)).is_ok(),"udp_port_available":std::net::UdpSocket::bind(("0.0.0.0",cli.port)).is_ok()}),
            );
        }
    }
    Ok(())
}
async fn serve(
    result: std::result::Result<Result<transport::Session>, tokio::time::error::Elapsed>,
    id: Arc<Identity>,
    options: Arc<Receiver>,
) {
    match result {
        Ok(Ok(mut s)) => {
            if let Err(e) = clipx::transfer::receive(&mut s, &id, options).await {
                let _ = s
                    .ctrl
                    .send(&Msg::Error {
                        message: e.to_string(),
                    })
                    .await;
                eprintln!("connection ended: {e:#}");
            }
        }
        Ok(Err(e)) => eprintln!("authentication/connection failed: {e}"),
        Err(_) => eprintln!("handshake timeout"),
    }
}
