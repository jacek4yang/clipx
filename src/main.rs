use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use clipx::{
    identity::Identity,
    pairing, paths,
    protocol::Kind,
    transfer::{Plan, Receiver},
    transport,
};
use std::{io::Read, path::PathBuf, sync::Arc, time::Duration};
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
    about = "Single-binary, one-time-confirmed clipboard and file transfer. No identity/config files."
)]
struct Cli {
    #[arg(long, global = true)]
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
    /// Receive; compare the one-time fingerprint and enter y for each session.
    Recv {
        /// Automatically accept incoming sessions during this run. Use only on trusted networks.
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(long)]
        headless: bool,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=4))]
        concurrency: u8,
    },
    /// Send copied files, image or text; no saved trust and no sender cache.
    Send {
        /// Skip local fingerprint confirmation for this run; the receiver decides independently.
        #[arg(long)]
        yes: bool,
        host: String,
        #[arg(long,num_args=1,action=clap::ArgAction::Append,conflicts_with_all=["text","stdin"])]
        path: Vec<PathBuf>,
        #[arg(long, conflicts_with = "stdin")]
        text: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long, value_enum, default_value = "auto")]
        compression: Compression,
        #[arg(long,default_value_t=3,value_parser=clap::value_parser!(u8).range(0..=12))]
        retries: u8,
    },
    /// Remove inactive Downloads checkpoints older than the retention period.
    Cleanup {
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    /// Display embedded third-party license notices without creating files.
    Licenses,
}
fn emit(cli: &Cli, event: &str, value: serde_json::Value) {
    if cli.json {
        println!("{}", serde_json::json!({"event":event,"data":value}));
    } else if !cli.quiet {
        match event {
            "connected" => println!(
                "Connected via {}",
                value["transport"].as_str().unwrap_or("")
            ),
            "verified" => {
                println!("Verified.");
                if let Some(a) = value["paths"].as_array() {
                    for p in a {
                        println!("  -> {}", p.as_str().unwrap_or(""));
                    }
                }
            }
            "progress" => println!("{}/{} bytes", value["verified_bytes"], value["total_bytes"]),
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
        let runtime = zstd::bulk::decompress(
            include_bytes!("../docs/licenses/rust-library.html.zst"),
            2 * 1024 * 1024,
        )?;
        let text = format!(
            "{}\n{}\n{}",
            include_str!("../THIRD_PARTY_NOTICES.md"),
            include_str!("../docs/licenses/musl.txt"),
            String::from_utf8(runtime)?
        );
        if cli.json {
            emit(&cli, "licenses", serde_json::json!(text));
        } else {
            print!("{text}");
        }
        return Ok(());
    }
    match &cli.command {
        Command::Licenses => {}
        Command::Cleanup { days } => {
            let downloads = cli
                .downloads
                .clone()
                .map(Ok)
                .unwrap_or_else(paths::downloads)?;
            emit(
                &cli,
                "cleaned",
                serde_json::json!(clipx::transfer::cleanup(&downloads, *days)?),
            );
        }
        Command::Send {
            yes,
            host,
            path,
            text,
            stdin,
            compression,
            retries,
        } => {
            let id = Identity::ephemeral()?;
            let content = if !path.is_empty() {
                clipx::clipboard::Content::Paths(path.clone())
            } else if let Some(text) = text {
                clipx::clipboard::Content::Bytes(Kind::Text, text.as_bytes().to_vec())
            } else if *stdin {
                let mut data = Vec::new();
                std::io::stdin().read_to_end(&mut data)?;
                std::str::from_utf8(&data)?;
                clipx::clipboard::Content::Bytes(Kind::Text, data)
            } else {
                clipx::clipboard::read()?
            };
            let plan = Arc::new(match content {
                clipx::clipboard::Content::Paths(p) => {
                    tokio::task::spawn_blocking(move || Plan::scan(&p, Kind::Files)).await??
                }
                clipx::clipboard::Content::Bytes(kind, data) => Plan::clipboard(kind, data)?,
            });
            let approval = if *yes {
                pairing::Approval::automatic()
            } else if *stdin {
                pairing::Approval::terminal()
            } else {
                pairing::Approval::new(true)
            };
            let progress = Arc::new(clipx::transfer::Progress::default());
            emit(
                &cli,
                "transfer",
                serde_json::json!({"entries":plan.entries.len(),"bytes":plan.offer.total}),
            );
            let task = async {
                let mut last = anyhow::anyhow!("not connected");
                for attempt in 0..=*retries {
                    if attempt > 0 {
                        let delay = (1u64 << attempt.min(5))
                            + u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 3;
                        emit(
                            &cli,
                            "reconnecting",
                            serde_json::json!({"attempt":attempt,"delay_seconds":delay,"confirmation":"compare the new session fingerprint again"}),
                        );
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                    progress
                        .verified
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    progress
                        .resumed
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    let mode = if attempt > 0 && cli.transport.name() == "auto" {
                        "tcp"
                    } else {
                        cli.transport.name()
                    };
                    let result = async {
                        let mut s = transport::connect(host, cli.port, mode, &id, true).await?;
                        pairing::authorize(&mut s, &id, &approval).await?;
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
                        Ok(p) => return Ok(p),
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
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            let result = loop {
                tokio::select! {r=&mut task=>break r,_=tokio::signal::ctrl_c()=>break Err(anyhow::anyhow!("cancelled")),_=tick.tick()=>{let n=progress.verified.load(std::sync::atomic::Ordering::Relaxed);if n>0{emit(&cli,"progress",serde_json::json!({"verified_bytes":n,"total_bytes":plan.offer.total}));}}}
            };
            match result {
                Ok(paths) => emit(
                    &cli,
                    "verified",
                    serde_json::json!({"paths":paths,"resumed_bytes":progress.resumed.load(std::sync::atomic::Ordering::Relaxed),"total_bytes":plan.offer.total}),
                ),
                Err(e) => bail!(
                    "{e:#}. No sender state saved. Repeat the same command to resume matching Downloads checkpoints after a fresh confirmation."
                ),
            }
        }
        Command::Recv {
            yes,
            bind,
            headless,
            concurrency,
        } => {
            let id = Arc::new(Identity::ephemeral()?);
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
                clipboard: clipx::clipboard::writer(),
                concurrency: *concurrency as usize,
                approval: if *yes {
                    pairing::Approval::automatic()
                } else {
                    pairing::Approval::new(true)
                },
            });
            let address = std::net::SocketAddr::new(bind.parse()?, cli.port);
            let tcp = if cli.transport.name() != "quic" {
                Some(tokio::net::TcpListener::bind(address).await?)
            } else {
                None
            };
            let quic = if cli.transport.name() != "tcp" {
                Some(transport::server_endpoint(address, &id)?)
            } else {
                None
            };
            let tls = Arc::new(id.server_config()?);
            emit(
                &cli,
                "listening",
                serde_json::json!({"address":address.to_string(),"downloads":options.downloads,"approval": if *yes {"automatic for this process (--yes); peer identity not manually verified"} else {"compare session fingerprint and type y"}}),
            );
            let permits = Arc::new(tokio::sync::Semaphore::new(8));
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=tokio::signal::ctrl_c()=>break,
                    _=options.approval.interrupted()=>break,
                    Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},
                    socket=async{match &tcp{Some(t)=>t.accept().await,None=>std::future::pending().await}}=>{let(socket,_)=socket?;let Ok(permit)=permits.clone().try_acquire_owned()else{continue;};let tls=tls.clone();let id=id.clone();let options=options.clone();jobs.spawn(async move{let _permit=permit;serve(tokio::time::timeout(Duration::from_secs(10),transport::accept_tcp(socket,tls)).await,id,options).await;});},
                    incoming=async{match &quic{Some(q)=>q.accept().await,None=>std::future::pending().await}}=>{let Some(incoming)=incoming else{break;};let Ok(permit)=permits.clone().try_acquire_owned()else{incoming.refuse();continue;};let id=id.clone();let options=options.clone();jobs.spawn(async move{let _permit=permit;serve(tokio::time::timeout(Duration::from_secs(10),transport::accept_quic(incoming)).await,id,options).await;});},
                }
            }
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
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
                    .send(&clipx::protocol::Msg::Error {
                        message: e.to_string(),
                    })
                    .await;
                eprintln!("connection ended: {e:#}");
            }
        }
        Ok(Err(e)) => eprintln!("connection failed: {e}"),
        Err(_) => eprintln!("handshake timeout"),
    }
}
