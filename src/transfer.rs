use crate::{
    identity::Identity,
    paths,
    protocol::{self, CHUNK, Entry, Kind, Msg, Offer},
    transport::{Session, Wire},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
pub struct Progress {
    pub verified: AtomicU64,
    pub resumed: AtomicU64,
}
#[derive(Clone)]
pub enum Source {
    File(PathBuf),
    Memory(Arc<[u8]>),
}
#[derive(Clone)]
pub struct Plan {
    pub offer: Offer,
    pub entries: Vec<Entry>,
    pub sources: Vec<Source>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Stored {
    format: String,
    offer: Offer,
    entries: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    format: String,
    manifest: String,
    paths: Vec<String>,
}
fn stamp(m: &fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn stamp_ns(m: &fs::Metadata) -> u32 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
}
fn open_regular(path: &Path, write: bool) -> Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let f = o.open(path)?;
    if !f.metadata()?.is_file() || fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("not a regular file: {}", path.display());
    }
    Ok(f)
}
impl Plan {
    pub fn clipboard(kind: Kind, data: Vec<u8>) -> Result<Self> {
        let path = match kind {
            Kind::Text => "clipboard.txt",
            Kind::Image => "clipboard.png",
            Kind::Files => bail!("expected clipboard payload"),
        };
        let size = data.len() as u64;
        let entries = vec![Entry {
            path: path.into(),
            size,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }];
        Ok(Self {
            offer: Offer {
                id: uuid::Uuid::new_v4(),
                kind,
                count: 1,
                total: size,
            },
            entries,
            sources: vec![Source::Memory(Arc::from(data))],
        })
    }

    pub fn scan(inputs: &[PathBuf], kind: Kind) -> Result<Self> {
        let mut entries = Vec::new();
        let mut sources = Vec::new();
        let mut used = HashSet::new();
        let mut total = 0u64;
        let mut metadata = 0usize;
        for input in inputs {
            let input = std::path::absolute(input)?;
            let mut mapping = HashMap::<PathBuf, String>::new();
            for item in walkdir::WalkDir::new(&input)
                .follow_links(false)
                .max_open(protocol::MAX_DEPTH + 1)
                .max_depth(protocol::MAX_DEPTH + 1)
            {
                let item = item?;
                let p = item.path();
                let m = fs::symlink_metadata(p)?;
                if !m.is_file() && !m.is_dir() {
                    bail!("symlink/special file refused: {}", p.display());
                }
                if item.depth() > protocol::MAX_DEPTH {
                    bail!("directory depth limit");
                }
                let name = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("filename is not Unicode")?;
                let base = paths::component(name)?;
                let parent = if p == input {
                    String::new()
                } else {
                    mapping
                        .get(p.parent().context("missing parent")?)
                        .context("missing mapped parent")?
                        .clone()
                        + "/"
                };
                let mut n = 0;
                let portable = loop {
                    let c = format!("{}{}", parent, paths::collision(&base, n, m.is_dir()));
                    if used.insert(c.to_lowercase()) {
                        break c;
                    }
                    n += 1;
                };
                metadata += portable.len() + 64;
                if entries.len() >= protocol::MAX_ENTRIES || metadata > protocol::MAX_METADATA {
                    bail!("manifest resource limit");
                }
                let size = if m.is_file() { m.len() } else { 0 };
                total = total.checked_add(size).context("total size overflow")?;
                mapping.insert(p.to_path_buf(), portable.clone());
                entries.push(Entry {
                    path: portable,
                    size,
                    directory: m.is_dir(),
                    modified: stamp(&m),
                    modified_ns: stamp_ns(&m),
                });
                sources.push(Source::File(p.to_path_buf()));
            }
        }
        if entries.is_empty() {
            bail!("nothing to send");
        }
        let mut paired: Vec<_> = entries.into_iter().zip(sources).collect();
        paired.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        let (entries, sources): (Vec<_>, Vec<_>) = paired.into_iter().unzip();
        paths::validate_manifest(&entries)?;
        Ok(Self {
            offer: Offer {
                id: uuid::Uuid::new_v4(),
                kind,
                count: entries.len(),
                total,
            },
            entries,
            sources,
        })
    }
}
fn manifest_hash(offer: &Offer, entries: &[Entry]) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(&(offer, entries))?)
        .to_hex()
        .to_string())
}
fn file_path(stage: &Path, index: usize) -> PathBuf {
    stage.join(format!("file-{index}"))
}
fn journal_path(stage: &Path, index: usize) -> PathBuf {
    stage.join(format!("journal-{index}"))
}
struct ActiveFile {
    file: File,
    journal: File,
    hasher: blake3::Hasher,
    offset: u64,
    size: u64,
    _guard: Option<Arc<File>>,
}
impl ActiveFile {
    #[cfg(test)]
    fn open(stage: &Path, index: usize, size: u64) -> Result<Self> {
        Self::open_cancel(stage, index, size, &AtomicBool::new(false))
    }
    fn open_cancel(stage: &Path, index: usize, size: u64, cancel: &AtomicBool) -> Result<Self> {
        let path = file_path(stage, index);
        if !path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
        }
        let mut file = open_regular(&path, true)?;
        let jp = journal_path(stage, index);
        if !jp.exists() {
            OpenOptions::new().create_new(true).write(true).open(&jp)?;
        }
        let mut journal = open_regular(&jp, true)?;
        let mut hasher = blake3::Hasher::new();
        let mut offset = 0u64;
        let mut records = 0u64;
        let mut data = vec![0; CHUNK];
        let mut hash = [0; 32];
        while offset < size && journal.read_exact(&mut hash).is_ok() {
            if cancel.load(Ordering::Relaxed) {
                bail!("verification cancelled");
            }
            let n = (size - offset).min(CHUNK as u64) as usize;
            if file.read_exact(&mut data[..n]).is_err()
                || blake3::hash(&data[..n]).as_bytes() != &hash
            {
                break;
            }
            hasher.update(&data[..n]);
            offset += n as u64;
            records += 1;
        }
        file.set_len(offset)?;
        file.seek(SeekFrom::Start(offset))?;
        journal.set_len(records * 32)?;
        journal.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            journal,
            hasher,
            offset,
            size,
            _guard: None,
        })
    }
    fn append(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if offset != self.offset || data.len() as u64 != (self.size - self.offset).min(CHUNK as u64)
        {
            bail!("unexpected chunk offset/length");
        }
        self.file.write_all(data)?;
        self.journal.write_all(blake3::hash(data).as_bytes())?;
        self.hasher.update(data);
        self.offset += data.len() as u64;
        // Journals are revalidated against bytes on every reconnect. An ACK is not a durability claim.
        if self.offset.is_multiple_of(8 * CHUNK as u64) {
            self.file.sync_data()?;
            self.journal.sync_data()?;
        }
        Ok(())
    }
    fn finish(&mut self, expected: &str) -> Result<()> {
        if self.offset != self.size || self.hasher.finalize().to_hex().as_str() != expected {
            bail!("complete-file integrity mismatch");
        }
        self.file.sync_all()?;
        self.journal.sync_all()?;
        Ok(())
    }
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await?
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
async fn blocking_heartbeat<T: Send + 'static>(
    w: &mut Wire,
    f: impl FnOnce(Arc<AtomicBool>) -> Result<T> + Send + 'static,
) -> Result<T> {
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());
    let mut task = tokio::task::spawn_blocking(move || f(cancel));
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.tick().await;
    loop {
        tokio::select! {r=&mut task=>return r?,_=tick.tick()=>{w.send(&Msg::Busy).await?;},}
    }
}
enum Input {
    File(File),
    Memory(std::io::Cursor<Arc<[u8]>>),
}
impl Read for Input {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(f) => f.read(b),
            Self::Memory(c) => std::io::Read::read(c, b),
        }
    }
}
impl Input {
    fn check(&self, e: &Entry) -> Result<()> {
        if let Self::File(f) = self {
            let m = f.metadata()?;
            if m.len() != e.size || stamp(&m) != e.modified || stamp_ns(&m) != e.modified_ns {
                bail!("source changed during transfer");
            }
        }
        Ok(())
    }
}
async fn send_file(
    w: &mut Wire,
    index: usize,
    entry: &Entry,
    source: &Source,
    compression: &str,
    progress: Arc<Progress>,
) -> Result<()> {
    w.send(&Msg::File { index }).await?;
    let (mut offset, prefix) = match w.recv().await? {
        Msg::Resume { offset, hash } => (offset, hash),
        _ => bail!("expected resume offset"),
    };
    if offset > entry.size || (offset != entry.size && offset % CHUNK as u64 != 0) {
        bail!("invalid resume range");
    }
    let src = source.clone();
    let expected = entry.clone();
    let (mut input, mut hasher) = blocking_heartbeat(w, move |cancel| {
        let mut input = match src {
            Source::File(p) => Input::File(open_regular(&p, false)?),
            Source::Memory(b) => Input::Memory(std::io::Cursor::new(b)),
        };
        input.check(&expected)?;
        let mut hash = blake3::Hasher::new();
        let mut buf = vec![0; CHUNK];
        let mut left = offset;
        while left > 0 {
            if cancel.load(Ordering::Relaxed) {
                bail!("verification cancelled");
            }
            let n = left.min(CHUNK as u64) as usize;
            input.read_exact(&mut buf[..n])?;
            hash.update(&buf[..n]);
            left -= n as u64;
        }
        Ok((input, hash))
    })
    .await?;
    if hasher.finalize().to_hex().as_str() != prefix {
        // A same-size/same-time file is not necessarily the same content.
        // Never splice a checkpoint from a different source into this transfer.
        w.send(&Msg::RestartFile).await?;
        if !matches!(w.recv().await?, Msg::Ack) {
            bail!("expected restart acknowledgement");
        }
        match &mut input {
            Input::File(f) => {
                f.seek(SeekFrom::Start(0))?;
            }
            Input::Memory(c) => c.set_position(0),
        }
        hasher = blake3::Hasher::new();
        offset = 0;
    }
    progress.resumed.fetch_add(offset, Ordering::Relaxed);
    progress.verified.fetch_add(offset, Ordering::Relaxed);
    let mut at = offset;
    let mut pending = 0;
    let mut pending_bytes = 0;
    while at < entry.size {
        let n = (entry.size - at).min(CHUNK as u64) as usize;
        let mode = compression.to_owned();
        let (encoded, compressed, digest, next_input, next_hash) = blocking(move || {
            let mut buf = vec![0; n];
            input.read_exact(&mut buf)?;
            hasher.update(&buf);
            let digest = blake3::hash(&buf).to_hex().to_string();
            let (e, c) = protocol::encode(&buf, &mode)?;
            Ok((e, c, digest, input, hasher))
        })
        .await?;
        input = next_input;
        hasher = next_hash;
        w.send(&Msg::Chunk {
            offset: at,
            logical: n,
            encoded: encoded.len(),
            compressed,
            hash: digest,
        })
        .await?;
        tokio::time::timeout(Duration::from_secs(120), w.w.write_all(&encoded)).await??;
        w.w.flush().await?;
        at += n as u64;
        pending += 1;
        pending_bytes += n as u64;
        if pending == 8 || at == entry.size {
            for _ in 0..pending {
                if !matches!(w.recv().await?, Msg::Ack) {
                    bail!("expected chunk ACK");
                }
            }
            progress
                .verified
                .fetch_add(pending_bytes, Ordering::Relaxed);
            pending = 0;
            pending_bytes = 0;
        }
    }
    input.check(entry)?;
    w.send(&Msg::FileDone {
        hash: hasher.finalize().to_hex().to_string(),
    })
    .await?;
    if !matches!(w.recv().await?, Msg::Ack) {
        bail!("expected file ACK");
    }
    Ok(())
}
async fn recv_worker(
    w: &mut Wire,
    stage: PathBuf,
    entries: Arc<Vec<Entry>>,
    busy: Arc<tokio::sync::Mutex<HashSet<usize>>>,
    guard: Arc<File>,
) -> Result<()> {
    loop {
        let index = match w.recv().await? {
            Msg::File { index } => index,
            Msg::WorkerDone => return Ok(()),
            _ => bail!("expected file or worker end"),
        };
        let entry = entries.get(index).context("invalid entry index")?;
        if entry.directory || !busy.lock().await.insert(index) {
            bail!("duplicate/invalid file stream");
        }
        let st = stage.clone();
        let size = entry.size;
        let guard = guard.clone();
        let mut active = blocking_heartbeat(w, move |cancel| {
            // A previous FileDone must never authorize newly repaired/truncated bytes.
            match fs::remove_file(st.join(format!("done-{index}.json"))) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let mut a = ActiveFile::open_cancel(&st, index, size, &cancel)?;
            a._guard = Some(guard);
            Ok(a)
        })
        .await?;
        w.send(&Msg::Resume {
            offset: active.offset,
            hash: active.hasher.finalize().to_hex().to_string(),
        })
        .await?;
        let mut may_restart = true;
        loop {
            match w.recv().await? {
                Msg::RestartFile if may_restart => {
                    active = blocking(move || {
                        active.file.set_len(0)?;
                        active.file.seek(SeekFrom::Start(0))?;
                        active.journal.set_len(0)?;
                        active.journal.seek(SeekFrom::Start(0))?;
                        active.hasher = blake3::Hasher::new();
                        active.offset = 0;
                        Ok(active)
                    })
                    .await?;
                    may_restart = false;
                    w.send(&Msg::Ack).await?;
                }
                Msg::Chunk {
                    offset,
                    logical,
                    encoded,
                    compressed,
                    hash,
                } => {
                    may_restart = false;
                    if logical == 0 || logical > CHUNK || encoded == 0 || encoded > CHUNK {
                        bail!("invalid chunk size");
                    }
                    let mut bytes = vec![0; encoded];
                    tokio::time::timeout(Duration::from_secs(120), w.r.read_exact(&mut bytes))
                        .await??;
                    active = blocking(move || {
                        let data = protocol::decode(&bytes, logical, compressed, &hash)?;
                        active.append(offset, &data)?;
                        Ok(active)
                    })
                    .await?;
                    w.send(&Msg::Ack).await?;
                }
                Msg::FileDone { hash } => {
                    let st = stage.clone();
                    blocking(move || {
                        active.finish(&hash)?;
                        paths::atomic_json(&st.join(format!("done-{index}.json")), &hash)
                    })
                    .await?;
                    w.send(&Msg::Ack).await?;
                    break;
                }
                _ => bail!("expected chunk or file digest"),
            }
        }
    }
}
async fn send_complete(w: &mut Wire, paths: Vec<String>) -> Result<()> {
    let mut batch = Vec::new();
    let mut bytes = 64usize;
    for path in paths {
        let n = serde_json::to_vec(&path)?.len() + 1;
        if !batch.is_empty() && bytes + n > protocol::MAX_CONTROL / 2 {
            w.send(&Msg::Paths {
                paths: std::mem::take(&mut batch),
            })
            .await?;
            bytes = 64;
        }
        if n > protocol::MAX_CONTROL / 2 {
            bail!("destination path exceeds protocol result limit");
        }
        batch.push(path);
        bytes += n;
    }
    w.send(&Msg::Complete { paths: batch }).await
}
async fn receive_complete(w: &mut Wire, mut msg: Msg) -> Result<Vec<String>> {
    let mut result = Vec::new();
    loop {
        let (paths, done) = match msg {
            Msg::Paths { paths } => (paths, false),
            Msg::Complete { paths } => (paths, true),
            _ => bail!("expected completion result"),
        };
        if result.len() + paths.len() > protocol::MAX_ENTRIES {
            bail!("result path count limit");
        }
        result.extend(paths);
        if done {
            let cleanup = async {
                w.send(&Msg::Ack).await?;
                if !matches!(w.recv().await?, Msg::Cleaned) {
                    bail!("expected cleanup confirmation");
                }
                w.send(&Msg::Ack).await
            };
            if let Err(e) = cleanup.await {
                eprintln!(
                    "Transfer verified and committed; checkpoint cleanup unconfirmed: {e}. Do not resend solely for this warning."
                );
            }
            return Ok(result);
        }
        msg = w.recv().await?;
    }
}
pub async fn send_session(
    s: &mut Session,
    plan: Arc<Plan>,
    compression: &str,
) -> Result<Vec<String>> {
    send_session_progress(s, plan, compression, Arc::new(Progress::default())).await
}
pub async fn send_session_progress(
    s: &mut Session,
    plan: Arc<Plan>,
    compression: &str,
    progress: Arc<Progress>,
) -> Result<Vec<String>> {
    if !s.authorized {
        bail!("session not mutually approved");
    }
    s.ctrl.send(&Msg::Offer(plan.offer.clone())).await?;
    for entry in &plan.entries {
        s.ctrl.send(&Msg::Entry(entry.clone())).await?;
    }
    let workers = match s.ctrl.recv().await? {
        Msg::Accept { workers } if (1..=4).contains(&workers) => workers,
        msg @ (Msg::Complete { .. } | Msg::Paths { .. }) => {
            return receive_complete(&mut s.ctrl, msg).await;
        }
        _ => bail!("expected transfer accept"),
    };
    if s.conn.is_some() {
        let next = Arc::new(AtomicUsize::new(0));
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..workers {
            let mut w = s.data().await?;
            let plan = plan.clone();
            let next = next.clone();
            let mode = compression.to_owned();
            let progress = progress.clone();
            jobs.spawn(async move {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= plan.entries.len() {
                        break;
                    }
                    if !plan.entries[i].directory {
                        send_file(
                            &mut w,
                            i,
                            &plan.entries[i],
                            &plan.sources[i],
                            &mode,
                            progress.clone(),
                        )
                        .await?;
                    }
                }
                w.send(&Msg::WorkerDone).await?;
                Ok::<_, anyhow::Error>(())
            });
        }
        while let Some(r) = jobs.join_next().await {
            r??;
        }
    } else {
        for (i, e) in plan.entries.iter().enumerate() {
            if !e.directory {
                send_file(
                    &mut s.ctrl,
                    i,
                    e,
                    &plan.sources[i],
                    compression,
                    progress.clone(),
                )
                .await?;
            }
        }
        s.ctrl.send(&Msg::WorkerDone).await?;
    }
    s.ctrl.send(&Msg::Finish).await?;
    let msg = s.ctrl.recv().await?;
    receive_complete(&mut s.ctrl, msg).await
}
fn resume_digest(kind: &Kind, entries: &[Entry]) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(&(kind, entries))?)
        .to_hex()
        .to_string())
}
fn stage_lock(stage: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(stage.join("lock"))?;
    fs2::FileExt::try_lock_exclusive(&f).context("matching transfer is active")?;
    Ok(f)
}
fn prepare(
    downloads: &Path,
    format: &str,
    offer: &Offer,
    entries: &[Entry],
) -> Result<(PathBuf, File, Option<Vec<String>>)> {
    paths::validate_manifest(entries)?;
    if offer.count != entries.len()
        || entries.iter().try_fold(0u64, |s, e| s.checked_add(e.size)) != Some(offer.total)
    {
        bail!("manifest totals mismatch");
    }
    if offer.kind != Kind::Files && (entries.len() != 1 || entries[0].directory) {
        bail!("clipboard transfer must contain one file");
    }
    if offer.kind == Kind::Text && entries[0].path != "clipboard.txt" {
        bail!("invalid text filename");
    }
    if offer.kind == Kind::Image && entries[0].path != "clipboard.png" {
        bail!("invalid image filename");
    }
    let digest = resume_digest(&offer.kind, entries)?;
    let direct = downloads.join(format!(".clipx-part-{}", offer.id));
    let mut selected = None;
    if direct.exists() {
        paths::private_dir(&direct)?;
        selected = Some((direct.clone(), stage_lock(&direct)?));
    } else {
        for item in fs::read_dir(downloads)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            if !name
                .strip_prefix(".clipx-part-")
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
                || !item.file_type()?.is_dir()
            {
                continue;
            }
            let candidate = item.path();
            if candidate.join("finalize.json").exists() {
                continue;
            }
            let marker = candidate.join("resume.json");
            if !fs::metadata(&marker).is_ok_and(|m| m.len() < 256) {
                continue;
            }
            let Ok(saved) = serde_json::from_reader::<_, String>(File::open(marker)?) else {
                continue;
            };
            if saved != digest {
                continue;
            }
            if let Ok(lock) = stage_lock(&candidate) {
                selected = Some((candidate, lock));
                break;
            }
        }
    }
    let (stage, lock) = match selected {
        Some(x) => x,
        None => {
            paths::private_dir(&direct)?;
            let lock = stage_lock(&direct)?;
            (direct, lock)
        }
    };
    let statefile = stage.join("state.json");
    if statefile.exists() {
        let old: Stored = serde_json::from_reader(File::open(&statefile)?)?;
        if old.format != format || old.entries != entries || old.offer.kind != offer.kind {
            bail!("checkpoint manifest mismatch");
        }
    }
    let stored = Stored {
        format: format.into(),
        offer: offer.clone(),
        entries: entries.to_vec(),
    };
    paths::atomic_json(&statefile, &stored)?;
    paths::atomic_json(&stage.join("resume.json"), &digest)?;
    if stage.join("finalize.json").exists() {
        let output = finish_commit(downloads, &stage, &stored)?;
        return Ok((stage, lock, Some(output)));
    }
    let mut have = 0u64;
    for (i, e) in entries.iter().enumerate() {
        if !e.directory {
            have = have.saturating_add(
                fs::metadata(file_path(&stage, i))
                    .map(|m| m.len().min(e.size))
                    .unwrap_or(0),
            );
        }
    }
    if fs2::available_space(downloads)? < offer.total.saturating_sub(have) {
        bail!("insufficient free disk space");
    }
    Ok((stage, lock, None))
}
fn commit_files(downloads: &Path, stage: &Path, stored: &Stored) -> Result<Vec<String>> {
    let tree = stage.join("tree");
    paths::private_dir(&tree)?;
    let cp = stage.join("commits.json");
    let mut commits: HashMap<String, String> = if cp.exists() {
        serde_json::from_reader(File::open(&cp)?)?
    } else {
        HashMap::new()
    };
    for (i, e) in stored.entries.iter().enumerate() {
        let root = e.path.split('/').next().context("empty path")?;
        if commits.contains_key(root) && !tree.join(root).exists() {
            continue;
        }
        let dst = tree.join(&e.path);
        if e.directory {
            fs::create_dir_all(&dst)?;
        } else {
            if !stage.join(format!("done-{i}.json")).exists() {
                bail!("entry not verified");
            }
            let src = file_path(stage, i);
            if src.exists() {
                paths::rename_noreplace(&src, &dst)?;
            } else if !dst.is_file() {
                bail!("missing staged file");
            }
            if fs::metadata(&dst)?.len() != e.size {
                bail!("staged size changed");
            }
        }
        if e.modified > 0 {
            filetime::set_file_mtime(
                &dst,
                filetime::FileTime::from_unix_time(e.modified, e.modified_ns),
            )?;
        }
    }
    // Apply directory times after children have been constructed.
    for e in stored
        .entries
        .iter()
        .rev()
        .filter(|e| e.directory && e.modified > 0)
    {
        let p = tree.join(&e.path);
        if p.exists() {
            filetime::set_file_mtime(
                p,
                filetime::FileTime::from_unix_time(e.modified, e.modified_ns),
            )?;
        }
    }
    for e in stored.entries.iter().rev().filter(|e| e.directory) {
        let p = tree.join(&e.path);
        if p.exists() {
            paths::sync_dir(&p)?;
        }
    }
    paths::sync_dir(&tree)?;
    let mut out = Vec::new();
    for e in stored.entries.iter().filter(|e| !e.path.contains('/')) {
        let src = tree.join(&e.path);
        if let Some(dst) = commits.get(&e.path)
            && !src.exists()
        {
            out.push(dst.clone());
            continue;
        }
        let mut n = 0u32;
        loop {
            let name = paths::collision(&e.path, n, e.directory);
            let dst = downloads.join(&name);
            if dst.try_exists()? {
                n = n.checked_add(1).context("too many collisions")?;
                continue;
            }
            commits.insert(e.path.clone(), dst.to_string_lossy().into_owned());
            paths::atomic_json(&cp, &commits)?;
            match paths::rename_noreplace(&src, &dst) {
                Ok(()) => {
                    paths::sync_dir(downloads)?;
                    paths::sync_dir(&tree)?;
                    out.push(dst.to_string_lossy().into_owned());
                    break;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        || dst.try_exists().unwrap_or(false) =>
                {
                    n = n.checked_add(1).context("too many collisions")?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(out)
}
fn finish_commit(downloads: &Path, stage: &Path, stored: &Stored) -> Result<Vec<String>> {
    let saved = stage.join("receipt.json");
    if saved.exists() {
        let receipt: Receipt = serde_json::from_reader(File::open(saved)?)?;
        if receipt.manifest != manifest_hash(&stored.offer, &stored.entries)? {
            bail!("receipt mismatch");
        }
        return Ok(receipt.paths);
    }
    let clipboard_output: Option<Vec<String>> =
        serde_json::from_reader(File::open(stage.join("finalize.json"))?)?;
    let output = match clipboard_output {
        Some(p) => p,
        None => commit_files(downloads, stage, stored)?,
    };
    paths::atomic_json(
        &saved,
        &Receipt {
            format: stored.format.clone(),
            manifest: manifest_hash(&stored.offer, &stored.entries)?,
            paths: output.clone(),
        },
    )?;
    Ok(output)
}
pub struct Receiver {
    pub downloads: PathBuf,
    pub headless: bool,
    pub clipboard: crate::clipboard::Writer,
    pub concurrency: usize,
    pub approval: crate::pairing::Approval,
}
pub async fn receive(s: &mut Session, id: &Identity, options: Arc<Receiver>) -> Result<()> {
    let name = match s.ctrl.recv().await? {
        Msg::Hello {
            version,
            chunk,
            name,
            device,
            ..
        } => {
            protocol::check_version(version, chunk)?;
            if name.len() > 128 || device.len() > 128 {
                bail!("identity field limit");
            }
            name
        }
        _ => bail!("expected hello"),
    };
    let nonce = uuid::Uuid::new_v4().to_string();
    s.ctrl
        .send(&Msg::Ready {
            version: 2,
            device: id.id.clone(),
            name: id.name.clone(),
            chunk: CHUNK,
            pairing_confirmation: true,
            session_nonce: nonce.clone(),
        })
        .await?;
    if !matches!(s.ctrl.recv().await?, Msg::PairStart) {
        bail!("expected selected session approval");
    }
    let code = crate::pairing::session_code(&id.fp(), &s.fingerprint, &nonce, &s.binding);
    if !crate::pairing::exchange(&mut s.ctrl, &options.approval, &code, &name).await? {
        bail!("session declined; no payload accepted");
    }
    s.ctrl.send(&Msg::SessionApproved).await?;
    if !matches!(s.ctrl.recv().await?, Msg::Ack) {
        bail!("expected approval acknowledgement");
    }
    s.authorized = true;
    let offer = match s.ctrl.recv().await? {
        Msg::Offer(o) if o.count > 0 && o.count <= protocol::MAX_ENTRIES => o,
        _ => bail!("invalid transfer offer"),
    };
    let mut entries = Vec::new();
    let mut metadata = 0;
    for _ in 0..offer.count {
        match s.ctrl.recv().await? {
            Msg::Entry(e) => {
                metadata += e.path.len() + 64;
                if metadata > protocol::MAX_METADATA {
                    bail!("metadata limit");
                }
                entries.push(e)
            }
            _ => bail!("expected manifest entry"),
        }
    }
    let stored = Stored {
        format: "clipx/2".into(),
        offer: offer.clone(),
        entries: entries.clone(),
    };
    let dl = options.downloads.clone();
    let copy = stored.clone();
    let (stage, _lock, receipt) =
        blocking(move || prepare(&dl, &copy.format, &copy.offer, &copy.entries)).await?;
    let guard = Arc::new(_lock);
    if let Some(paths) = receipt {
        send_complete(&mut s.ctrl, paths).await?;
        if matches!(s.ctrl.recv().await, Ok(Msg::Ack)) {
            drop(guard);
            let cleanup = stage.clone();
            blocking(move || {
                fs::remove_dir_all(cleanup)?;
                Ok(())
            })
            .await?;
            s.ctrl.send(&Msg::Cleaned).await?;
            let _ = s.ctrl.recv().await;
        }
        return Ok(());
    }
    let workers = if s.conn.is_some() {
        options.concurrency.clamp(1, 4)
    } else {
        1
    };
    s.ctrl.send(&Msg::Accept { workers }).await?;
    let entries = Arc::new(entries);
    let busy = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    if let Some(conn) = &s.conn {
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..workers {
            let (w, r) = tokio::time::timeout(Duration::from_secs(20), conn.accept_bi()).await??;
            let mut wire = Wire {
                r: Box::new(r),
                w: Box::new(w),
            };
            let stage = stage.clone();
            let entries = entries.clone();
            let busy = busy.clone();
            let guard = guard.clone();
            jobs.spawn(async move {
                let result = recv_worker(&mut wire, stage, entries, busy, guard).await;
                if let Err(e) = &result {
                    let _ = wire
                        .send(&Msg::Error {
                            message: e.to_string(),
                        })
                        .await;
                }
                result
            });
        }
        while let Some(r) = jobs.join_next().await {
            r??;
        }
    } else {
        recv_worker(
            &mut s.ctrl,
            stage.clone(),
            entries,
            busy.clone(),
            guard.clone(),
        )
        .await?;
    }
    if !matches!(s.ctrl.recv().await?, Msg::Finish) {
        bail!("expected transfer finish");
    }
    if busy.lock().await.len() != stored.entries.iter().filter(|e| !e.directory).count() {
        bail!("every file must complete integrity verification in this session");
    }
    let checked = stored.entries.clone();
    let checked_stage = stage.clone();
    let checked_guard = guard.clone();
    blocking(move || {
        let _guard = checked_guard;
        for (i, e) in checked.iter().enumerate() {
            if !e.directory
                && (!checked_stage.join(format!("done-{i}.json")).is_file()
                    || fs::metadata(file_path(&checked_stage, i))?.len() != e.size)
            {
                bail!("cannot finish: missing verified entry");
            }
        }
        Ok(())
    })
    .await?;
    let mut paths_out: Option<Vec<String>> = None;
    if offer.kind != Kind::Files && !options.headless {
        let p = file_path(&stage, 0);
        let data = blocking(move || Ok(fs::read(p)?)).await?; // Clipboard APIs necessarily materialize one payload.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let writer = options.clipboard.clone();
        let kind = offer.kind.clone();
        blocking(move || {
            writer
                .send((kind, data, tx))
                .map_err(|_| anyhow::anyhow!("clipboard actor stopped"))?;
            Ok(())
        })
        .await?;
        match rx.await? {
            Ok(()) => paths_out = Some(vec!["clipboard".into()]),
            Err(e) => eprintln!("Clipboard unavailable ({e}); safely saving in Downloads"),
        }
    }
    let dl = options.downloads.clone();
    let st = stage.clone();
    let commit_guard = guard.clone();
    let paths = blocking(move || {
        let _guard = commit_guard;
        paths::atomic_json(&st.join("finalize.json"), &paths_out)?;
        finish_commit(&dl, &st, &stored)
    })
    .await?;
    send_complete(&mut s.ctrl, paths).await?;
    if matches!(s.ctrl.recv().await, Ok(Msg::Ack)) {
        drop(guard);
        blocking(move || {
            fs::remove_dir_all(stage)?;
            Ok(())
        })
        .await?;
        s.ctrl.send(&Msg::Cleaned).await?;
        let _ = s.ctrl.recv().await;
    }
    Ok(())
}
pub fn cleanup(downloads: &Path, days: u64) -> Result<usize> {
    if !downloads.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for item in fs::read_dir(downloads)? {
        let item = item?;
        let name = item.file_name();
        let name = name.to_string_lossy();
        if !name
            .strip_prefix(".clipx-part-")
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
            || !item.file_type()?.is_dir()
        {
            continue;
        }
        let stage = item.path();
        let Ok(lock) = stage_lock(&stage) else {
            continue;
        };
        let mut latest = item.metadata()?.modified()?;
        for child in fs::read_dir(&stage)? {
            let child = child?;
            if let Ok(t) = child.metadata().and_then(|m| m.modified()) {
                latest = latest.max(t);
            }
        }
        if SystemTime::now().duration_since(latest).unwrap_or_default()
            < Duration::from_secs(days.saturating_mul(86400))
        {
            continue;
        }
        let Ok(saved) = serde_json::from_reader::<_, Stored>(File::open(stage.join("state.json"))?)
        else {
            continue;
        };
        if saved.format != "clipx/2" {
            continue;
        }
        let deleting = downloads.join(format!(".clipx-cleanup-{}", uuid::Uuid::new_v4()));
        paths::rename_noreplace(&stage, &deleting)?;
        drop(lock);
        fs::remove_dir_all(deleting)?;
        count += 1;
    }
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_checks_bytes_not_just_sidecar() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let data = vec![7; CHUNK];
        {
            let mut a = ActiveFile::open(temp.path(), 0, (CHUNK * 2 + 3) as u64)?;
            a.append(0, &data)?;
        }
        let a = ActiveFile::open(temp.path(), 0, (CHUNK * 2 + 3) as u64)?;
        assert_eq!(a.offset, CHUNK as u64);
        drop(a);
        let mut f = OpenOptions::new()
            .write(true)
            .open(file_path(temp.path(), 0))?;
        f.write_all(b"corrupted")?;
        drop(f);
        let a = ActiveFile::open(temp.path(), 0, (CHUNK * 2 + 3) as u64)?;
        assert_eq!(a.offset, 0);
        Ok(())
    }
    #[test]
    fn duplicate_and_truncated_chunks_fail() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut a = ActiveFile::open(temp.path(), 0, (CHUNK * 2) as u64)?;
        assert!(a.append(0, b"short").is_err());
        a.append(0, &vec![9; CHUNK])?;
        assert!(a.append(0, &vec![9; CHUNK]).is_err());
        assert!(a.finish("00").is_err());
        Ok(())
    }
    #[test]
    fn zero_byte_and_large_u64() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut a = ActiveFile::open(temp.path(), 0, 0)?;
        a.finish(blake3::hash(b"").to_hex().as_str())?;
        let big = (u32::MAX as u64) + CHUNK as u64;
        let a = ActiveFile::open(temp.path(), 1, big)?;
        assert_eq!(a.size, big);
        let offer = Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: big,
        };
        let restored: Offer = serde_json::from_slice(&serde_json::to_vec(&offer)?)?;
        assert_eq!(restored.total, big);
        Ok(())
    }
    #[test]
    fn manifest_mapping_and_symlink() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("Case"), b"a")?;
        fs::write(root.path().join("case"), b"b")?;
        #[cfg(unix)]
        fs::write(root.path().join("CON:bad."), b"c")?;
        let plan = Plan::scan(&[root.path().to_owned()], Kind::Files)?;
        paths::validate_manifest(&plan.entries)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.path(), root.path().join("cycle"))?;
            assert!(Plan::scan(&[root.path().to_owned()], Kind::Files).is_err());
        }
        Ok(())
    }
    #[test]
    fn finalization_crash_is_idempotent() -> Result<()> {
        let root = tempfile::tempdir()?;
        let offer = Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: 7,
        };
        let entries = vec![Entry {
            path: "result".into(),
            size: 7,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }];
        let stored = Stored {
            format: "clipx/2".into(),
            offer: offer.clone(),
            entries: entries.clone(),
        };
        let (stage, lock, _) = prepare(root.path(), "clipx/2", &offer, &entries)?;
        let hash = blake3::hash(b"success").to_hex().to_string();
        {
            let mut a = ActiveFile::open(&stage, 0, 7)?;
            a.append(0, b"success")?;
            a.finish(&hash)?;
        }
        paths::atomic_json(&stage.join("done-0.json"), &hash)?;
        paths::atomic_json(&stage.join("finalize.json"), &Option::<Vec<String>>::None)?;
        let first = commit_files(root.path(), &stage, &stored)?;
        drop(lock);
        // Crash point: root has moved, but no receipt was written yet.
        let (_, lock, second) = prepare(root.path(), "clipx/2", &offer, &entries)?;
        assert_eq!(Some(first), second);
        assert_eq!(fs::read(root.path().join("result"))?, b"success");
        assert!(!root.path().join("result (1)").exists());
        drop(lock);
        Ok(())
    }
    #[tokio::test]
    async fn completion_paths_are_paged() -> Result<()> {
        let paths: Vec<String> = (0..2000)
            .map(|i| format!("/Downloads/{i}/{}", "x".repeat(80)))
            .collect();
        let expected = paths.clone();
        let (a, b) = tokio::io::duplex(8192);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let mut sender = Wire {
            r: Box::new(ar),
            w: Box::new(aw),
        };
        let mut receiver = Wire {
            r: Box::new(br),
            w: Box::new(bw),
        };
        let task = tokio::spawn(async move {
            send_complete(&mut sender, paths).await?;
            assert!(matches!(sender.recv().await?, Msg::Ack));
            sender.send(&Msg::Cleaned).await?;
            assert!(matches!(sender.recv().await?, Msg::Ack));
            Ok::<_, anyhow::Error>(())
        });
        let first = receiver.recv().await?;
        let paths = receive_complete(&mut receiver, first).await?;
        assert_eq!(paths, expected);
        task.await??;
        Ok(())
    }
    #[test]
    fn cleanup_preserves_active_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let offer = Offer {
            id: uuid::Uuid::new_v4(),
            kind: Kind::Files,
            count: 1,
            total: 0,
        };
        let entries = vec![Entry {
            path: "empty".into(),
            size: 0,
            directory: false,
            modified: 0,
            modified_ns: 0,
        }];
        let (stage, lock, _) = prepare(root.path(), "clipx/2", &offer, &entries)?;
        assert_eq!(cleanup(root.path(), 0)?, 0);
        assert!(stage.exists());
        drop(lock);
        assert_eq!(cleanup(root.path(), 0)?, 1);
        assert!(!stage.exists());
        Ok(())
    }
}
