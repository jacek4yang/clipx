use crate::protocol::Kind;
use anyhow::{Result, anyhow, bail};
use clipboard_rs::{Clipboard, ClipboardContext, RustImageData, common::RustImage};
use std::path::PathBuf;

pub enum Content {
    Paths(Vec<PathBuf>),
    Bytes(Kind, Vec<u8>),
}
pub fn read() -> Result<Content> {
    let ctx = ClipboardContext::new()
        .map_err(|e| anyhow!("clipboard unavailable: {e}; use --path, --text or --stdin"))?;
    if let Ok(files) = ctx.get_files()
        && !files.is_empty()
    {
        let paths = files
            .into_iter()
            .map(|s| {
                if s.starts_with("file:") {
                    url::Url::parse(&s)?
                        .to_file_path()
                        .map_err(|_| anyhow!("nonlocal file URI"))
                } else {
                    Ok(PathBuf::from(s))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(Content::Paths(paths));
    }
    if let Ok(image) = ctx.get_image() {
        let png = image.to_png().map_err(|e| anyhow!("image encode: {e}"))?;
        return Ok(Content::Bytes(Kind::Image, png.get_bytes().to_vec()));
    }
    match ctx.get_text() {
        Ok(text) => Ok(Content::Bytes(Kind::Text, text.into_bytes())),
        Err(e) => {
            bail!("clipboard has no supported file/image/text: {e}; use --path, --text or --stdin")
        }
    }
}
// A persistent actor owns the context so X11 selection ownership survives each write.
pub type Writer =
    std::sync::mpsc::SyncSender<(Kind, Vec<u8>, tokio::sync::oneshot::Sender<Result<()>>)>;
pub fn writer() -> Writer {
    let (tx, rx) =
        std::sync::mpsc::sync_channel::<(Kind, Vec<u8>, tokio::sync::oneshot::Sender<Result<()>>)>(
            1,
        );
    std::thread::spawn(move || {
        let ctx = ClipboardContext::new();
        while let Ok((kind, data, reply)) = rx.recv() {
            let result = (|| -> Result<()> {
                let ctx = ctx
                    .as_ref()
                    .map_err(|e| anyhow!("clipboard unavailable: {e}"))?;
                match kind {
                    Kind::Text => ctx
                        .set_text(String::from_utf8(data)?)
                        .map_err(|e| anyhow!("clipboard text: {e}"))?,
                    Kind::Image => {
                        let image = RustImageData::from_bytes(&data)
                            .map_err(|e| anyhow!("image decode: {e}"))?;
                        ctx.set_image(image)
                            .map_err(|e| anyhow!("clipboard image: {e}"))?;
                    }
                    Kind::Files => bail!("files are saved, not written to clipboard"),
                }
                Ok(())
            })();
            let _ = reply.send(result);
        }
    });
    tx
}
