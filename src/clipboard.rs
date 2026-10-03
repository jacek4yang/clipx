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
                        set_image(ctx, image)?;
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

/// Work around clipboard-rs 0.3.5 assuming BMPV5 when image's BMP encoder emits V4.
/// Use documented CF_DIBV5 bytes plus the lossless registered PNG format on Windows.
pub fn set_image(ctx: &ClipboardContext, image: RustImageData) -> Result<()> {
    #[cfg(not(windows))]
    {
        ctx.set_image(image)
            .map_err(|e| anyhow!("clipboard image: {e}"))?;
    }
    #[cfg(windows)]
    {
        let _ = ctx;
        let (width, height) = image.get_size();
        let rgba = image
            .to_rgba8()
            .map_err(|e| anyhow!("image pixels: {e}"))?
            .into_raw();
        let dib = dibv5(width, height, &rgba)?;
        let png = image.to_png().map_err(|e| anyhow!("image PNG: {e}"))?;
        let format = clipboard_win::register_format("PNG")
            .ok_or_else(|| anyhow!("cannot register PNG clipboard format"))?;
        let _lock = clipboard_win::Clipboard::new_attempts(10)
            .map_err(|e| anyhow!("clipboard busy: {e}"))?;
        clipboard_win::empty().map_err(|e| anyhow!("clipboard clear: {e}"))?;
        clipboard_win::raw::set_without_clear(clipboard_win::formats::CF_DIBV5, &dib)
            .map_err(|e| anyhow!("clipboard DIBV5: {e}"))?;
        clipboard_win::raw::set_without_clear(format.get(), png.get_bytes())
            .map_err(|e| anyhow!("clipboard PNG: {e}"))?;
    }
    Ok(())
}
/// https://learn.microsoft.com/windows/win32/api/wingdi/ns-wingdi-bitmapv5header
/// Top-down 32-bit BGRA with explicit channel masks. No packed structs or unsafe casts.
pub fn dibv5(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    let width = i32::try_from(width)?;
    let height = i32::try_from(height)?;
    if width <= 0 || height <= 0 {
        bail!("empty image");
    }
    let size = (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| anyhow!("image size overflow"))?;
    if size != rgba.len() {
        bail!("RGBA length mismatch");
    }
    let size32 = u32::try_from(size)?;
    let mut data = vec![0u8; 124];
    for (offset, value) in [
        (0, 124u32),
        (4, width as u32),
        (8, (-height) as u32),
        (16, 3),
        (20, size32),
        (40, 0x00ff0000),
        (44, 0x0000ff00),
        (48, 0x000000ff),
        (52, 0xff000000),
        (56, 0x73524742),
        (108, 4),
    ] {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[12..14].copy_from_slice(&1u16.to_le_bytes());
    data[14..16].copy_from_slice(&32u16.to_le_bytes());
    data.try_reserve_exact(size)?;
    for px in rgba.as_chunks::<4>().0 {
        data.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
    }
    Ok(data)
}
#[cfg(test)]
mod tests {
    #[test]
    fn tiny_dibv5_has_correct_header_and_pixels() {
        let d = super::dibv5(1, 1, &[200, 50, 10, 255]).unwrap();
        assert_eq!(d.len(), 128);
        assert_eq!(&d[0..4], &124u32.to_le_bytes());
        assert_eq!(&d[8..12], &(-1i32).to_le_bytes());
        assert_eq!(&d[124..], &[10, 50, 200, 255]);
        assert!(super::dibv5(1, 1, &[0]).is_err());
        assert!(super::dibv5(0, 1, &[]).is_err());
    }
}
