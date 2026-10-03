//! Run on a disposable X11 server with xvfb-run; Windows CI uses its desktop session.
use anyhow::{Result, anyhow};
use clipboard_rs::{Clipboard, ClipboardContext, RustImageData, common::RustImage};
#[test]
#[ignore = "requires a real clipboard session; run under xvfb-run on Linux"]
fn graphical_text_image_and_copied_file_list() -> Result<()> {
    let owner = ClipboardContext::new().map_err(|e| anyhow!("{e}"))?;
    owner
        .set_text("clipx UTF-8 你好".into())
        .map_err(|e| anyhow!("{e}"))?;
    assert!(
        matches!(clipx::clipboard::read()?,clipx::clipboard::Content::Bytes(clipx::protocol::Kind::Text,data) if data=="clipx UTF-8 你好".as_bytes())
    );
    // Valid 1x1 PNG generated once as a test fixture, not a mock clipboard backend.
    let png = include_bytes!("fixtures/pixel.png");
    let image = RustImageData::from_bytes(png).map_err(|e| anyhow!("{e}"))?;
    owner.set_image(image).map_err(|e| anyhow!("{e}"))?;
    match clipx::clipboard::read()? {
        clipx::clipboard::Content::Bytes(clipx::protocol::Kind::Image, data) => {
            assert!(RustImageData::from_bytes(&data).is_ok());
        }
        _ => anyhow::bail!("expected screenshot image"),
    }
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("copied.txt");
    std::fs::write(&path, b"test")?;
    #[cfg(windows)]
    let copied = path.to_string_lossy().into_owned();
    #[cfg(not(windows))]
    let copied = url::Url::from_file_path(&path)
        .map_err(|_| anyhow!("file URI"))?
        .to_string();
    owner.set_files(vec![copied]).map_err(|e| anyhow!("{e}"))?;
    match clipx::clipboard::read()? {
        clipx::clipboard::Content::Paths(files) => assert_eq!(files, vec![path]),
        _ => anyhow::bail!("expected copied file list"),
    }
    Ok(())
}
