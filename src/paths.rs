//! One portable filename policy. Percent escaping is reversible and injective before case-folding.
use crate::protocol::{Entry, MAX_DEPTH, MAX_ENTRIES, MAX_METADATA};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

pub fn downloads() -> Result<PathBuf> {
    dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|p| p.join("Downloads")))
        .context("cannot locate Downloads; use --downloads")
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("symlink directory refused: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn component(name: &str) -> Result<String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        bail!("unsafe filename component");
    }
    let mut result = String::new();
    for (pos, c) in name.char_indices() {
        if c.is_control() || "<>:\"|?*%".contains(c) || c == ' ' || c == '.' {
            // Preserve interior dots/spaces for familiar names, escape only trailing ones below.
            if (c == '.' || c == ' ')
                && pos + c.len_utf8() < name.trim_end_matches([' ', '.']).len()
            {
                result.push(c);
            } else {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{b:02X}"));
                }
            }
        } else {
            result.push(c);
        }
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        result = format!("%{:02X}{}", result.as_bytes()[0], &result[1..]);
    }
    if result.len() > 180 {
        let hash = blake3::hash(name.as_bytes()).to_hex().to_string();
        let mut end = 140.min(result.len());
        while !result.is_char_boundary(end) {
            end -= 1;
        }
        result = format!("{}~{}", &result[..end], &hash[..24]);
    }
    Ok(result)
}
pub fn validate_relative(path: &str) -> Result<()> {
    if path.len() > 4096 || path.split('/').count() > MAX_DEPTH {
        bail!("path length/depth limit");
    }
    for c in path.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.contains(['\\', ':', '\0']) {
            bail!("unsafe path");
        }
        if c.len() > 200
            || c.chars().any(|x| x.is_control() || "<>:\"|?*".contains(x))
            || c.ends_with([' ', '.'])
        {
            bail!("nonportable incoming path");
        }
        let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            bail!("reserved device name");
        }
    }
    Ok(())
}
pub fn validate_manifest(entries: &[Entry]) -> Result<()> {
    if entries.len() > MAX_ENTRIES {
        bail!("entry count limit");
    }
    let mut seen = HashSet::new();
    let mut dirs = HashSet::new();
    let mut bytes = 0;
    for e in entries {
        validate_relative(&e.path)?;
        bytes += e.path.len() + 64;
        if bytes > MAX_METADATA {
            bail!("manifest metadata limit");
        }
        let key = e.path.to_lowercase();
        if !seen.insert(key.clone()) {
            bail!("case-insensitive name collision");
        }
        if let Some((parent, _)) = key.rsplit_once('/')
            && !dirs.contains(parent)
        {
            bail!("missing parent directory");
        }
        if e.directory {
            if e.size != 0 {
                bail!("directory size must be zero");
            }
            dirs.insert(key);
        }
    }
    Ok(())
}
pub fn collision(name: &str, n: u32, directory: bool) -> String {
    if n == 0 {
        return name.to_owned();
    }
    if !directory
        && let Some((stem, ext)) = name.rsplit_once('.')
        && !stem.is_empty()
    {
        return format!("{stem} ({n}).{ext}");
    }
    format!("{name} ({n})")
}
pub fn rename_noreplace(source: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            dest,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let a: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = dest.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both buffers are NUL-terminated and live for this synchronous call.
        // WRITE_THROUGH requests durability; no REPLACE_EXISTING or COPY_ALLOWED flags are used.
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (source, dest);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic no-replace supported on Linux and Windows",
        ))
    }
}
pub fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path; // Windows move uses WRITE_THROUGH; file content is FlushFileBuffers-backed.
    Ok(())
}
pub fn atomic_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("missing parent")?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(f.as_file_mut(), value)?;
    f.flush()?;
    f.as_file().sync_all()?;
    f.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_names() {
        for s in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(component(s).is_err());
        }
        for s in ["../a", "/a", "C:/a", "a/../b", "a\\b", "CON"] {
            assert!(validate_relative(s).is_err());
        }
        for s in ["CON", "com1.txt", "NUL", "a:", "a.", "a ", "a%b"] {
            assert_ne!(component(s).unwrap(), s);
        }
        assert_eq!(component("你好.txt").unwrap(), "你好.txt");
        assert!(component(&"界".repeat(300)).unwrap().len() < 180);
    }
    #[test]
    fn no_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::write(&a, b"first").unwrap();
        fs::write(&b, b"second").unwrap();
        assert!(rename_noreplace(&a, &b).is_err());
        assert_eq!(fs::read(b).unwrap(), b"second");
        assert_eq!(collision("a.txt", 1, false), "a (1).txt");
    }
    proptest::proptest! { #[test] fn never_escape(s in ".*") { if let Ok(mapped)=component(&s) { proptest::prop_assert!(!mapped.contains(['/','\\','\0'])); proptest::prop_assert!(!mapped.is_empty()); } } }
}
