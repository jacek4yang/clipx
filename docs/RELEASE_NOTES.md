First clipx release candidate for Windows 11 x86-64 and Linux Mint/x86-64 GNU/Linux.

- Explicit clipboard/file/directory push; no watcher or cloud service.
- QUIC first, TLS 1.3 TCP fallback, mutual certificate pinning.
- Verified 1 MiB chunk resume, reconnect, streamed directory manifests, zstd.
- No-overwrite atomic commits, headless fallback, portable filenames.
- Windows/Linux executables built by the attached GitHub Actions run.

Verify SHA256SUMS.txt before installation. Pair by independently checking both
devices' fingerprints. Read README and SECURITY before use.

This is an initial pre-release, not an independently audited stable release.
Physical Windows 11/Mint tailnet acceptance and broad Wayland compositor testing
remain important. No universal speed or LocalSend superiority claim is made.
