# Validation record — 2026-10-03

## Verified locally (Debian 13 x86-64, Rust 1.99.0)

- 17 unit/property tests and 11 real loopback integration tests pass.
- Formatting and strict all-target/all-feature Clippy pass.
- Real QUIC and TLS/TCP transfer, automatic QUIC-to-TCP connection fallback.
- Interrupted TCP transfer continues over QUIC from verified stored chunks.
- Native X11 text, image, copied-file list and receiving clipboard actor tested
  on a disposable authenticated Xvfb display. No user's clipboard was used.
- Black-box CLI fault injection severs the TLS connection mid-file and kills the
  receiver process, then restarts it. Sender automatically reconnects and resumes
  verified data (64 MiB file; representative run reused 7 MiB). Independent SHA-256
  matches, and only one final output is produced.
- A real 4,294,967,313-byte transfer passes independent source/output SHA-256:
  sparse mostly-zero source, nonzero tail marker, streamed QUIC/zstd reception.
  The receiver writes real file bytes; this is not just a large-size metadata test.
  A representative GNU build run measured 15,916 KiB maximum child RSS. This is
  not a general clipboard memory limit or a WAN throughput claim.
- 18 reproducible loopback benchmark cases: compressible/incompressible 32 MiB
  file and 1,000 small files; QUIC/TCP × off/auto/zstd. Every output verified by
  SHA-256. See tools/benchmark.py to reproduce throughput/CPU/peak-RSS measures.
- Collision races, finalization-crash recovery, duplicate receipts, bad checksums,
  missing-file finalization, path traversal, stale-journal corruption, zero-byte
  files, Unicode names, large result pagination, and active-cleanup locks covered.
- Static Linux musl build has no ELF interpreter and no NEEDED shared-library
  entries; the same integration suite and process-restart test pass on musl.

## GitHub Actions evidence

The earlier two-target validation at commit
`ea7425456f76b2792213dc4411a01dbb30ae6071` passed all Linux and Windows gates:
https://github.com/jacek4yang/clipx/actions/runs/37113477687

This includes real X11/Windows clipboard tests, static-CRT Windows build, and
black-box receiver-process-restart recovery on each OS. The downloaded Windows
artifact's SHA-256 matched the Actions API digest. Its PE import table contains
only Windows system DLLs; no separate VC runtime or application DLL is needed.

The first Windows graphical test failed on clipboard-rs's BMP V4/V5 assumption.
It was fixed with a proper DIBV5+PNG writer, not skipped. A later Rust lint
failure was also fixed rather than suppressed. See docs/VENDORED.md for the
separate X11 stdout-diagnostic compatibility patch.

Final release CI additionally tests **three** targets (GNU, musl, Windows), asserts
static/system-only linkage, and packages only after tests succeed. Follow the
Release's associated exact workflow run for the final source SHA and artifacts;
earlier green runs are not substitutes for validation after later source changes.

## Boundaries

Windows CI is Windows Server 2025, not a physical Windows 11 laptop. Linux CI
uses Ubuntu and local testing uses Debian, not a physical Mint desktop. The
project targets Windows 11/Mint x86-64 using those platform APIs. User-machine
acceptance and real Tailscale/Headscale WAN soak remain outstanding.

Wayland support is implemented through a Rust data-control client, but compositor
coverage has not been exhaustively tested. No claim of universal GNOME/Wayland
support, 100 GB real-disk testing, independent security audit, or superiority to
LocalSend is made. Supported protocol/OS constraints are documented in README.
