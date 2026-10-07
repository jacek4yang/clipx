# Validation record — v0.1.0, 2026-10-03

## Local gates (Debian 13 x64, Rust 1.99.0)

- 33 unit/property/real-network tests pass. Coverage includes QUIC/TCP, automatic
  fallback, fresh-key/fresh-operation checkpoint adoption after interruption,
  corrupted journal recovery, same-metadata/different-content prefix rejection
  and restart, traversal rejection, checksums, collision/no-overwrite, finalization
  recovery, completion pagination, unauthorized payload and declined sessions.
- Strict all-target/all-feature Clippy and rustfmt pass.
- Real POSIX PTY / Windows ConPTY terminal test, not redirected stdin: twelve
  QUIC/TCP/auto × independent --yes combinations; direct Y without Enter; Enter/N/
  Esc rejection; invalid key; peer cancellation then another working prompt;
  Ctrl+C exit; no configuration files and successful checkpoint removal.
- RAM certificate-pin tests verify same-process reconnect reuse, changed identity
  rejection and fresh-process reset. Automatic --yes does not seed manual trust.
- CLI fault injection: sever TLS mid-file, kill/restart receiver, reconnect with
  new ephemeral identity and resume a 64 MiB file; independent SHA-256 matches.
  This test uses explicit --yes on disposable loopback endpoints.
- Real X11 text/image/copied-file and receiver-actor round-trip runs on a private,
  authenticated disposable Xvfb display, never the user's clipboard.
- Optional large-file script transfers 4,294,967,313 bytes over QUIC/zstd and
  independently compares SHA-256. Sparse mostly-zero source with nonzero tail;
  receiver writes actual bytes, not just large metadata. Not a 100 GB/WAN claim.

## Per-commit release gates

GitHub Actions tests Windows x64, Linux GNU x64, Linux musl x64 and Intel macOS. Every target
must pass format/lint/unit/network tests, actual platform clipboard tests, release
build, real CLI confirmation and receiver-restart tests. Windows PE imports must
be OS-only; musl must have neither ELF interpreter nor NEEDED shared libraries.
Only then can the release job publish all three archives and SHA256SUMS.txt.
Use the workflow run for the exact release commit, not RC1 as evidence for RC3:
https://github.com/jacek4yang/clipx/actions/workflows/ci.yml

The Windows DIBV5+PNG writer and vendored X11 diagnostic fix were established by
RC1 failures and retained; graphical tests are not silently skipped in CI.
Versioned release runs are authoritative for cross-platform results.

## Honest limits

Local environment is Debian/Xvfb, not the user's physical Windows 11 or Mint
hardware. Windows CI is a Windows runner, not every desktop/security policy.
Wayland data-control compatibility is compositor-dependent and not end-to-end
validated across GNOME/KDE here. No ARM/macOS binary is promised. No independent
security audit, WAN congestion/loss campaign, 100 GB soak, universal filesystem
power-loss guarantee or superiority over LocalSend is claimed.

Clipboard text/image decoding is memory-resident; only file streaming is bounded
independently of payload size. OS clipboard ownership and permissions still apply.
Successful stateless cleanup intentionally removes long-term deduplication
history. A completion-boundary crash can produce a suffixed duplicate on a fresh
send, never replacement of existing output.

Reproduce with README commands, tests/large_file.py and tools/benchmark.py.

RC2 pipe-only prompt tests did not cover real terminal behavior reported broken
by the user. RC3 replaces that gate with actual pseudoterminal interaction.


## Intel macOS coverage boundary

The native runner is `macos-15-intel`, with an `x86_64-apple-darwin`
executable and `MACOSX_DEPLOYMENT_TARGET=10.13`. Its Mach-O load commands are
checked for the architecture, maximum minimum-OS version, and system-only dylibs.
These checks do not emulate older macOS releases or prove every runtime API is
available there. A 2017 Intel MacBook remains a physical acceptance target.

The same native job runs atomic no-replace file/directory tests, real pasteboard
text/image/file-list tests, POSIX terminal confirmation and killed-receiver
restart/resume tests. The clipboard fixture supplies a local path to the macOS
backend, which constructs NSURL itself; passing a percent-encoded URI as a path
would invalidate the Unicode/space fixture. CI packaging has no end-user Python
or Homebrew dependency. Actual run receipts belong to their exact commit's Actions
run; a configured test job is not evidence of a pass.
