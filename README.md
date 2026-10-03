# clipx

[中文快速上手](README.zh-CN.md)

Explicit, encrypted, resumable clipboard and file transfers between your own
Windows 11 and Linux Mint computers. One Rust executable; no cloud service,
account, multicast discovery, HTTP server, GUI or background clipboard watcher.

**Initial release candidate.** This is a new implementation, not a claim of
proven production reliability or benchmark superiority over LocalSend. Test it
on your own machines before depending on it for irreplaceable data.

## Quick start

Download the appropriate executable archive from GitHub Releases, verify its
SHA-256 against `SHA256SUMS.txt`, extract, and put `clipx` / `clipx.exe` on PATH.
Linux binaries target x86-64 GNU/Linux; release builds use Ubuntu 22.04 for a
conservative glibc baseline. Windows builds target x86-64 MSVC.

On each device, print its identity:

```sh
clipx fingerprint
```

Compare fingerprints through an independent trusted channel. On the receiver,
trust the sender's 64-hex-character fingerprint (not the device name):

```sh
clipx peer trust SENDER_FINGERPRINT
clipx recv --bind 100.64.0.6
```

On the sender, pin the receiver's independently verified fingerprint:

```sh
clipx peer trust RECEIVER_FINGERPRINT --host 100.64.0.6
clipx peer add lab 100.64.0.6
clipx send lab
```

Both devices are symmetric: repeat trust setup in the other direction to send
back. `recv` reads its TLS client trust list at startup; restart it after changing
trust. The host mapping uses the actual IP/hostname, not an alias.

### Interactive discovery alternative

The receiver can temporarily allow **pair-only** probes:

```sh
clipx recv --pairing --bind 100.64.0.6
# On sender:
clipx pair 100.64.0.6
# Or noninteractive with an independently verified pin:
clipx pair 100.64.0.6 --fingerprint RECEIVER_FINGERPRINT
```

`pair` prints the receiver fingerprint and requires an exact `yes`. The receiver
prints the probing sender fingerprint; verify it on the sender and run
`peer trust SENDER_FINGERPRINT` locally. Restart `recv` without `--pairing`.
Pair probes cannot send files or clipboard contents, and do not automatically
trust the connecting sender. A changed known fingerprint fails closed; deliberate
identity rotation requires `clipx peer forget OLD_FINGERPRINT` and re-pairing.

## Everyday use

```sh
clipx recv                           # default IPv4 wildcard, UDP and TCP 45817
clipx recv --bind 100.64.0.6          # recommended tailnet-only binding
clipx recv --bind ::                 # IPv6; dual-stack behavior depends on OS
clipx recv --headless
clipx send lab                       # copied files, then image, then text
clipx send lab --path report.pdf
clipx send lab --path project --path photo.png
clipx send lab --text 'hello'
printf 'hello' | clipx send lab --stdin
clipx send lab --transport tcp
clipx send lab --compression off
clipx peer list
clipx peer remove lab
clipx doctor
clipx cleanup                        # remove inactive state older than 7 days
```

Global options may appear after subcommands. `--config-dir` (or
`CLIPX_CONFIG_DIR`) and `--downloads` (or `CLIPX_DOWNLOADS`) support isolated
instances and tests. `--port` changes both UDP and TCP port. `--json` emits
machine-readable stdout events; diagnostics use stderr. `--quiet` silences normal
stdout; `--verbose` includes retry error details.

There is no daemon installer, autostart, firewall rule modification, automatic
clipboard synchronization or password-history collection. Run the receiver in
your preferred terminal/service manager. No root/admin privileges are required.

## Clipboard and files

- Windows: native text, image and Explorer copied-file list via `clipboard-rs`.
- Linux X11: text, image and copied-file URI lists, with a persistent clipboard
  owner in the receiving process. Keep `recv` running for selection ownership.
- Wayland: `clipboard-rs` with `wl-clipboard-rs`; requires a compositor supporting
  ext-data-control or wlr-data-control. This does **not** promise arbitrary GNOME
  Wayland support. `doctor` reports availability; use explicit inputs if absent.
- Headless or unavailable receiving clipboard: text becomes `clipboard.txt`,
  image becomes `clipboard.png` in Downloads. Existing files receive suffixes.
- Clipboard text/images necessarily materialize in memory, including image
  decoding. Their practical limits depend on OS, application and available RAM.
  Large arbitrary data should be sent as a file instead.
- Files/archives are transferred unchanged; directories use a native manifest
  and streamed files, never a whole temporary archive.
- Symlinks, FIFOs, sockets and devices are rejected. Non-Unicode filenames are
  rejected with an actionable error. Windows-invalid components are escaped;
  long names are shortened with a hash, and case-insensitive collisions get
  suffixes. Mapping does not change file contents.
- Downloads uses the platform directory API, then `$HOME/Downloads` fallback.

## Transports, compression and recovery

QUIC/UDP is preferred. Auto mode starts TCP/TLS after 350 ms if QUIC has not
completed an authenticated application session. Only the winner may offer a
transfer. Both use TLS **1.3 only**, client certificates and pinned certificate
fingerprints, with ALPN `clipx/1`. No TLS 0-RTT or QUIC datagrams are used.
Quinn's conservative MTU/PMTU and CUBIC defaults remain intact.

QUIC uses one control stream and up to four reusable worker streams; TCP uses
one framed sequential stream. Each file is streamed in independent 1 MiB chunks.
Each chunk and complete file have real BLAKE3 hashes. Up to eight chunks per
worker may be in flight before the sender waits for their verification ACKs. Zstd auto mode tests a
small sample; already compressed/random content typically stays uncompressed.
The receiver bounds both encoded and decoded chunk sizes.

On a transient disconnection, the sender retries with bounded exponential
backoff (five retries by default). Auto retries favor TCP after failure. Ctrl+C
preserves resumable state. The command prints its transfer ID:

```sh
clipx send lab --resume TRANSFER_UUID
```

Keep the original files unchanged. Resume state is bound to the sender
certificate and exact manifest. The receiver rechecks every journaled chunk
against stored bytes and resumes at the verified prefix of each file. Corrupt
or torn journal tails are truncated; they are never blindly trusted. Sender and
receiver re-hash their existing prefixes on resume to reconstruct a real
whole-file BLAKE3 state. This adds disk reads on resume, but not network retransmit
of verified prefixes. Normal fresh transfers hash while streaming.

Partial data lives in Downloads/.clipx-state/partials and outgoing plans in the
private configuration directory. Clipboard payloads are temporarily spooled for
resumability, then removed from disk after acknowledged success. Interrupted
clipboard spools contain potentially sensitive data: complete or remove them
when no longer needed. `cleanup` removes abandoned incoming partials/receipts and outgoing plans/spools
older than the retention threshold, excluding active locked transfers.

## Commit and metadata semantics

A file/tree becomes visible only after all entries pass final verification.
Linux uses `renameat2(RENAME_NOREPLACE)`; Windows uses `MoveFileExW` without
replacement. If a destination races with commit, a new numeric suffix is tried.
There is no delete-and-overwrite fallback. Unsupported filesystems fail safely.
Staging is on the destination filesystem. Multiple selected top-level roots
commit one root at a time, **not** as one cross-root atomic transaction.
A durable finalization journal recovers interrupted commits; completion receipts
make repeat delivery of the same ID idempotent until receipt cleanup (7 days by
default). If you delete final output, a receipt can still report the earlier
successful delivery; start a new transfer to deliver again.

Contents and tree shape are preserved; modification times are applied where
supported. Ownership is the receiving user's. Windows inherits local ACLs. Unix
uses local umask/private staging permissions. No foreign ACL, UID/GID, xattr,
NTFS ADS, executable mode or setuid/setgid metadata is imported. This is a data
transfer utility, not a filesystem backup program. Source files must not change
during transfer; size/mtime and final hashes detect common concurrent edits.

## Limits and troubleshooting

Limits: 1 MiB chunks, 64 KiB control frames, 100,000 entries, 16 MiB estimated
manifest metadata, 64 components, 4096-byte relative paths, four QUIC workers,
eight active connections. There is no 32-bit file-size cap. Clipboard memory is
separate from the bounded file-transfer pipeline. Free-space checks are
conservative estimates, not guarantees; ENOSPC is a failure, never success.

Allow **both UDP and TCP 45817** in your existing firewall/tailnet ACLs. No Tailscale
API is needed. MagicDNS names, ordinary DNS, IPv4 and IPv6 are supported. For
restricted exposure bind the actual tailnet address; default wildcard binding
can accept connections on the LAN too (authentication remains mandatory).

If pairing fails, check fingerprints in both directions, restart the receiver,
then check port/ACL and `clipx doctor`. If X11 lacks DISPLAY/Xauthority or Wayland
lacks a data-control protocol, use `--path`, `--text`, `--stdin`, or `--headless`.
The program does not bypass desktop permission or clipboard restrictions.

## Build and verification

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
# Disposable X11 environment (Linux):
xvfb-run -a cargo test --test clipboard_graphical -- --ignored --nocapture
# Windows interactive desktop:
cargo test --test clipboard_graphical -- --ignored --nocapture
```

Rust 1.99.0 is pinned in rust-toolchain.toml; Cargo.lock is committed. Linux
clipboard support uses Rust X11/Wayland clients; no OpenSSL or language runtime
is needed. A working system Wayland client library/compositor may be needed on
Wayland. Tests distinguish headless payload delivery from actual clipboard
round-trips. CI builds and tests Windows and Linux, then publishes archives and
SHA-256 checksums only after both succeed. Initial releases are marked pre-release.

See [SECURITY.md](SECURITY.md), [protocol](docs/PROTOCOL.md) and
[validation](docs/VALIDATION.md). The repository-local helper
`sh tools/setup-git-identity.sh` configures the maintainer's Git identity without
changing global Git configuration or any other computer.
