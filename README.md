# clipx

[中文快速上手](README.zh-CN.md)

One Rust executable for encrypted clipboard, file and directory transfers between
Windows, Linux and macOS computers. No account, config, saved identity, trust
store, daemon, autostart, watcher, discovery or cloud service.

## Install once

Download from [Releases](https://github.com/jacek4yang/clipx/releases), check the
archive against SHA256SUMS.txt, extract the executable and put it on PATH.
Linux x64: prefer **x86_64-unknown-linux-musl** (static, no shared-library runtime).
Linux ARM64: choose **aarch64-unknown-linux-musl**, also static.
Place `clipx` in `~/.local/bin` and ensure that directory is on your PATH.
Windows x64: put `clipx.exe` in a PATH directory of your choice. Static MSVC CRT;
only OS DLLs are imported. Windows builds are unsigned and may require normal
SmartScreen review. Documents are optional; `clipx licenses` embeds all notices.
A binary is specific to its OS/architecture, not universal across every computer.

Intel macOS: use **x86_64-apple-darwin**, including Intel 2017 MacBook Pro.
The build deployment target is macOS 10.13; native CI runs on macOS 15 Intel,
so the deployment setting alone is not a claim of runtime testing on every
older macOS release. Apple Silicon uses **aarch64-apple-darwin** (macOS 11+
deployment target), tested natively on the ARM64 macOS runner.
No Homebrew, Rust, Python or third-party dylibs are needed to run the executable;
macOS system frameworks remain required. After verifying the archive checksum,
extract it and install only the executable:

```sh
mkdir -p "$HOME/.local/bin"
install -m 755 clipx "$HOME/.local/bin/clipx"
export PATH="$HOME/.local/bin:$PATH"
clipx --help
```

Add the PATH line to your shell configuration yourself if desired. The program
does not install services or edit shell settings. Builds are unsigned and not
notarized; if macOS blocks one, review it using macOS's normal security UI after
verifying its source and checksum. Do not disable Gatekeeper globally.
Clipboard operations require a logged-in graphical session. Over SSH/headless,
use explicit inputs (`--path`, `--text`, `--stdin`) and `recv --headless`.
The Intel CI job tests real pasteboard text/image/file lists, terminal prompts,
file/directory publication and interrupted-transfer recovery, and rejects
non-system runtime dylibs or a newer-than-declared deployment target.


## Two commands

Receiver:
```sh
clipx recv
```
Sender (replace IP with receiver address):
```sh
clipx send IP
```
Both terminals display the SAME one-time session fingerprint. Compare the entire
line over an independent trusted channel, then press `Y` on each computer (no Enter needed). `N` or Enter declines; Esc cancels; Ctrl+C exits.
Dialoguer/Console render an inline prompt; Crossterm handles native, cancellable
keyboard input. No full-screen UI. NO_COLOR is respected. A real terminal is
required unless `--yes` was explicitly supplied.

After both approve, each process remembers the peer certificate fingerprint ONLY
in RAM. Reconnects between those same running processes do not prompt again.
Fresh session codes still change, but the verified ephemeral peer identity is the
cache key. Changed keys require new confirmation. Restart clears trust: running
`clipx send` again creates a new process, even in the same terminal window.
A displayed name is unverified metadata, not an identity guarantee.

### Optional unattended approval

```sh
clipx recv --yes
clipx send --yes IP
```
Each flag skips ONLY local confirmation, only for this process. One side using
`--yes` does not override the other side. The fingerprint is still printed.
`recv --yes` accepts incoming sessions for as long as it runs, so use only on a
trusted network with appropriately restricted binding/firewall/tailnet ACLs.
With both sides using `--yes`, TLS still encrypts traffic, but no human verifies
peer identity; active interception and unwanted senders are not excluded.
Nothing about `--yes` is saved. There is no remembered trust setting.

## Useful explicit inputs

```sh
clipx recv --bind 100.64.0.6         # restrict to your actual tailnet address
clipx recv --headless              # save clipboard payloads as Downloads files
clipx send IP --path report.pdf
clipx send IP --path folder --path image.png
clipx send IP --text 'hello'
printf 'hello' | clipx send --yes IP --stdin
clipx send IP --transport tcp
clipx send IP --compression off
clipx cleanup                      # inactive checkpoints older than 7 days
```

Without `--yes`, `--stdin` reads confirmation from the controlling terminal,
not from payload input. If no terminal exists, it fails safely. Piped `y` is not
an interactive terminal and cannot silently authorize. Use `--yes` deliberately for scripts. There is no remote shell or
automatic execution of received files.
Global `--downloads`, `--port`, `--transport`, `--json`, `--quiet`, `--verbose`
may appear after subcommands. Default port is UDP/TCP 45817. JSON data goes to
stdout; fingerprints, prompts and warnings go to stderr even with `--quiet`.

## Disk footprint and recovery

The sender creates no identity/config/cache/spool files. Ephemeral keys and
clipboard bytes exist only in memory. The receiver creates Downloads if needed,
final output, and a private `.clipx-part-UUID` checkpoint there while transferring.
Checkpoints contain payload bytes, manifests and integrity journals, never keys,
fingerprints or trust records. Successful acknowledged delivery removes them.
Interrupted transfers retain them so repeating the SAME send command with unchanged
source data can resume, even after either process restarts with new keys. The
receiver revalidates stored chunks; both ends compare the prefix hash before using
it. A different source prefix restarts that file rather than splicing content.

Transient failures retry up to three times by default (`--retries 0..12`), with
backoff. A peer already verified in the same process is remembered in RAM; otherwise
confirmation is required unless that side uses `--yes`. Auto retries prefer TCP. Ctrl+C stops the process; partial output remains
hidden and resumable. `cleanup --days N` removes only inactive recognized
checkpoints. No startup service or automatic cleanup task is installed.

A finalization receipt is kept only inside an unfinished checkpoint, and deleted
after successful acknowledgement. There is deliberately no long-term delivery
history. If a crash loses completion acknowledgement, a later fresh send can
produce a suffixed duplicate, never overwrite existing output. After a verified
completion followed by cleanup warning, do not resend solely for that warning.

## Clipboard and files

- Windows: native text, image and Explorer copied-file list via `clipboard-rs`.
- Linux X11: text, image and copied-file URI lists, with a persistent clipboard
  owner in the receiving process. Keep `recv` running for selection ownership.
- Wayland: `clipboard-rs` with `wl-clipboard-rs`; requires a compositor supporting
  ext-data-control or wlr-data-control. This does **not** promise arbitrary GNOME
  Wayland support. Use explicit file/text inputs if unavailable.
- Headless or unavailable receiving clipboard: text becomes `clipboard.txt`,
  image becomes `clipboard.png` in Downloads. Existing files receive suffixes.
- Clipboard text/images necessarily materialize in memory, including image
  decoding. Their practical limits depend on OS, application and available RAM.
  Large arbitrary data should be sent as a file instead.
- Files/archives are transferred unchanged; directories use a native manifest
  and streamed files, never a whole temporary archive.
- Symlinks, FIFOs, sockets and devices are rejected. Non-Unicode filenames are
  rejected with an actionable error. Network-share clipboard paths require
  explicit `--path` to avoid implicit SMB authentication. Windows-invalid components are escaped;
  long names are shortened with a hash, and case-insensitive collisions get
  suffixes. Mapping does not change file contents.
- Downloads uses the platform directory API, then `$HOME/Downloads` fallback.

## Transport and integrity

QUIC is preferred; TCP/TLS starts after 350 ms if needed. Only the selected
connection prompts or transfers. TLS 1.3 only, ALPN `clipx/2`, no 0-RTT. Both
ends prove possession of ephemeral certificate keys. The displayed code binds
both certificate fingerprints, receiver nonce and this connection's TLS exporter.
It is not merely a static certificate fingerprint. Version 2 is intentionally
incompatible with RC1; upgrade both ends.

One control stream plus up to four QUIC workers; TCP uses one sequential stream.
Files use 1 MiB chunks, up to eight in-flight chunks per worker, bounded zstd
compression/decompression and BLAKE3 chunk/full-file checks. Normal transfers
hash while streaming. Resume re-reads verified prefixes without retransmitting
matching bytes. Quinn CUBIC/PMTU defaults are retained.

Verified trees commit via Linux renameat2(RENAME_NOREPLACE), macOS
renameatx_np(RENAME_EXCL), or Windows MoveFileExW without replacement. Names get suffixes on collision. Multiple roots commit
one at a time; no cross-root atomicity or filesystem-backup promise.

Contents and tree shape are preserved; modification times are applied where
supported. Ownership is the receiving user's. Windows inherits local ACLs. Unix
uses local umask/private staging permissions. No foreign ACL, UID/GID, xattr,
NTFS ADS, executable mode or setuid/setgid metadata is imported. This is a data
transfer utility, not a filesystem backup program. Source files must not change
during transfer; size/mtime and final hashes detect common concurrent edits.

## Limits and verification

64 KiB control frames; 100,000 entries; 16 MiB manifest metadata; 64 path
components; 4096-byte relative paths; four QUIC workers; eight active connections.
File sizes use u64. Clipboard text/image decoding is necessarily memory-resident;
large data should be sent as files. ENOSPC and unsupported filesystem operations
fail rather than reporting success. Default receiver binds IPv4 wildcard: restrict
`--bind` if other networks should not reach it. `--bind ::` enables IPv6; dual-stack
behavior is OS-dependent. No firewall/network configuration is modified.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
python tests/cli_confirmation.py target/release/clipx
python tests/cli_recovery.py target/release/clipx
```

Rust 1.99.0 is pinned. CI tests Windows x64, GNU/Linux x64, static musl x64/ARM64 and Intel/ARM64 macOS,
including real clipboard round-trips and process-level transfer tests, before
release. This stable release is not an independent security audit or a
promise to outperform LocalSend. Wayland/compositor and physical desktop coverage
are documented in [validation](docs/VALIDATION.md).
See [security](SECURITY.md) and [protocol](docs/PROTOCOL.md).
