# Small clipboard-rs compatibility patch

`vendor/clipboard-rs` is clipboard-rs 0.3.5 from crates.io. Its original
MIT license is retained in vendor/clipboard-rs/LICENSE. The published crate's
source is otherwise retained rather than reimplementing desktop clipboard backends.

Local change: the X11 backend's four diagnostic `println!` calls are changed to
`eprintln!`. A background selection-owner thread previously wrote unstructured
messages into clipx's `--json` stdout stream. Sending diagnostics to stderr keeps
that public machine interface parseable, without disabling diagnostics.

A separate clipx-level Windows writer builds a documented 124-byte DIBV5 header
with top-down BGRA data and registers both DIBV5 and PNG. This works around the
upstream writer interpreting image's BMP V4 encoding as V5, which failed the
real Windows CI test for a 1x1 image. The public reader still uses clipboard-rs.

When upgrading clipboard-rs, re-run the real X11 and Windows clipboard tests and
check whether these workarounds can be removed. Do not remove a failing test.

## Dialoguer 0.12.0

Upstream https://github.com/console-rs/dialoguer, MIT. Vendored from crates.io
0.12.0 with a narrow adapter: Confirm::interact_on_with_reader accepts a key-read
closure, while retaining upstream rendering and acceptance behavior. Existing
interact methods retain their original console reader. clipx supplies cancellable
Crossterm poll/read events, so a peer disconnect or timeout can restore raw mode
and release the prompt instead of leaving a detached stdin thread behind.
The source patch is confined to src/prompts/confirm.rs. Optional editor/password/
history features are disabled; no runtime dependency files are required.
