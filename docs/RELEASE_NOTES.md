# clipx v0.1.0

Fix real terminal confirmation and add explicitly requested RAM-only peer trust.

- Dialoguer/Console inline prompt with cancellable native Crossterm key events.
  Press Y to accept immediately; N or Enter declines; Esc cancels; Ctrl+C exits.
  Clear bilingual labels, no full-screen takeover, NO_COLOR support.
- Peer cancellation/timeout restores terminal mode and cursor and releases the
  input reader. No detached read_line stealing the next answer.
- A successful mutual confirmation remembers the peer certificate identity only
  in this process's RAM. Same-process reconnects skip repeat prompts; changed keys
  or restarting either side requires new confirmation. No disk trust/config.
- --yes remains independently local and process-scoped. A noninteractive input
  pipe is not treated as an interactive terminal; scripts must explicitly use --yes.
- Actual Linux PTY and Windows ConPTY keyboard tests replace RC2 pipe-only tests.
- Protocol clipx/2 remains compatible, but upgrade both ends for the corrected UX.

Windows x64 static CRT, Linux x64 static musl and GNU builds. All prior streaming,
resume and no-overwrite behavior retained. Stable release, not a zero-defect or
universal-desktop guarantee. No runtime installation beyond the one executable.
