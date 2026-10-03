# clipx v0.1.0-rc.2

Stateless, one-time-confirmed transfer workflow. Upgrade BOTH ends: protocol v2
is intentionally incompatible with rc.1.

- `clipx recv` and `clipx send IP`: compare the same fresh session fingerprint,
  type y on both computers. Codes bind the ephemeral TLS session, not saved trust.
- Optional `recv --yes` / `send --yes IP` waive only that side's local prompt.
  Use trusted networks; unattended receivers accept reachable incoming senders.
- No config, saved identity/private key, trust list, aliases or sender disk cache.
- Only Downloads output and necessary private resumable checkpoints; successful
  acknowledged delivery removes checkpoints. Repeat unchanged commands to resume.
- QUIC/TCP TLS 1.3, bounded streaming/zstd, chunk/full-file checks, prefix validation,
  restart-safe no-overwrite commit and explicit cleanup-completion handshake.
- Windows x64 static CRT, Linux x64 musl static and GNU alternatives. Copy just
  the binary into PATH; licenses remain embedded. No services or firewall changes.

Candidate release: no independent security audit, no universal-platform claim.
Windows binaries are unsigned; Wayland requires supported data-control protocols.
Clipboard payloads use RAM; files stream. No durable delivery history means an
ambiguous completion crash may yield a suffixed duplicate on a later new send.
See README and SECURITY.md for exact semantics and limits.
