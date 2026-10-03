# Security model — stateless sessions

clipx is an explicit-push utility for trusted personal computers. An approved
session can create files in Downloads and replace clipboard contents. It cannot
execute received files, overwrite existing output, install services or change
firewall settings. Run it as your normal user.

TLS 1.3 is enforced on QUIC and TCP (ALPN clipx/2, no 0-RTT). Self-signed
certificate keys are ephemeral, kept only in process memory. TLS CertificateVerify
signatures are checked with rustls/ring, but no persistent pin, WebPKI hostname
or CA identity validation is claimed. The provisional TLS connection carries
only bounded greeting and approval messages before application authorization.

Both computers display a full 256-bit grouped hexadecimal code derived from
both certificate fingerprints, a fresh receiver nonce and the connection's TLS
exporter. Compare the ENTIRE code over an independent trusted channel and type
y on both ends. A man-in-the-middle terminates different TLS sessions and produces
different codes. Device names are untrusted, escaped display metadata. Each process remembers mutually approved certificate fingerprints only in RAM.
Reconnects proving possession of those same keys reuse local approval; changed
keys or a restarted process require new approval. Decline, EOF, invalid messages and timeout fail closed.
Concurrent interactive prompts are rejected. A cancelled prompt stops its input
reader, restores terminal raw/cursor state, and releases the next prompt without
requiring a stale Enter. Terminal events use cancellable Crossterm polling;
Dialoguer renders confirmation. Buffered type-ahead is drained and bracketed
paste ignored before accepting a fresh physical Y/N key. No terminal means a
fail-closed error unless explicit --yes is used.

`--yes` deliberately waives LOCAL manual identity verification for this process.
The other endpoint still independently decides. Both `--yes` means encryption
without human-authenticated identity: active interception is not excluded.
`recv --yes` automatically accepts new incoming sessions while running, including
unwanted senders that can reach its port. Restrict binding and existing firewall/
tailnet ACLs. The tool does not modify those security settings. No trust decision
is written to disk; approved certificate identities expire when the process exits. There is no safety bypass hidden in a config or environment variable.

Sender writes no identity/config/cache/spool. Receiver checkpoints exist only as
private `.clipx-part-UUID` directories inside Downloads. They contain payloads,
manifests and hashes, not keys or fingerprints, and are removed after success.
Interrupted checkpoints may contain sensitive clipboard data; finish the transfer
or explicitly clean old inactive checkpoints. OS paging/core dumps are outside
the program's no-application-persistence guarantee.

Incoming paths reject traversal, absolute/drive/UNC paths, NUL, alternate
separators, reserved Windows names and missing parents. Symlinks/special-file
input is rejected. Partial files use numeric names. Existing output is never
deleted: commit uses atomic no-replace operations and collision suffixes.
Do not share Downloads staging with untrusted local users. A same-user/root
adversary is out of scope because it already controls the process and files.

File chunks, zstd output, control frames, manifests, worker streams and connection
counts are bounded. Every chunk and complete file is hashed. Resume journals are
revalidated, and the sender checks the receiver's prefix hash before reusing bytes.
Same metadata is not treated as proof of same content. Clipboard APIs and image
decoding can use substantial memory; malicious approved senders can exhaust
memory/disk with valid transfers. Use only trusted peers and OS quotas as needed.

No clipboard watcher/history is installed. Explicit send transfers what you
copied, possibly secrets; inspect before sending. Successful receipts are removed,
so no long-term exactly-once guarantee exists. A crash at completion may cause a
suffixed duplicate on a later fresh send; it never justifies overwriting data.
Multiple selected roots are not a single atomic transaction.

This new implementation has not had an independent security audit. Report issues
privately using the repository owner's GitHub profile contact, without posting
credentials or payloads in public issues.
