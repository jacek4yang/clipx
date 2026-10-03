# Security model

clipx is an explicit-push tool for mutually trusted personal computers, normally
inside a tailnet. A trusted peer is authorized to write new files in Downloads
and replace clipboard contents when the receiver is running. Do not trust devices
whose users/programs you do not trust. Tailnet membership alone is not sufficient.

TLS 1.3 is enforced by rustls on QUIC and TCP, with `clipx/1` ALPN. Certificate
fingerprints are BLAKE3 over DER certificate bytes, pinned exactly in the local
trust store. TLS CertificateVerify signatures are validated using rustls/ring;
no normal sending path accepts arbitrary server certificates. Certificate pinning
uses explicit identity rather than WebPKI hostname or CA validation. Self-signed
certificates are persistent, and fingerprint changes fail closed.

An explicit pair probe can inspect an unpinned certificate while verifying key
possession. This does not establish identity by itself: verify the displayed
fingerprint independently. Pair probes transfer no payload and grant no receiver
trust automatically. The optional receiver pairing mode permits only this limited
probe for unknown identities. Never enable it as a substitute for verification.

Private identity material lives under the standard per-user config directory;
Unix directories are 0700 and atomically written identity files are 0600.
Windows relies on the current user's application-data ACL. Keep your config
private, especially when overriding its location. No secret is logged. Rotating
identity requires removing old fingerprints on each peer and pairing again.

Incoming paths are validated component by component: no parent/absolute/drive/
UNC paths, NUL, alternate separators, Windows devices or trailing dot/space
components. Case-folded duplicate paths and missing parents are rejected.
Symlink/special-file input is rejected. Receiver staging contains no peer-created
symlinks. New output is committed with OS-level atomic no-replace operations;
existing destination files are never deleted. The local same-user/root adversary
is outside the threat model: it already controls the process, Downloads and keys.
Do not share clipx's private staging/config directories with untrusted users.

Chunk lengths, control size, metadata count, worker streams and connections are
bounded. Zstd decompression is given a bounded output capacity. Clipboard APIs
and decoded images can require substantial memory; only authorize peers you trust
to replace your clipboard. File transfer memory is bounded independently of file
size. TLS does not replace storage verification: every chunk and complete file
is hashed, and resume journals are checked against bytes before use.

There is no watcher or clipboard history. The explicit `send` action may transfer
whatever you most recently copied, including secrets; inspect it before sending.
Interrupted clipboard transfers keep private local spool data for resume. Successful
transfers delete that spool; headless/fallback outputs intentionally remain as files.

Receipts suppress duplicate output after an ACK is lost. Receipt expiry or removal
ends this deduplication window. Cross-root commits are not transactional. This
version does not defend against a malicious authorized peer exhausting disk by
sending multiple individually valid transfers; use OS quotas and least-privilege
trust/bind settings where needed.

Report vulnerabilities privately through the repository owner's GitHub profile
contact channel. Do not include credentials or private payloads in public issues.
This initial implementation has not undergone an independent security audit.
