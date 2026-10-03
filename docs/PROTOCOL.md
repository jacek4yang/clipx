# clipx/1 wire protocol

TLS 1.3 with mutual certificate key-possession proof and explicit DER BLAKE3 pins.
ALPN `clipx/1`. No 0-RTT. QUIC: one control bi-stream and 1–4 reusable worker
bi-streams. TCP: control and worker messages sequentially on one TLS stream.

Control frames: 4-byte big-endian unsigned length, followed by serde JSON
internally tagged with `type` (snake_case). Zero/over-65536 length is rejected
before allocation. Binary chunk data follows a Chunk control frame exactly;
it is never encoded into JSON. Max encoded/uncompressed chunk = 1,048,576 bytes.

1. Hello(version=1, device, name, pair, chunk=1048576).
2. Ready(version=1, device, name, chunk). Reject incompatible major/chunk settings.
   Pair ends here without a transfer. The certificate, not Hello names, authenticates.
3. Offer(id UUID, kind files/text/image, count, total), then `count` Entry messages
   (portable relative path, size u64, directory flag, Unix modified seconds).
4. Receiver validates manifest and owner/ID binding, locks transfer, checks space,
   then Accept(workers), or Complete(paths) for an earlier receipt.
5. Worker: File(index) -> Resume(offset). Only one worker may own an index.
6. Chunk(offset, logical, encoded, compressed, hash) + encoded binary bytes -> Ack.
   Receiver requires contiguous correct-size chunks, verifies BLAKE3, writes bytes
   and appends a 32-byte BLAKE3 journal record. An ACK permits network progress;
   it does not claim fsync durability. Resume rechecks bytes and discards torn tails.
7. FileDone(real full-file BLAKE3 hex) -> Ack only after size/hash/fsync verification.
8. WorkerDone on each worker, then Finish on control. Receiver requires every file
   verified, performs clipboard delivery or journaled no-replace commit, and writes
   receipt before Complete(paths). Large result lists use bounded Paths batches
   followed by Complete; sender sends Ack after the final page. Success is already durable.

Any invalid state yields Error(message) or connection termination; it never
commits unverified output. Per-connection limits and timeouts apply. New physical
connections reuse the same UUID/manifest and peer certificate, not TLS session state.
Busy messages reset an idle timer during long, cancellable prefix verification.
Resume is a verified per-file prefix, not arbitrary sparse range claiming. Completed
files may be re-read for integrity reconstruction but need not be retransmitted.

Manifest order is parent-first. Sibling portable paths must be unique after Unicode
lowercasing. Filename mapping happens at the sender; receiver independently rejects
nonportable/malicious names. Data filenames in staging are numeric entry IDs;
peer paths are not used for partial chunk storage.

Finalization records intended destination roots before rename. If a crash occurs
after a no-replace rename, a retry recognizes a missing staged root and the saved
intent rather than producing a second suffixed copy. Receipts retain owner,
manifest digest and resulting paths (not file contents).
