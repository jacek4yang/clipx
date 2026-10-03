# clipx/2 wire protocol

TLS 1.3, mutual ephemeral certificate key-possession proof, no 0-RTT. ALPN
clipx/2 intentionally rejects RC1. QUIC uses one control and up to four worker
bi-streams; TCP uses one sequential framed TLS stream.

Frames are a 4-byte big-endian unsigned length and tagged snake_case JSON.
Zero or >65536 lengths are rejected before allocation. Chunk bytes follow their
control frame directly, never base64/JSON. Both logical and encoded chunks are
bounded to 1 MiB; zstd window/output bounds apply.

1. Hello(version=2, device/name metadata, pair, chunk=1048576).
2. Ready(version=2, device/name, chunk, pairing_confirmation=true, session_nonce).
   Names/IDs are bounded, nonce is a fresh UUID. No file metadata is sent yet.
3. The selected connection alone receives PairStart (auto transport losers close).
4. Each side derives the same session code from both certificate fingerprints,
   nonce and TLS exporter label EXPORTER-clipx-session. Each sends PairDecision
   after explicit local y, or explicit per-process --yes. Both must accept.
   Receiver sends SessionApproved; sender Ack. No persisted trust results.
5. Offer(UUID, kind, count, total), then count Entry(path,size,directory,mtime/ns).
   Receiver validates paths, counts, metadata and free space, locks a checkpoint,
   then Accept(workers), or earlier Complete if this checkpoint already committed.
6. Worker File(index) -> Resume(offset, prefix BLAKE3). Stored journaled chunks
   are checked against bytes. Sender reconstructs its prefix hash and compares.
   On mismatch, RestartFile -> Ack truncates this file/journal before new chunks.
   Only one worker may own an index and restart is allowed only before new chunks.
7. Chunk(offset,logical,encoded,compressed,hash) + bytes -> Ack after verification
   and append. ACK permits progress, not a durability claim. Every eighth chunk
   syncs; reconnect revalidates even acknowledged bytes after power loss.
8. FileDone(full-file BLAKE3) -> Ack only after complete size/hash/fsync checks.
9. WorkerDone, then Finish. Receiver requires all files verified, journals commit
   intent, performs no-replace output/clipboard delivery, writes checkpoint receipt.
10. Bounded Paths pages then Complete -> Ack. Receiver removes checkpoint -> Cleaned
    -> final Ack. Once Complete is received, cleanup-channel failure is only a
    warning; it must not trigger retransmission of already committed data.

Busy frames provide keepalive during cancellable prefix hashing. Invalid states
fail closed. New physical connections require fresh approval. Same-process retries
reuse operation UUID; fresh-process sends may adopt matching unfinished manifests,
but validate content prefixes independently. No identity binding is persisted.
Successful checkpoint removal ends deduplication. A later new send after an
ambiguous crash may create a suffixed copy. Finalization journaling recovers a
known checkpoint's intended no-replace renames, not arbitrary old deliveries.
