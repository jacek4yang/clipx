# Validation record

Updated during implementation; final evidence is the exact commit's GitHub Actions run.

Local environment: Debian 13 x86-64, Rust 1.99.0. Initial suites passed real
loopback QUIC and TCP/TLS transfers, automatic fallback, verified-prefix transfer
recovery from TCP to QUIC, headless text/image-byte delivery, zero-byte files,
many small files, nested Unicode trees, duplicate names/receipts, untrusted and
changed certificates, path traversal, corrupted journal revalidation and cleanup
locking. This is not a claim of real 100 GB or physical Windows/Mint acceptance.

The GUI-independent image-byte test is separate from clipboard_graphical, which
requires a real clipboard session. GitHub CI explicitly runs the graphical test
under Xvfb and a Windows runner desktop, and failures block releases.

No invented throughput figures. Use tools/benchmark.py on an isolated local
receiver to measure your own machine/network. Re-run with both transports and
compression modes. A tailnet's throughput and interruption behavior depend on
network, disk and CPU; loopback is not a WAN benchmark.
