# clipx v0.1.1

Native macOS support and broader desktop/server architecture coverage.

- Intel macOS: atomic no-overwrite file/directory finalization through Darwin's
  exclusive rename, using the existing rustix safe wrapper.
- Correct Unix dependency declaration for secure O_NOFOLLOW file access on macOS.
- Native Intel and Apple Silicon macOS jobs exercise real clipboard text/images/
  file lists, terminal confirmation and killed-receiver transfer recovery.
- Linux ARM64 musl joins Linux x64 GNU/musl and Windows x64.
- macOS packages are checked for their intended CPU and system-only dylibs;
  Linux musl binaries for static linkage; Windows for system-only DLL imports.
- Protocol clipx/2 and RAM-only peer trust remain unchanged.

## Choose your download

- Windows x64: x86_64-pc-windows-msvc.zip
- Linux x64 portable/static: x86_64-unknown-linux-musl.tar.gz
- Linux x64 GNU: x86_64-unknown-linux-gnu.tar.gz
- Linux ARM64 portable/static: aarch64-unknown-linux-musl.tar.gz
- Intel Mac, including 2017 MacBook Pro: x86_64-apple-darwin.tar.gz
- Apple Silicon Mac: aarch64-apple-darwin.tar.gz

Archive filenames begin with clipx-. Verify SHA256SUMS.txt, extract, and place
only the executable on PATH. On Linux/macOS ~/.local/bin is suitable; Windows
users choose an existing PATH directory. No Homebrew, Rust or Python runtime.
There is no daemon, automatic shell configuration, or persistent trust store.

macOS deployment targets are10.13(Intel) and11.0(ARM64); native CI runs macOS15.
Deployment targets do not constitute testing on every older OS or physical Mac.
macOS/Windows packages are unsigned; macOS packages are not notarized. Review
trusted downloads with the normal OS security UI, not global security bypasses.
Clipboard use needs a graphical session; use explicit inputs and --headless
for servers/SSH. Windows ARM64,32-bit/mobile systems are not native targets.

A platform is qualified only by this release commit's successful CI results.
No claim of universal-device support or an independent security audit is made.
