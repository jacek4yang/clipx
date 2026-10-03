//! Dialoguer renders the prompt; Crossterm supplies cancellable native terminal events.
use anyhow::{Result, bail};
use console::{Key, Term, style};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Running {
    cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
struct Restore(Term);
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stderr(), event::DisableBracketedPaste);
        let _ = terminal::disable_raw_mode();
        let _ = self.0.show_cursor();
        let _ = self.0.write_line("");
    }
}
pub fn start(
    interrupted: Arc<tokio::sync::Notify>,
) -> (Running, tokio::sync::oneshot::Receiver<Result<bool>>) {
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let _ = tx.send(confirm(flag, interrupted));
    });
    (
        Running {
            cancel,
            thread: Some(thread),
        },
        rx,
    )
}
fn confirm(cancel: Arc<AtomicBool>, interrupted: Arc<tokio::sync::Notify>) -> Result<bool> {
    let term = Term::stderr();
    if !term.is_term() {
        bail!(
            "confirmation needs an interactive terminal; use --yes explicitly for unattended input"
        );
    }
    terminal::enable_raw_mode()?;
    let _restore = Restore(term.clone());
    crossterm::execute!(std::io::stderr(), event::EnableBracketedPaste)?;
    while event::poll(Duration::ZERO)? {
        let _ = event::read()?;
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    let theme = dialoguer::theme::ColorfulTheme::default();
    let answer = dialoguer::Confirm::with_theme(&theme)
        .with_prompt("Fingerprints match? / 指纹一致，允许传输？")
        .default(false)
        .wait_for_newline(false)
        .interact_on_with_reader(&term, true, || {
            loop {
                if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "confirmation cancelled or timed out",
                    ));
                }
                if !event::poll(Duration::from_millis(50))? {
                    continue;
                }
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
                        interrupted.notify_one();
                        return Ok(Key::Escape);
                    }
                    return Ok(match k.code {
                        KeyCode::Char(c) => Key::Char(c),
                        KeyCode::Enter => Key::Enter,
                        KeyCode::Esc => Key::Escape,
                        _ => Key::Unknown,
                    });
                }
            }
        })?;
    Ok(answer.unwrap_or(false))
}
pub fn banner(code: &str, peer: &str) {
    let term = Term::stderr();
    if term.is_term() {
        eprintln!(
            "\n{}",
            style("── clipx · 核对本次连接 / Verify connection ──")
                .cyan()
                .bold()
        );
        eprintln!("  对方 / Peer: {peer:?}");
        // Keep a plain machine-readable line too; never hide or truncate the actual code.
        eprintln!("Pairing fingerprint: {code}");
        eprintln!(
            "  {}",
            style("核对两端完整指纹 · Compare the full code on both computers").bold()
        );
        eprintln!("  Y 允许 / accept · N / Enter 拒绝 / decline · Esc 取消 · Ctrl+C 退出");
    } else {
        eprintln!("\nPairing fingerprint: {code}\nPeer name (not verified): {peer:?}");
    }
}
