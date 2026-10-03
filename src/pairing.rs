//! One-time session approval. No identity or trust is persisted.
use crate::{
    identity::Identity,
    protocol::{self, Msg},
    transport::{self, Wire},
};
use anyhow::{Result, bail};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Approval {
    pub interactive: bool,
    busy: Arc<AtomicBool>,
    terminal: bool,
    automatic: bool,
    #[cfg(test)]
    test_answer: Option<bool>,
}
struct Busy(Arc<AtomicBool>);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Approval {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            busy: Arc::new(AtomicBool::new(false)),
            terminal: false,
            automatic: false,
            #[cfg(test)]
            test_answer: None,
        }
    }
    pub fn automatic() -> Self {
        let mut s = Self::new(false);
        s.automatic = true;
        s
    }
    pub fn terminal() -> Self {
        let mut s = Self::new(true);
        s.terminal = true;
        s
    }
    #[cfg(test)]
    pub fn testing(answer: bool) -> Self {
        let mut s = Self::new(false);
        s.test_answer = Some(answer);
        s
    }
    pub async fn confirm(&self, code: &str, peer: &str) -> Result<bool> {
        #[cfg(test)]
        if let Some(answer) = self.test_answer {
            return Ok(answer);
        }
        if self.automatic {
            eprintln!(
                "\nPairing fingerprint: {code}\nPeer name (not verified): {peer:?}\nWARNING: --yes accepts this session without local identity verification."
            );
            return Ok(true);
        }
        if !self.interactive {
            bail!("confirmation input is unavailable; run send/recv in terminals");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            bail!("another pairing prompt is waiting; finish or clear that prompt before retrying");
        }
        let busy = Busy(self.busy.clone());
        eprintln!(
            "\nPairing fingerprint: {code}\nPeer name (not yet trusted): {peer:?}\nCompare the ENTIRE identical fingerprint on the other computer."
        );
        eprintln!("Allow this transfer only? [y/N]");
        io::stderr().flush()?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        // A detached input thread does not keep the runtime alive on Ctrl+C.
        // If the peer cancels, the gate remains held until this pending line is cleared.
        let terminal = self.terminal;
        std::thread::spawn(move || {
            let _busy = busy;
            let mut line = String::new();
            let result = if terminal {
                use std::io::BufRead;
                #[cfg(windows)]
                let path = "CONIN$";
                #[cfg(not(windows))]
                let path = "/dev/tty";
                std::fs::File::open(path)
                    .and_then(|f| std::io::BufReader::new(f).read_line(&mut line))
                    .map(|_| accepted(&line))
            } else {
                io::stdin().read_line(&mut line).map(|_| accepted(&line))
            };
            let _ = tx.send(result);
        });
        match tokio::time::timeout(Duration::from_secs(300), rx).await {
            Ok(result) => Ok(result??),
            Err(_) => bail!("pairing prompt timed out; press Enter to clear it before retrying"),
        }
    }
}
pub fn accepted(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
pub fn code(a: &str, b: &str) -> String {
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    let h = blake3::hash(format!("clipx mutual pairing v1\0{a}\0{b}").as_bytes())
        .to_hex()
        .to_string();
    h.as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
pub async fn exchange(w: &mut Wire, approval: &Approval, code: &str, peer: &str) -> Result<bool> {
    let local = approval.confirm(code, peer);
    let remote = async {
        let m: Msg =
            tokio::time::timeout(Duration::from_secs(300), protocol::read(&mut *w.r)).await??;
        match m {
            Msg::PairDecision { accept } => Ok::<bool, anyhow::Error>(accept),
            _ => bail!("expected pairing decision"),
        }
    };
    tokio::pin!(local);
    tokio::pin!(remote);
    // Keep the same framed read future alive while writing; cancelling a partial read
    // and starting a new one would corrupt framing. An aborted connection is discarded.
    tokio::select! {
        decision=&mut local=>{let accept=decision?;protocol::write(&mut *w.w,&Msg::PairDecision{accept}).await?;if !accept{return Ok(false);}Ok(remote.await?)},
        decision=&mut remote=>{if !decision?{eprintln!("Other computer declined pairing. Clear any pending prompt with Enter.");return Ok(false);}let accept=local.await?;protocol::write(&mut *w.w,&Msg::PairDecision{accept}).await?;Ok(accept)},
    }
}
pub async fn authorize(
    s: &mut transport::Session,
    id: &Identity,
    approval: &Approval,
) -> Result<()> {
    if !s.pairing_confirmation {
        bail!("both computers need clipx 0.1.0-rc.2 or newer");
    }
    s.ctrl.send(&Msg::PairStart).await?;
    if !exchange(
        &mut s.ctrl,
        approval,
        &session_code(&id.fp(), &s.fingerprint, &s.session_nonce, &s.binding),
        &s.peer_name,
    )
    .await?
    {
        bail!("session declined; nothing saved or transferred");
    }
    if !matches!(s.ctrl.recv().await?, Msg::SessionApproved) {
        bail!("receiver did not approve this session");
    }
    s.ctrl.send(&Msg::Ack).await?;
    s.authorized = true;
    Ok(())
}
pub fn session_code(a: &str, b: &str, nonce: &str, binding: &[u8; 32]) -> String {
    code(
        &code(a, b),
        &format!("clipx/2:{nonce}:{}", blake3::hash(binding).to_hex()),
    )
}
#[cfg(test)]
mod tests {
    #[test]
    fn fingerprint_matches_both_directions() {
        assert_eq!(super::code("a", "b"), super::code("b", "a"));
        assert_ne!(super::code("a", "b"), super::code("a", "attacker"));
    }
    #[test]
    fn only_explicit_yes_accepts() {
        for s in ["y", "Y", "yes", " YES\n"] {
            assert!(super::accepted(s));
        }
        for s in ["", "\n", "n", "no", "maybe", "okay"] {
            assert!(!super::accepted(s));
        }
    }
}
