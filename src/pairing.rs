//! Process-local peer approval. Verified certificate pins live only in RAM.
use crate::{
    identity::Identity,
    protocol::{self, Msg},
    transport::{self, Wire},
};
use anyhow::{Result, bail};
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Approval {
    pub interactive: bool,
    busy: Arc<AtomicBool>,
    trusted: Arc<Mutex<HashSet<String>>>,
    interrupted: Arc<tokio::sync::Notify>,
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
            trusted: Arc::new(Mutex::new(HashSet::new())),
            interrupted: Arc::new(tokio::sync::Notify::new()),
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
        Self::new(true)
    }
    pub async fn interrupted(&self) {
        self.interrupted.notified().await;
    }
    pub fn remember(&self, fingerprint: &str) {
        if !self.automatic {
            self.trusted
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(fingerprint.into());
        }
    }
    pub fn knows(&self, fingerprint: &str) -> bool {
        self.trusted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(fingerprint)
    }
    #[cfg(test)]
    pub fn testing(answer: bool) -> Self {
        let mut s = Self::new(false);
        s.test_answer = Some(answer);
        s
    }
    pub async fn confirm(&self, code: &str, peer: &str, fingerprint: &str) -> Result<bool> {
        #[cfg(test)]
        if let Some(answer) = self.test_answer {
            return Ok(answer);
        }
        if self.automatic {
            eprintln!("Pairing fingerprint: {code}\nPeer: {peer:?}");
            eprintln!("WARNING: --yes skips local verification for this process.");
            return Ok(true);
        }
        if self.knows(fingerprint) {
            eprintln!("Pairing fingerprint: {code}\nPeer: {peer:?}");
            eprintln!("✓ 已在当前进程核对 / Verified earlier in this process; waiting for peer.");
            return Ok(true);
        }
        crate::prompt::banner(code, peer);
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
        let _busy = Busy(self.busy.clone());
        let (_running, rx) = crate::prompt::start(self.interrupted.clone());
        rx.await?
    }
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
pub async fn exchange(
    w: &mut Wire,
    approval: &Approval,
    code: &str,
    peer: &str,
    fingerprint: &str,
) -> Result<bool> {
    let local = approval.confirm(code, peer, fingerprint);
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
        decision=&mut remote=>{if !decision?{eprintln!("Other computer declined this session.");return Ok(false);}let accept=local.await?;protocol::write(&mut *w.w,&Msg::PairDecision{accept}).await?;Ok(accept)},
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
        &s.fingerprint,
    )
    .await?
    {
        bail!("session declined; nothing saved or transferred");
    }
    if !matches!(s.ctrl.recv().await?, Msg::SessionApproved) {
        bail!("receiver did not approve this session");
    }
    s.ctrl.send(&Msg::Ack).await?;
    approval.remember(&s.fingerprint);
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
    #[tokio::test]
    async fn trust_is_process_local_and_key_specific() {
        let approval = super::Approval::new(false);
        assert!(approval.confirm("code", "peer", "a").await.is_err());
        approval.remember("a");
        assert!(approval.confirm("code", "peer", "a").await.unwrap());
        assert!(approval.confirm("code", "peer", "b").await.is_err());
        assert!(!super::Approval::new(false).knows("a"));
        let auto = super::Approval::automatic();
        auto.remember("a");
        assert!(!auto.knows("a"));
    }
}
