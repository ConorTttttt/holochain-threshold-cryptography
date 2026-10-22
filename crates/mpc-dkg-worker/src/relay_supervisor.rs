//! v0.4.0 Phase 4: bounded, fail-closed polling supervisor.
//!
//! No reconnect/retry of ambiguous signed calls, nor continuation of an
//! interrupted FROST ceremony. The durable worker journal makes an already
//! admitted proposal unusable after exit; a fresh proposal is required.
use crate::relay::{LocalDkgNode, MpcTransport, Phase, RelayEngine, TickReport};
use std::future::Future;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollPolicy {
    pub interval: Duration,
    pub rpc_deadline: Duration,
    pub max_polls: u32,
}

impl PollPolicy {
    pub fn validate(self) -> Result<(), String> {
        if !(100..=30_000).contains(&(self.interval.as_millis() as u64)) ||
           !(1000..=120_000).contains(&(self.rpc_deadline.as_millis() as u64)) ||
           self.max_polls == 0 || self.max_polls > 100_000 {
            return Err("relay polling bounds are invalid".into());
        }
        Ok(())
    }
}

#[allow(async_fn_in_trait)]
pub trait RelayTicks {
    fn phase(&self) -> Phase;
    async fn start(&mut self) -> Result<TickReport, String>;
    async fn poll_once(&mut self) -> Result<TickReport, String>;
}

impl<N: LocalDkgNode, T: MpcTransport> RelayTicks for RelayEngine<N, T> {
    fn phase(&self) -> Phase { RelayEngine::phase(self) }
    async fn start(&mut self) -> Result<TickReport, String> { RelayEngine::start(self).await }
    async fn poll_once(&mut self) -> Result<TickReport, String> { RelayEngine::poll_once(self).await }
}

/// Shutdown, signed-RPC uncertainty, poll timeout, or deadline exhaustion all
/// terminate this process's ceremony. The caller must DROP the worker bridge,
/// not retry its old proposal. A Completed result is the only success state.
pub async fn supervise<R, F>(relay: &mut R, policy: PollPolicy, shutdown: F) -> Result<(), String>
where R: RelayTicks, F: Future<Output=()> {
    policy.validate()?;
    if relay.phase() != Phase::New { return Err("cannot supervise previously started relay".into()); }
    let mut shutdown = Box::pin(shutdown);
    let began = tokio::select! {
        biased;
        _ = &mut shutdown => return Err("relay was stopped before DKG admission".into()),
        outcome = tokio::time::timeout(policy.rpc_deadline, relay.start()) =>
            outcome.map_err(|_| "DKG start deadline exceeded; ceremony must abort".to_owned())?,
    }?;
    if began.phase == Phase::Complete { return Ok(()); }
    for _ in 0..policy.max_polls {
        if relay.phase() == Phase::Complete { return Ok(()); }
        if relay.phase() == Phase::Aborted { return Err("worker reported aborted ceremony".into()); }
        tokio::select! {
            biased;
            _ = &mut shutdown => return Err("relay shutdown; do not resume this DKG proposal".into()),
            _ = tokio::time::sleep(policy.interval) => {},
        }
        let report = tokio::select! {
            biased;
            _ = &mut shutdown => return Err("relay shutdown while polling; do not resume".into()),
            outcome = tokio::time::timeout(policy.rpc_deadline, relay.poll_once()) =>
                outcome.map_err(|_| "DKG polling deadline exceeded; do not retry RPC".to_owned())?,
        }?;
        match report.phase {
            Phase::Complete => return Ok(()),
            Phase::Aborted | Phase::New => return Err("unexpected relay phase after poll".into()),
            _ => {},
        }
    }
    Err("DKG did not complete within bounded poll budget; do not restart proposal".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    struct Dummy {
        phase: Phase, starts: Arc<AtomicUsize>, polls: usize,
        complete_after: usize, fail_at: Option<usize>, stall: bool,
    }
    impl Dummy {
        fn new() -> Self { Self { phase: Phase::New, starts: Arc::new(AtomicUsize::new(0)),
            polls:0, complete_after:1, fail_at:None, stall:false } }
    }
    impl RelayTicks for Dummy {
        fn phase(&self) -> Phase { self.phase }
        async fn start(&mut self) -> Result<TickReport, String> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            self.phase=Phase::Echo;
            Ok(TickReport{ phase:self.phase, published:2, delivered:0 })
        }
        async fn poll_once(&mut self) -> Result<TickReport, String> {
            if self.stall { tokio::time::sleep(Duration::from_secs(5)).await; }
            self.polls+=1;
            if self.fail_at==Some(self.polls) { self.phase=Phase::Aborted; return Err("uncertain RPC".into()); }
            if self.polls>=self.complete_after { self.phase=Phase::Complete; }
            Ok(TickReport{ phase:self.phase, published:0, delivered:0 })
        }
    }
    fn policy() -> PollPolicy { PollPolicy { interval:Duration::from_millis(100),
        rpc_deadline:Duration::from_millis(1000), max_polls:3 } }
    #[tokio::test]
    async fn completes_once_without_duplicate_start() {
        let mut d=Dummy::new();
        supervise(&mut d,policy(),std::future::pending()).await.unwrap();
        assert_eq!(d.starts.load(Ordering::SeqCst),1);
        assert_eq!(d.polls,1);
        assert!(supervise(&mut d,policy(),std::future::pending()).await.is_err());
    }
    #[tokio::test]
    async fn cancelled_before_start_never_admits_worker() {
        let mut d=Dummy::new();
        assert!(supervise(&mut d,policy(),std::future::ready(())).await.is_err());
        assert_eq!(d.starts.load(Ordering::SeqCst),0);
    }
    #[tokio::test]
    async fn does_not_retry_uncertain_or_timeout_calls() {
        let mut d=Dummy::new();d.fail_at=Some(1);
        assert!(supervise(&mut d,policy(),std::future::pending()).await.is_err());
        assert_eq!(d.polls,1);
        let mut d=Dummy::new();d.stall=true;
        assert!(supervise(&mut d,policy(),std::future::pending()).await.is_err());
        assert_eq!(d.starts.load(Ordering::SeqCst),1);
        assert_eq!(d.polls,0);
    }
    #[tokio::test]
    async fn polling_budget_is_a_terminal_error() {
        let mut d=Dummy::new();d.complete_after=usize::MAX;
        assert!(supervise(&mut d,policy(),std::future::pending()).await.is_err());
        assert_eq!(d.polls,3);
        let mut bad=policy();bad.max_polls=0;
        let mut d=Dummy::new();
        assert!(supervise(&mut d,bad,std::future::pending()).await.is_err());
        assert_eq!(d.starts.load(Ordering::SeqCst),0);
    }
}
