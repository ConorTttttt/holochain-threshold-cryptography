//! Demo mode: the real service over a mock chain and a simulated 2-of-3 group,
//! with a simulated second operator who approves a few seconds after this
//! node. Everything it shows is EXAMPLE DATA, for building and testing UIs.
use crate::chain::Chain;
use crate::engine::*;
use crate::mock_chain::MockChain;
use crate::mock_node::MockNet;
use crate::node::PlanView;
use crate::store::Store;
use crate::util::Clock;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub struct Demo { pub engine: Engine, pub net: Arc<MockNet>, pub chain: Arc<MockChain> }

pub async fn start(data_dir: &Path, clock: Arc<dyn Clock>, remote_delay: Duration) -> Result<Demo, String> {
    let net = MockNet::new();
    let chain = Arc::new(MockChain::new());
    let mut node = net.node(0);
    node.sign_wait = Duration::from_secs(3600);
    let c: Arc<dyn Chain> = chain.clone();
    let engine = Engine::open(Store::open(data_dir)?, vec![c], Arc::new(node), clock,
        EngineConfig { confirm_poll: Duration::from_millis(500), ..EngineConfig::default() })?;
    if engine.list_vaults().is_empty() {
        let v = engine.create_vault("EXAMPLE vault (demo data)", "mock").await.map_err(|e| e.message)?;
        chain.fund(&v.address, 5_000_000_000);
    }
    // The simulated other operator: approves the proposal's other selected signer after a delay.
    let (e, n) = (engine.clone(), net.clone());
    tokio::spawn(async move {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(list) = e.list_proposals(None, None) else { continue };
            for p in list.iter().filter(|p| matches!(p.state, State::Proposed | State::Approved)) {
                let Ok(plan) = e.plan_of(&p.id) else { continue };
                let Ok(view) = PlanView::parse(&plan) else { continue };
                let Some(other) = view.selected.iter().find(|s| **s != n.members[0]) else { continue };
                let Some(idx) = n.members.iter().position(|m| m == other) else { continue };
                if p.signers.iter().any(|s| s.local && s.approved == Some(true)) && seen.insert(p.id.clone()) {
                    let (n2, plan2) = (n.clone(), plan.clone());
                    tokio::spawn(async move { tokio::time::sleep(remote_delay).await; n2.approve_as(idx, &plan2); });
                }
            }
        }
    });
    Ok(Demo { engine, net, chain })
}
