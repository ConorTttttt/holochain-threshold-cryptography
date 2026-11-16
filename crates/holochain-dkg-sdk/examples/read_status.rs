//! Demonstrates the typed facade using a FIXTURE backend, not a conductor.
//! A live read requires the native-holochain feature and an operator signer
//! explicitly authorised to call get_session_status.
use holochain_dkg_sdk::{
    BackendFuture, CeremonyId, CoordinatorSessionStatus, DkgBackend, DkgSdk,
    ParticipantId, SdkConfig,
};
use holochain_mpc_core::SessionSpec;

struct FixtureBackend {
    proposal: CeremonyId,
}
impl DkgBackend for FixtureBackend {
    fn get_session_status(&self, ceremony: CeremonyId)
        -> BackendFuture<'_, CoordinatorSessionStatus> {
        Box::pin(async move {
            if ceremony != self.proposal {
                return Err(holochain_dkg_sdk::SdkError::NotFound);
            }
            Ok(CoordinatorSessionStatus {
                spec: SessionSpec {
                    session_id: [3; 32],
                    application_id: "org.example.dkg".into(),
                    protocol_id: "frost-ed25519".into(),
                    protocol_version: 1,
                    context_hash: [4; 32],
                    participants: vec![vec![1; 39], vec![2; 39], vec![3; 39]],
                    threshold: 2,
                    max_round: 6,
                },
                accepted: vec![vec![1; 39]],
                ready_observed: false,
            })
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local = ParticipantId::try_from(&[1; 39][..])?;
    let ceremony = CeremonyId::try_from(&[9; 39][..])?;
    let sdk = DkgSdk::new(
        SdkConfig::new("org.example.dkg", local)?,
        FixtureBackend { proposal: ceremony },
    )?;
    let status = sdk.group_status(ceremony).await?;
    println!("Observed state: {:?}, acceptances: {} of {}",
        status.state, status.accepted.len(), status.participants.len());
    // No DKG is started by this read; group activation is not inferred.
    Ok(())
}
