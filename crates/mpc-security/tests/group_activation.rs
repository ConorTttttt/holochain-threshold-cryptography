use holochain_mpc_core::{commitment,SessionSpec};
use holochain_mpc_security::activation::{GroupDescriptor,GroupActivation,SigningIntent,SigningProfile,IntentApprovals,PinnedKeyChain};
type T=Result<(),Box<dyn std::error::Error>>;
fn descriptor()->GroupDescriptor {
    let members=vec![vec![1;39],vec![2;39],vec![3;39]];
    GroupDescriptor{proposal_action:vec![6;39],epoch:0,
        spec:SessionSpec{session_id:commitment("session",b"test"),application_id:"test".into(),
            protocol_id:"frost-ed25519".into(),protocol_version:1,
            context_hash:commitment("context",b"test"),participants:members.clone(),
            threshold:2,max_round:6},
        dkg_transcript_hash:commitment("dkg",b"transcript"),
        public_key_package_hash:commitment("group",b"package"),
        group_verifying_key:vec![7;32],encryption_key_binding_actions:vec![vec![8;39],vec![9;39],vec![10;39]]}
}
#[test]
fn full_group_confirmation_required_and_mismatched_party_fails_closed()->T{
    let d=descriptor();let mut a=GroupActivation::new(d.clone())?;
    let h=d.digest()?;
    a.attest(&d.spec.participants[0],h)?;
    a.attest(&d.spec.participants[1],h)?;
    assert!(a.finalize().is_err());
    let mut b=GroupActivation::new(d.clone())?;
    assert!(b.attest(&[42;39],h).is_err());
    assert!(b.attest(&d.spec.participants[0],[5;32]).is_err());
    assert!(b.finalize().is_err());
    let mut c=GroupActivation::new(d.clone())?;
    for member in &d.spec.participants { c.attest(member,h)?; }
    assert_eq!(c.finalize()?.digest(),h);
    Ok(())
}
#[test]
fn signing_intent_requires_exact_selected_signers_and_approval()->T {
    let d=descriptor();let mut c=GroupActivation::new(d.clone())?;
    for p in &d.spec.participants { c.attest(p,d.digest()?)?; }
    let active=c.finalize()?;
    let roster=d.spec.participants[..2].to_vec();
    let intent=SigningIntent::new(&active,commitment("op",b"1"),b"invoice 1",roster.clone(),SigningProfile::ContextBoundV1)?;
    let mut gate=IntentApprovals::new(intent.clone());
    gate.approve(&roster[0],intent.digest()?)?;
    assert!(gate.finalize().is_err());
    let mut gate=IntentApprovals::new(intent.clone());
    assert!(gate.approve(&d.spec.participants[2],intent.digest()?).is_err());
    for member in &roster { gate.approve(member,intent.digest()?)?; }
    assert_eq!(gate.finalize()?.intent(),&intent);
    assert!(SigningIntent::new(&active,commitment("op",b"1"),b"invoice 1",vec![roster[0].clone(),roster[0].clone()],SigningProfile::ContextBoundV1).is_err());
    Ok(())
}
#[test]
fn key_rotation_cannot_downgrade_switch_member_or_reuse_parent()->T {
    let chain=PinnedKeyChain{member:vec![1;39],epoch:0,binding_action:vec![2;39],public_key:[3;32]};
    assert!(chain.rotate(&[9;39],&[2;39],1,vec![5;39],[4;32]).is_err());
    assert!(chain.rotate(&[1;39],&[2;39],0,vec![5;39],[4;32]).is_err());
    let next=chain.rotate(&[1;39],&[2;39],1,vec![5;39],[4;32])?;
    assert!(next.rotate(&[1;39],&[2;39],2,vec![6;39],[5;32]).is_err());
    Ok(())
}
