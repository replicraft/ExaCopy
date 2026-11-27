use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadDestination, RemoteDownloadError, RemoteDownloadOwnerRecord,
};

use super::{FRESH, FrameKind as Kind, LinuxFileIdentity, Transcript, boundary_of, recorded, scan};

#[test]
fn recovered_observation_matches_independent_record_and_exact_clean_successor() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let recovered = recorded("recovered");
	let intent = boundary_of(&recovered, Kind::PublishIntent);
	let intent_end = usize::try_from(intent.offset).unwrap();
	let observed = boundary_of(&recovered, Kind::PublishObserved);
	let prior = scan(&run, &recovered[..intent_end], FRESH);
	let witness = prior.witness().unwrap();
	let target = witness.binding().stage();
	let proposal = prior
		.prepare_recovered_observation(&trust, witness, target)
		.unwrap();
	assert_eq!(proposal.kind(), Kind::PublishObserved);
	assert_eq!(proposal.previous(), intent);
	assert_eq!(proposal.successor(), observed);
	assert_eq!(proposal.encoded(), &recovered[intent_end..]);

	let exact = scan(&run, recovered.as_slice(), FRESH);
	assert!(proposal.confirms_recovered_observation(&exact, witness, target));
	assert!(!proposal.confirms_live_observation(
		&exact,
		witness,
		super::RemoteWitnessedOutcome::Recovered {
			target,
			witness: witness.boundary().head,
		},
	));
	assert!(
		exact
			.prepare_live_durability(&trust, witness, target)
			.is_err()
	);

	let published = recorded("published");
	let submitted_end = boundary_of(&published, Kind::PublishObserved).offset;
	let submitted = scan(
		&run,
		&published[..usize::try_from(submitted_end).unwrap()],
		FRESH,
	);
	assert!(!proposal.confirms_recovered_observation(&submitted, witness, target));
	let advanced = recorded("recovered-published");
	let advanced = scan(&run, advanced.as_slice(), FRESH);
	assert!(!proposal.confirms_recovered_observation(&advanced, witness, target));

	let torn = scan(&run, &recovered[..recovered.len() - 1], FRESH);
	assert_eq!(torn.boundary(), intent);
	assert!(!proposal.confirms_recovered_observation(&torn, witness, target));
	let mut trailing = recovered;
	trailing.push(0);
	let unclean = scan(&run, trailing.as_slice(), FRESH);
	assert_eq!(unclean.boundary(), observed);
	assert!(!proposal.confirms_recovered_observation(&unclean, witness, target));
}

#[test]
fn recovered_observation_refuses_wrong_phase_owner_witness_and_target() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let recovered = recorded("recovered");
	let intent = boundary_of(&recovered, Kind::PublishIntent);
	let intent_end = usize::try_from(intent.offset).unwrap();
	let metadata = boundary_of(&recovered, Kind::MetadataRecorded);
	let metadata_end = usize::try_from(metadata.offset).unwrap();
	let prior = scan(&run, &recovered[..intent_end], FRESH);
	let witness = prior.witness().unwrap();
	let target = witness.binding().stage();

	for bytes in [
		&recovered[..metadata_end],
		&recovered[..recovered.len() - 1],
		recovered.as_slice(),
	] {
		assert!(
			scan(&run, bytes, FRESH)
				.prepare_recovered_observation(&trust, witness, target)
				.is_err()
		);
	}
	let wrong_target = LinuxFileIdentity::new(target.device(), target.inode() + 1);
	let alternate = recorded("archived-expired-consent");
	let other_witness = scan(&run, alternate.as_slice(), FRESH).witness().unwrap();
	for (witness, target) in [(other_witness, target), (witness, wrong_target)] {
		assert!(matches!(
			prior.prepare_recovered_observation(&trust, witness, target),
			Err(RemoteDownloadError::Binding),
		));
	}

	let mut changed = run.fixture.owner.manifest().clone();
	changed.scope.destination = RemoteDownloadDestination::new(
		changed.scope.destination.root(),
		changed.scope.destination.parent(),
		UnixComponent::new(b"other-target").unwrap(),
	);
	let owner = RemoteDownloadOwnerRecord::sign(changed, &run.fixture.key).unwrap();
	let other_trust = RemoteBootstrapTrust::new(
		&owner,
		run.fixture.owner.manifest().profile,
		&run.fixture.verify,
	)
	.unwrap();
	assert!(matches!(
		prior.prepare_recovered_observation(&other_trust, witness, target),
		Err(RemoteDownloadError::Binding),
	));
}
