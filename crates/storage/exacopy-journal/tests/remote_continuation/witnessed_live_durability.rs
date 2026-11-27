use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadDestination, RemoteDownloadError, RemoteDownloadOwnerRecord,
};

use super::{FRESH, FrameKind as Kind, LinuxFileIdentity, Transcript, boundary_of, recorded, scan};

#[test]
fn outbound_live_durability_matches_independent_bytes_and_refuses_non_live_cuts() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let published = recorded("published");
	let observed = boundary_of(&published, Kind::PublishObserved);
	let observed_end = usize::try_from(observed.offset).unwrap();
	let durable = boundary_of(&published, Kind::DurabilityRecorded);
	let durable_end = usize::try_from(durable.offset).unwrap();
	let prior = scan(&run, &published[..observed_end], FRESH);
	let witness = prior.witness().unwrap();
	let target = witness.binding().stage();
	let wrong_target = LinuxFileIdentity::new(target.device(), target.inode() + 1);
	let proposal = prior
		.prepare_live_durability(&trust, witness, target)
		.unwrap();
	assert_eq!(proposal.kind(), Kind::DurabilityRecorded);
	assert_eq!(proposal.previous(), observed);
	assert_eq!(proposal.successor(), durable);
	assert_eq!(proposal.encoded(), &published[observed_end..durable_end]);

	let exact = scan(&run, &published[..durable_end], FRESH);
	assert!(proposal.confirms_live_durability(&exact, witness, target));
	assert!(!proposal.confirms_live_durability(&exact, witness, wrong_target));
	assert!(
		exact
			.prepare_live_durability(&trust, witness, target)
			.is_err()
	);
	let torn = scan(&run, &published[..durable_end - 1], FRESH);
	assert_eq!(torn.boundary(), observed);
	assert!(!proposal.confirms_live_durability(&torn, witness, target));
	assert!(
		torn.prepare_live_durability(&trust, witness, target)
			.is_err()
	);
	let trailing = scan(&run, &published[..durable_end + 1], FRESH);
	assert_eq!(trailing.boundary(), durable);
	assert!(!proposal.confirms_live_durability(&trailing, witness, target));
	assert!(
		prior
			.prepare_live_durability(&trust, witness, wrong_target)
			.is_err()
	);

	let alternate = recorded("archived-expired-consent");
	let other_witness = scan(&run, alternate.as_slice(), FRESH).witness().unwrap();
	assert!(!proposal.confirms_live_durability(&exact, other_witness, target));
	assert!(
		prior
			.prepare_live_durability(&trust, other_witness, target)
			.is_err()
	);
	for alternative in ["recovered", "conflict", "uncertain"] {
		let bytes = recorded(alternative);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert!(
			replay
				.prepare_live_durability(&trust, witness, target)
				.is_err()
		);
	}

	let intent = usize::try_from(boundary_of(&published, Kind::PublishIntent).offset).unwrap();
	assert!(
		scan(&run, &published[..intent], FRESH)
			.prepare_live_durability(&trust, witness, target)
			.is_err()
	);
	let mut changed = run.fixture.owner.manifest().clone();
	changed.scope.destination = RemoteDownloadDestination::new(
		changed.scope.destination.root(),
		changed.scope.destination.parent(),
		UnixComponent::new(b"other-target").unwrap(),
	);
	let alternate_owner = RemoteDownloadOwnerRecord::sign(changed, &run.fixture.key).unwrap();
	let alternate_trust = RemoteBootstrapTrust::new(
		&alternate_owner,
		run.fixture.owner.manifest().profile,
		&run.fixture.verify,
	)
	.unwrap();
	assert!(matches!(
		prior.prepare_live_durability(&alternate_trust, witness, target),
		Err(RemoteDownloadError::Binding),
	));
}
