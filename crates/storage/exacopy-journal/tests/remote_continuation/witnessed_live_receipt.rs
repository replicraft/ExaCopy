use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadDestination, RemoteDownloadOwnerRecord,
};

use super::{
	FRESH, FrameKind as Kind, LinuxFileIdentity, Phase, Transcript, boundary_of, recorded, scan,
};

#[test]
fn outbound_live_receipt_proposals_match_independent_frames_and_exact_canonical_artifact() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let published = recorded("published");
	let durable = boundary_of(&published, Kind::DurabilityRecorded);
	let ready_cut = boundary_of(&published, Kind::RemoteReceiptReady);
	let committed = boundary_of(&published, Kind::ReceiptCommitted);
	let durable_end = usize::try_from(durable.offset).unwrap();
	let ready_end = usize::try_from(ready_cut.offset).unwrap();
	let committed_end = usize::try_from(committed.offset).unwrap();
	let prior = scan(&run, &published[..durable_end], FRESH);
	let pending = scan(&run, &published[..ready_end], FRESH);
	let final_replay = scan(&run, &published[..committed_end], FRESH);
	let witness = prior.witness().unwrap();
	let ready = pending.receipt_ready().unwrap();
	let inode = ready.receipt();
	let other_inode = LinuxFileIdentity::new(inode.device(), inode.inode() + 101);
	let basis = prior.durable_receipt_basis().unwrap();
	assert_eq!(basis.bytes(), recorded("receipt"));
	assert_eq!(basis.digest(), ready.digest());
	assert_eq!(basis.length(), ready.length());

	let ready_proposal = prior
		.prepare_live_receipt_ready(&trust, witness, inode)
		.unwrap();
	assert_eq!(ready_proposal.previous(), durable);
	assert_eq!(ready_proposal.successor(), ready_cut);
	assert_eq!(ready_proposal.encoded(), &published[durable_end..ready_end]);
	assert!(ready_proposal.confirms_live_receipt_ready(&pending, witness, inode));
	assert!(!ready_proposal.confirms_live_receipt_ready(&pending, witness, other_inode));
	assert!(!ready_proposal.confirms_live_receipt_ready(&final_replay, witness, inode));

	let commit_proposal = pending
		.prepare_live_receipt_commit(&trust, witness, ready)
		.unwrap();
	assert_eq!(commit_proposal.previous(), ready_cut);
	assert_eq!(commit_proposal.successor(), committed);
	assert_eq!(
		commit_proposal.encoded(),
		&published[ready_end..committed_end]
	);
	assert!(commit_proposal.confirms_live_receipt_commit(&final_replay, witness, ready));
	assert!(!commit_proposal.confirms_live_receipt_commit(&pending, witness, ready));
	assert!(final_replay.matches_committed_receipt(inode, basis.bytes()));

	let alternate = prior
		.prepare_live_receipt_ready(&trust, witness, other_inode)
		.unwrap();
	let other = scan(
		&run,
		[&published[..durable_end], alternate.encoded()]
			.concat()
			.as_slice(),
		FRESH,
	);
	assert_eq!(other.phase(), Phase::ReceiptReadyRequiresInspection);
	let alternate_ready = other.receipt_ready().unwrap();
	assert_eq!(alternate_ready.receipt(), other_inode);
	assert!(
		pending
			.prepare_live_receipt_commit(&trust, witness, alternate_ready)
			.is_err()
	);
	assert!(!commit_proposal.confirms_live_receipt_commit(&final_replay, witness, alternate_ready));

	for alias in [
		witness.binding().stage(),
		basis.job_directory(),
		basis.target_parent(),
	] {
		assert!(
			prior
				.prepare_live_receipt_ready(&trust, witness, alias)
				.is_err()
		);
	}
	let torn_ready = scan(&run, &published[..ready_end - 1], FRESH);
	assert!(!ready_proposal.confirms_live_receipt_ready(&torn_ready, witness, inode));
	assert!(
		torn_ready
			.prepare_live_receipt_ready(&trust, witness, inode)
			.is_err()
	);
	let torn_commit = scan(&run, &published[..committed_end - 1], FRESH);
	assert!(!commit_proposal.confirms_live_receipt_commit(&torn_commit, witness, ready));
	assert!(
		torn_commit
			.prepare_live_receipt_commit(&trust, witness, ready)
			.is_err()
	);
	let wrong_digest = recorded("wrong-ready-digest");
	let wrong_ready = scan(&run, wrong_digest.as_slice(), FRESH);
	assert!(!ready_proposal.confirms_live_receipt_ready(&wrong_ready, witness, inode));
	let wrong_inode = recorded("wrong-committed-inode");
	let wrong_commit = scan(&run, wrong_inode.as_slice(), FRESH);
	assert!(!commit_proposal.confirms_live_receipt_commit(&wrong_commit, witness, ready));

	assert!(
		pending
			.prepare_live_receipt_ready(&trust, witness, inode)
			.is_err()
	);
	assert!(
		prior
			.prepare_live_receipt_commit(&trust, witness, ready)
			.is_err()
	);
	assert!(
		final_replay
			.prepare_live_receipt_commit(&trust, witness, ready)
			.is_err()
	);

	let recovered = recorded("recovered-published");
	let recovered_durable =
		usize::try_from(boundary_of(&recovered, Kind::DurabilityRecorded).offset).unwrap();
	let recovered_ready =
		usize::try_from(boundary_of(&recovered, Kind::RemoteReceiptReady).offset).unwrap();
	let replay = scan(&run, &recovered[..recovered_durable], FRESH);
	assert!(
		replay
			.prepare_live_receipt_ready(&trust, witness, inode)
			.is_err()
	);
	let replay = scan(&run, &recovered[..recovered_ready], FRESH);
	assert!(
		replay
			.prepare_live_receipt_commit(&trust, witness, replay.receipt_ready().unwrap())
			.is_err()
	);

	let expired = recorded("archived-expired-consent");
	let other_witness = scan(&run, expired.as_slice(), FRESH).witness().unwrap();
	assert!(
		prior
			.prepare_live_receipt_ready(&trust, other_witness, inode)
			.is_err()
	);
	assert!(
		pending
			.prepare_live_receipt_commit(&trust, other_witness, ready)
			.is_err()
	);

	let mut changed = run.fixture.owner.manifest().clone();
	changed.scope.destination = RemoteDownloadDestination::new(
		changed.scope.destination.root(),
		changed.scope.destination.parent(),
		UnixComponent::new(b"other-target").unwrap(),
	);
	let alternative_owner = RemoteDownloadOwnerRecord::sign(changed, &run.fixture.key).unwrap();
	let alternative_trust = RemoteBootstrapTrust::new(
		&alternative_owner,
		run.fixture.owner.manifest().profile,
		&run.fixture.verify,
	)
	.unwrap();
	assert!(
		prior
			.prepare_live_receipt_ready(&alternative_trust, witness, inode)
			.is_err()
	);
	assert!(
		pending
			.prepare_live_receipt_commit(&alternative_trust, witness, ready)
			.is_err()
	);
}
