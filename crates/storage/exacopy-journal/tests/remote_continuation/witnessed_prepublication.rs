use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::witness::replay::WitnessedPrepublicationFact as Fact;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadDestination, RemoteDownloadError, RemoteDownloadOwnerRecord,
};

use super::{
	FRESH, FrameKind as Kind, Phase, StreamDigest, Transcript, boundary_of, recorded, scan,
};

#[test]
fn outbound_prepublication_matches_all_four_independent_framed_records() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let bytes = recorded("published");
	let witness_cut = boundary_of(&bytes, Kind::RemoteWitnessIntent);
	let witness = scan(&run, &bytes[..witness_cut.offset as usize], FRESH)
		.witness()
		.unwrap();
	let digest = StreamDigest::from_bytes(*blake3::hash(b"ABCD").as_bytes());
	let facts = [
		(
			Fact::Sealed,
			Kind::StageSealed,
			Phase::WitnessIntentRequiresInspection,
		),
		(
			Fact::Verified {
				source: digest,
				stage: digest,
			},
			Kind::VerificationRecorded,
			Phase::Sealed,
		),
		(
			Fact::Metadata(RemoteLocalMetadata {
				uid: 1001,
				gid: 1002,
			}),
			Kind::MetadataRecorded,
			Phase::Verified,
		),
		(
			Fact::PublishIntent,
			Kind::PublishIntent,
			Phase::MetadataReady,
		),
	];
	let alternate = recorded("archived-expired-consent");
	let other_witness = scan(&run, alternate.as_slice(), FRESH).witness().unwrap();
	let mut prior = witness_cut;
	for (fact, kind, phase) in facts {
		let previous = prior.offset as usize;
		let expected = boundary_of(&bytes, kind);
		let end = expected.offset as usize;
		let replay = scan(&run, &bytes[..previous], FRESH);
		assert_eq!(replay.phase(), phase);
		let proposal = replay
			.prepare_prepublication(&trust, witness, fact)
			.unwrap();
		assert_eq!(proposal.previous(), prior);
		assert_eq!(proposal.kind(), kind);
		assert_eq!(proposal.successor(), expected);
		assert_eq!(proposal.encoded(), &bytes[previous..end]);
		assert!(
			replay
				.prepare_prepublication(&trust, other_witness, fact)
				.is_err()
		);
		assert!(
			scan(&run, &bytes[..end - 1], FRESH)
				.prepare_prepublication(&trust, witness, fact)
				.is_err()
		);
		for (later, other, _) in facts {
			if other != kind {
				assert!(
					replay
						.prepare_prepublication(&trust, witness, later)
						.is_err()
				);
			}
		}
		if phase == Phase::Sealed {
			let mismatch = Fact::Verified {
				source: digest,
				stage: StreamDigest::from_bytes([0xcc; 32]),
			};
			assert!(
				replay
					.prepare_prepublication(&trust, witness, mismatch)
					.is_err()
			);
		}
		prior = expected;
	}
	let after = scan(&run, &bytes[..prior.offset as usize], FRESH);
	assert_eq!(after.phase(), Phase::PublishIntentRequiresObservation);
	assert!(
		after
			.prepare_prepublication(&trust, witness, Fact::PublishIntent)
			.is_err()
	);
}

#[test]
fn publish_intent_refuses_an_alternate_signed_target_for_the_same_job_and_entry() {
	let run = Transcript::read(false);
	let owner = &run.fixture.owner;
	let mut changed = owner.manifest().clone();
	changed.scope.destination = RemoteDownloadDestination::new(
		changed.scope.destination.root(),
		changed.scope.destination.parent(),
		UnixComponent::new(b"alternate-target").unwrap(),
	);
	let alternate = RemoteDownloadOwnerRecord::sign(changed, &run.fixture.key).unwrap();
	let original = owner.manifest();
	assert_eq!(alternate.manifest().job, original.job);
	assert_eq!(alternate.manifest().scope.entry, original.scope.entry);
	assert_eq!(alternate.manifest().profile, original.profile);
	assert_ne!(
		alternate.manifest().scope.destination.target(),
		original.scope.destination.target(),
	);
	assert_ne!(alternate.digest(), owner.digest());
	assert_ne!(
		alternate.manifest().scope.digest().unwrap(),
		original.scope.digest().unwrap(),
	);
	let other_trust =
		RemoteBootstrapTrust::new(&alternate, original.profile, &run.fixture.verify).unwrap();
	let bytes = recorded("published");
	let metadata = boundary_of(&bytes, Kind::MetadataRecorded);
	let replay = scan(
		&run,
		&bytes[..usize::try_from(metadata.offset).unwrap()],
		FRESH,
	);
	assert_eq!(replay.phase(), Phase::MetadataReady);
	let witness = replay.witness().unwrap();
	assert_eq!(witness.binding().context().owner, owner.digest());
	assert!(
		replay
			.prepare_prepublication(&run.fixture.trust(), witness, Fact::PublishIntent)
			.is_ok()
	);
	assert!(matches!(
		replay.prepare_prepublication(&other_trust, witness, Fact::PublishIntent),
		Err(RemoteDownloadError::Binding),
	));
}
