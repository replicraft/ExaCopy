use exacopy_journal::NamespaceObservation;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome as Outcome;

use super::{
	FRESH, FrameKind as Kind, LinuxFileIdentity, Phase, RemoteReplayIssue, Transcript, boundary_of,
	recorded, scan,
};

#[test]
fn outbound_live_observation_matches_independent_bytes_and_exact_accepted_cut() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let published = recorded("published");
	let intent = boundary_of(&published, Kind::PublishIntent);
	let intent_end = usize::try_from(intent.offset).unwrap();
	let prior = scan(&run, &published[..intent_end], FRESH);
	let witness = prior.witness().unwrap();
	let stage = witness.binding().stage();
	let unrelated = recorded("archived-expired-consent");
	let other_witness = scan(&run, unrelated.as_slice(), FRESH).witness().unwrap();
	let uncertain = Outcome::Uncertain {
		target: NamespaceObservation::Unobserved,
		stage: NamespaceObservation::Absent,
		witness: NamespaceObservation::Present(stage),
	};

	for (label, outcome) in [
		("published", Outcome::Submitted(stage)),
		("conflict", Outcome::Conflict),
		("uncertain", uncertain),
	] {
		let bytes = recorded(label);
		let observed = boundary_of(&bytes, Kind::PublishObserved);
		let observed_end = usize::try_from(observed.offset).unwrap();
		let proposed = prior
			.prepare_live_observation(&trust, witness, outcome)
			.unwrap();
		assert_eq!(proposed.kind(), Kind::PublishObserved);
		assert_eq!(proposed.previous(), intent);
		assert_eq!(proposed.successor(), observed);
		assert_eq!(proposed.encoded(), &bytes[intent_end..observed_end]);
		let exact = scan(&run, &bytes[..observed_end], FRESH);
		assert!(proposed.confirms_live_observation(&exact, witness, outcome));
		assert!(!proposed.confirms_live_observation(&exact, other_witness, outcome));
		assert!(
			exact
				.prepare_live_observation(&trust, witness, outcome)
				.is_err()
		);

		let torn = scan(&run, &bytes[..observed_end - 1], FRESH);
		assert!(!proposed.confirms_live_observation(&torn, witness, outcome));
		assert!(
			torn.prepare_live_observation(&trust, witness, outcome)
				.is_err()
		);
		if label == "uncertain" {
			assert_eq!(exact.phase(), Phase::Uncertain);
			assert!(matches!(
				exact.issue(),
				Some(RemoteReplayIssue::RecordedUncertainty)
			));
			let suffix = recorded("uncertain-then-durability");
			let extra = scan(&run, suffix.as_slice(), FRESH);
			assert_eq!(extra.boundary(), observed);
			assert!(!proposed.confirms_live_observation(&extra, witness, outcome));
		}
	}

	for wrong in [
		Outcome::Submitted(LinuxFileIdentity::new(7, 900)),
		Outcome::Recovered {
			target: stage,
			witness: witness.boundary().head,
		},
	] {
		assert!(
			prior
				.prepare_live_observation(&trust, witness, wrong)
				.is_err()
		);
	}
	assert!(
		prior
			.prepare_live_observation(&trust, other_witness, Outcome::Conflict)
			.is_err()
	);
	let metadata = usize::try_from(boundary_of(&published, Kind::MetadataRecorded).offset).unwrap();
	assert!(
		scan(&run, &published[..metadata], FRESH)
			.prepare_live_observation(&trust, witness, Outcome::Conflict)
			.is_err()
	);
}
