use std::fs;

use exacopy_endpoint::UnixComponent;
use exacopy_model::retained_prefix::Head;

use super::{
	Progress, StageError, WitnessPublicationObservation, WitnessReservationObservationError,
};
use crate::linux::ReadRoot;
use crate::scratch::Scratch;

#[test]
fn durability_preflight_consumes_attempt_and_requires_positive_exact_accepted_head() {
	use WitnessPublicationObservation::{Conflict, Published, Reconcile};
	use WitnessReservationObservationError::Native;

	let scratch = Scratch::new();
	fs::write(scratch.path("observation"), b"fixture bytes").unwrap();
	let root = ReadRoot::from_directory(scratch.open()).unwrap();
	let file = root
		.open_regular(UnixComponent::new(b"observation").unwrap())
		.unwrap();
	let stamp = file.observation();
	let expected = Head {
		digest: [8; 32],
		sequence: 8,
		end: 1200,
	};
	let altered = Head {
		digest: [9; 32],
		..expected
	};
	let later_sequence = Head {
		sequence: 9,
		..expected
	};
	let later_end = Head {
		end: 1201,
		..expected
	};

	let published = Published(stamp);
	let conflict = Conflict(stamp);
	let uncertain = Reconcile {
		submission: Ok(()),
		names: Box::default(),
		observation_failure: Some(StageError::IdentityChanged),
	};
	for (label, observed, head, active, identity_error) in [
		("conflict", &conflict, Some(expected), expected, false),
		("uncertain", &uncertain, Some(expected), expected, false),
		("kind 8 pending", &published, None, expected, true),
		("changed kind 8", &published, Some(altered), expected, true),
		(
			"same digest with changed kind-8 sequence",
			&published,
			Some(later_sequence),
			expected,
			true,
		),
		(
			"same digest with changed active end",
			&published,
			Some(expected),
			later_end,
			true,
		),
		(
			"changed active head",
			&published,
			Some(expected),
			altered,
			true,
		),
	] {
		let mut progress = Progress::Unspent;
		let refusal = progress
			.begin(observed, head, active, expected)
			.unwrap_err();
		assert!(
			matches!(
				(refusal, identity_error),
				(Native(StageError::IdentityChanged), true)
					| (Native(StageError::PriorBarrierFailure), false)
			),
			"{label}"
		);
		assert!(matches!(progress, Progress::Spent), "{label}");
		assert!(matches!(
			progress.begin(&published, Some(expected), expected, expected),
			Err(Native(StageError::PriorBarrierFailure))
		));
	}

	let mut progress = Progress::Unspent;
	let admitted = progress
		.begin(&published, Some(expected), expected, expected)
		.unwrap();
	assert_eq!(admitted, stamp);
	assert!(matches!(progress, Progress::Spent));
	assert!(matches!(
		progress.begin(&published, Some(expected), expected, expected),
		Err(Native(StageError::PriorBarrierFailure))
	));

	let successor = Head {
		digest: [9; 32],
		sequence: 9,
		end: 1500,
	};
	let mut confirmed = Progress::Confirmed(successor);
	assert!(matches!(
		confirmed.begin(&published, Some(expected), expected, expected),
		Err(Native(StageError::PriorBarrierFailure))
	));
	assert!(matches!(confirmed, Progress::Confirmed(head) if head == successor));
}
