//! Independent decision tables and fail-closed controls for the sync classifier.

use exacopy_model::{
	RegularFileEvidence, SyncBaseline, SyncBlock, SyncConflict, SyncCopyTarget,
	SyncInventoryCompleteness, SyncObservation, SyncPathDecision, SyncSide, classify_two_way_path,
};

use SyncBaseline::{Asymmetric, CommonAbsent, CommonPresent, Uninitialized};
use SyncCopyTarget::{AbsentName, ExistingIncumbent};
use SyncObservation::{AbsentObserved, Present, Unknown, UnsupportedEntry};
use SyncPathDecision::{
	BaselineMatch, Blocked, BothAbsentAfterCommonPresent, Conflict, CopyCandidate, NoChange,
};
use SyncSide::{Left, Right};

const COMMON: RegularFileEvidence = RegularFileEvidence {
	byte_len: 29,
	content_digest: [1; 32],
	required_metadata_digest: [2; 32],
};

const CONTENT_EDIT: RegularFileEvidence = RegularFileEvidence {
	content_digest: [3; 32],
	..COMMON
};

const METADATA_EDIT: RegularFileEvidence = RegularFileEvidence {
	required_metadata_digest: [4; 32],
	..COMMON
};

const LENGTH_EDIT: RegularFileEvidence = RegularFileEvidence {
	byte_len: COMMON.byte_len + 1,
	..COMMON
};

const BASELINES: [SyncBaseline; 4] = [
	Uninitialized,
	CommonAbsent,
	CommonPresent(COMMON),
	Asymmetric,
];
const OBSERVATIONS: [SyncObservation; 6] = [
	AbsentObserved,
	Present(COMMON),
	Present(CONTENT_EDIT),
	Present(METADATA_EDIT),
	Unknown,
	UnsupportedEntry,
];

fn classify(
	baseline: SyncBaseline,
	left: SyncObservation,
	right: SyncObservation,
) -> SyncPathDecision {
	classify_two_way_path(SyncInventoryCompleteness::Complete, baseline, left, right)
}

#[test]
fn first_scan_and_common_absence_follow_the_additive_preview_table() {
	// Raw path observations are ordered absent, first verified version,
	// independently verified different version on each axis.
	let observed = [AbsentObserved, Present(COMMON), Present(CONTENT_EDIT)];
	let expected = [
		[
			NoChange,
			CopyCandidate {
				from: Right,
				target: AbsentName,
			},
			CopyCandidate {
				from: Right,
				target: AbsentName,
			},
		],
		[
			CopyCandidate {
				from: Left,
				target: AbsentName,
			},
			BaselineMatch,
			Conflict(SyncConflict::DivergentVersions),
		],
		[
			CopyCandidate {
				from: Left,
				target: AbsentName,
			},
			Conflict(SyncConflict::DivergentVersions),
			BaselineMatch,
		],
	];

	for baseline in [Uninitialized, CommonAbsent] {
		for (left, row) in observed.into_iter().zip(expected) {
			for (right, decision) in observed.into_iter().zip(row) {
				assert_eq!(
					classify(baseline, left, right),
					decision,
					"{baseline:?} {left:?} {right:?}"
				);
			}
		}
	}
}

#[test]
fn verified_common_file_follows_the_three_way_preview_table() {
	// Index each axis as unchanged, changed content, changed metadata, absent.
	let observed = [
		Present(COMMON),
		Present(CONTENT_EDIT),
		Present(METADATA_EDIT),
		AbsentObserved,
	];
	let expected = [
		[
			NoChange,
			CopyCandidate {
				from: Right,
				target: ExistingIncumbent,
			},
			CopyCandidate {
				from: Right,
				target: ExistingIncumbent,
			},
			Conflict(SyncConflict::DeletionAgainstUnchanged { absent: Right }),
		],
		[
			CopyCandidate {
				from: Left,
				target: ExistingIncumbent,
			},
			BaselineMatch,
			Conflict(SyncConflict::DivergentVersions),
			Conflict(SyncConflict::EditAgainstDeletion { edited: Left }),
		],
		[
			CopyCandidate {
				from: Left,
				target: ExistingIncumbent,
			},
			Conflict(SyncConflict::DivergentVersions),
			BaselineMatch,
			Conflict(SyncConflict::EditAgainstDeletion { edited: Left }),
		],
		[
			Conflict(SyncConflict::DeletionAgainstUnchanged { absent: Left }),
			Conflict(SyncConflict::EditAgainstDeletion { edited: Right }),
			Conflict(SyncConflict::EditAgainstDeletion { edited: Right }),
			BothAbsentAfterCommonPresent,
		],
	];

	for (left, row) in observed.into_iter().zip(expected) {
		for (right, decision) in observed.into_iter().zip(row) {
			assert_eq!(
				classify(CommonPresent(COMMON), left, right),
				decision,
				"{left:?} {right:?}"
			);
		}
	}
}

#[test]
fn required_metadata_and_length_can_make_otherwise_matching_evidence_diverge() {
	for changed in [METADATA_EDIT, LENGTH_EDIT] {
		assert_eq!(
			classify(Uninitialized, Present(COMMON), Present(changed)),
			Conflict(SyncConflict::DivergentVersions)
		);
		assert_eq!(
			classify(
				CommonPresent(COMMON),
				Present(changed),
				Present(CONTENT_EDIT)
			),
			Conflict(SyncConflict::DivergentVersions)
		);
		assert_eq!(
			classify(CommonPresent(COMMON), Present(changed), Present(COMMON)),
			CopyCandidate {
				from: Left,
				target: ExistingIncumbent
			}
		);
		assert_eq!(
			classify(CommonPresent(COMMON), AbsentObserved, Present(changed)),
			Conflict(SyncConflict::EditAgainstDeletion { edited: Right })
		);
	}
}

#[test]
fn incomplete_inventory_blocks_all_path_decisions_even_with_local_observations() {
	for baseline in BASELINES {
		for left in OBSERVATIONS {
			for right in OBSERVATIONS {
				assert_eq!(
					classify_two_way_path(
						SyncInventoryCompleteness::Incomplete,
						baseline,
						left,
						right
					),
					Blocked(SyncBlock::IncompleteInventory),
					"{baseline:?} {left:?} {right:?}"
				);
			}
		}
	}
}

#[test]
fn unknown_observation_on_either_side_blocks_even_when_its_peer_is_absent() {
	for baseline in BASELINES {
		for observed in OBSERVATIONS {
			assert_eq!(
				classify(baseline, observed, Unknown),
				Blocked(SyncBlock::UnknownObservation)
			);
			assert_eq!(
				classify(baseline, Unknown, observed),
				Blocked(SyncBlock::UnknownObservation)
			);
		}
	}
}

#[test]
fn unsupported_file_types_and_asymmetric_history_require_review() {
	let ordinary = [AbsentObserved, Present(COMMON), Present(CONTENT_EDIT)];
	for left in ordinary {
		for right in ordinary {
			assert_eq!(
				classify(Asymmetric, left, right),
				Conflict(SyncConflict::AsymmetricBaseline)
			);
		}
	}
	for baseline in BASELINES {
		for other in ordinary.into_iter().chain([UnsupportedEntry]) {
			assert_eq!(
				classify(baseline, other, UnsupportedEntry),
				Conflict(SyncConflict::UnsupportedEntry)
			);
			assert_eq!(
				classify(baseline, UnsupportedEntry, other),
				Conflict(SyncConflict::UnsupportedEntry)
			);
		}
	}
}
