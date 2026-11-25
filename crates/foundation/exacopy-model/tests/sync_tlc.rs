//! Replay every subject of the bounded TLA+ classifier against the Rust API.

use std::collections::HashSet;

use exacopy_model::{
	RegularFileEvidence, SyncBaseline, SyncBlock, SyncConflict, SyncCopyTarget,
	SyncInventoryCompleteness, SyncObservation, SyncPathDecision, SyncSide, classify_two_way_path,
};

const TABLE: &str = include_str!("../verification/tla/SyncBaseline.classifier.tsv");
const A: RegularFileEvidence = RegularFileEvidence {
	byte_len: 17,
	content_digest: [1; 32],
	required_metadata_digest: [2; 32],
};
const B: RegularFileEvidence = RegularFileEvidence {
	content_digest: [3; 32],
	..A
};
const C: RegularFileEvidence = RegularFileEvidence {
	required_metadata_digest: [4; 32],
	..A
};

fn file(token: &str) -> RegularFileEvidence {
	match token {
		"A" => A,
		"B" => B,
		"C" => C,
		_ => panic!("invalid file evidence token: {token}"),
	}
}

fn baseline(token: &str) -> SyncBaseline {
	match token {
		"uninitialized" => SyncBaseline::Uninitialized,
		"common-absent" => SyncBaseline::CommonAbsent,
		"asymmetric" => SyncBaseline::Asymmetric,
		_ => SyncBaseline::CommonPresent(file(token)),
	}
}

fn observation(token: &str) -> SyncObservation {
	match token {
		"absent" => SyncObservation::AbsentObserved,
		"unknown" => SyncObservation::Unknown,
		"unsupported" => SyncObservation::UnsupportedEntry,
		_ => SyncObservation::Present(file(token)),
	}
}

fn decision_name(decision: SyncPathDecision) -> &'static str {
	use SyncBlock::{IncompleteInventory, UnknownObservation};
	use SyncConflict::{
		AsymmetricBaseline, DeletionAgainstUnchanged, DivergentVersions, EditAgainstDeletion,
		UnsupportedEntry,
	};
	use SyncCopyTarget::{AbsentName, ExistingIncumbent};
	use SyncPathDecision::{
		BaselineMatch, Blocked, BothAbsentAfterCommonPresent, Conflict, CopyCandidate, NoChange,
	};
	use SyncSide::{Left, Right};

	match decision {
		NoChange => "unchanged",
		BaselineMatch => "baseline-match",
		BothAbsentAfterCommonPresent => "tombstone",
		CopyCandidate {
			from: Left,
			target: AbsentName,
		} => "left-absent",
		CopyCandidate {
			from: Right,
			target: AbsentName,
		} => "right-absent",
		CopyCandidate {
			from: Left,
			target: ExistingIncumbent,
		} => "left-incumbent",
		CopyCandidate {
			from: Right,
			target: ExistingIncumbent,
		} => "right-incumbent",
		Conflict(DeletionAgainstUnchanged { absent: Left }) => "deleted-left",
		Conflict(DeletionAgainstUnchanged { absent: Right }) => "deleted-right",
		Conflict(EditAgainstDeletion { edited: Left }) => "edited-left",
		Conflict(EditAgainstDeletion { edited: Right }) => "edited-right",
		Conflict(DivergentVersions) => "divergent",
		Conflict(UnsupportedEntry) => "unsupported",
		Conflict(AsymmetricBaseline) => "asymmetric",
		Blocked(IncompleteInventory) => "incomplete",
		Blocked(UnknownObservation) => "unknown",
	}
}

#[test]
fn sync_classifier_matches_all_tlc_subjects() {
	let mut subjects = HashSet::new();
	for row in TABLE.lines() {
		let parts: Vec<_> = row.split('\t').collect();
		let [old, complete, left, right, expected] = parts.as_slice() else {
			panic!("invalid TLC classifier row: {row}");
		};
		assert!(
			subjects.insert((*old, *complete, *left, *right)),
			"duplicated TLC row: {row}"
		);
		let completeness = match *complete {
			"TRUE" => SyncInventoryCompleteness::Complete,
			"FALSE" => SyncInventoryCompleteness::Incomplete,
			_ => panic!("invalid TLC completeness token: {complete}"),
		};
		let decision = classify_two_way_path(
			completeness,
			baseline(old),
			observation(left),
			observation(right),
		);
		assert_eq!(
			decision_name(decision),
			*expected,
			"TLC classifier row: {row}"
		);
	}
	assert_eq!(subjects.len(), 6 * 2 * 6 * 6);
}
