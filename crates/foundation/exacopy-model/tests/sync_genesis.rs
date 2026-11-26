//! Verify pure genesis admission against an independent finite defect oracle.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use exacopy_model::RegularFileEvidence;
use exacopy_model::sync_genesis::{
	FileId, GenesisRefusal, Measurement, ObservationStamp, RecheckedObservation, RootId, Scope,
	Selection, admit,
};

#[path = "../verification/sync_genesis/oracle.rs"]
mod oracle;

#[derive(Clone, Copy)]
struct Subject {
	selection: Selection<'static>,
	measurements: [Option<Measurement<'static>>; 2],
	rechecked: [Option<RecheckedObservation<'static>>; 2],
}

impl Subject {
	fn baseline(right_read_first: bool) -> Self {
		let roots = [RootId([1; 32]), RootId([2; 32])];
		let scope = Scope {
			selection: [3; 32],
			name: component(b"report-\xff"),
			policy: [4; 32],
		};
		let scan = position(9);
		let selection = Selection { roots, scope, scan };
		let observations = [
			ObservationStamp {
				root: roots[0],
				scope,
				scan,
				file: FileId([5; 32]),
				stability: [6; 32],
			},
			ObservationStamp {
				root: roots[1],
				scope,
				scan,
				file: FileId([7; 32]),
				stability: [8; 32],
			},
		];
		let order = if right_read_first { [2, 1] } else { [1, 2] };
		let recheck_positions = [position(3), position(4)];
		let evidence = RegularFileEvidence {
			byte_len: 17,
			content_digest: [10; 32],
			required_metadata_digest: [11; 32],
		};
		let measurements = [0, 1].map(|side| {
			Some(Measurement {
				observation: observations[side],
				completed_at: position(order[side]),
				evidence,
			})
		});
		Self {
			selection,
			measurements,
			rechecked: [0, 1].map(|side| {
				Some(RecheckedObservation {
					observation: observations[side],
					observed_at: recheck_positions[side],
				})
			}),
		}
	}

	fn alter(&mut self, mask: u32) {
		use oracle::Fault;

		let [Some(mut left), Some(mut right)] = self.measurements else {
			panic!("fixture starts from two completed reads");
		};
		let has = |fault| oracle::contains(mask, fault);
		if has(Fault::AliasedRoots) {
			self.selection.roots[1] = self.selection.roots[0];
			right.observation.root = left.observation.root;
		}
		if has(Fault::SwappedRoots) {
			core::mem::swap(&mut left.observation.root, &mut right.observation.root);
		}
		if has(Fault::WrongSubject) {
			left.observation.scope.selection = [31; 32];
		}
		if has(Fault::WrongPolicy) {
			right.observation.scope.policy = [32; 32];
		}
		if has(Fault::OldScan) {
			left.observation.scan = position(8);
		}
		if has(Fault::AliasedFiles) {
			right.observation.file = left.observation.file;
		}
		if has(Fault::ReusedRead) {
			right.completed_at = left.completed_at;
		}
		if has(Fault::UnequalLength) {
			left.evidence.byte_len = 18;
		}
		if has(Fault::UnequalStream) {
			right.evidence.content_digest = [33; 32];
		}
		if has(Fault::UnequalMetadata) {
			left.evidence.required_metadata_digest = [34; 32];
		}
		self.measurements = [
			(!has(Fault::MissingLeftRead)).then_some(left),
			(!has(Fault::MissingRightRead)).then_some(right),
		];
		let mut rechecked_left = left.observation;
		if has(Fault::ChangedFinalObservation) {
			rechecked_left.stability = [35; 32];
		}
		let left_position = if has(Fault::EarlyRecheck) { 2 } else { 3 };
		self.rechecked = [
			(!has(Fault::MissingLeftRecheck)).then_some(RecheckedObservation {
				observation: rechecked_left,
				observed_at: position(left_position),
			}),
			(!has(Fault::MissingRightRecheck)).then_some(RecheckedObservation {
				observation: right.observation,
				observed_at: position(4),
			}),
		];
	}
}

fn position(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).expect("fixture positions are nonzero")
}

#[test]
fn genesis_matches_independent_bounded_observation_oracle() {
	for right_read_first in [false, true] {
		let baseline = Subject::baseline(right_read_first);
		for defects in oracle::bounded_histories() {
			let mut subject = baseline;
			subject.alter(defects);
			let result = admit(subject.selection, subject.measurements, subject.rechecked);
			assert_eq!(
				result.is_ok(),
				oracle::has_complete_matched_pair(defects),
				"defects {defects:#06x}, right measured first: {right_read_first}, result: {result:?}",
			);
			if let Ok(seed) = result {
				assert_eq!(seed.selection(), subject.selection);
				assert_eq!(seed.measurements().map(Some), subject.measurements);
			}
		}
	}
}

#[test]
fn a_final_recheck_from_a_different_scan_cannot_confirm_identical_files() {
	let mut subject = Subject::baseline(false);
	subject.rechecked[0].as_mut().unwrap().observation.scan = position(8);
	assert_eq!(
		admit(subject.selection, subject.measurements, subject.rechecked),
		Err(GenesisRefusal::StaleRecheck),
	);
}

#[test]
fn a_late_left_observation_cannot_cover_an_early_right_observation() {
	let mut subject = Subject::baseline(false);
	subject.rechecked[1].as_mut().unwrap().observed_at = position(2);
	assert_eq!(
		admit(subject.selection, subject.measurements, subject.rechecked),
		Err(GenesisRefusal::StaleRecheck),
	);
}

#[test]
fn a_raw_basename_mismatch_refuses_identical_inode_and_measurement_evidence() {
	let subject = Subject::baseline(false);
	let other_name = component(b"report-\xfe");
	let mut measurement = subject.measurements;
	measurement[0].as_mut().unwrap().observation.scope.name = other_name;
	assert_eq!(
		admit(subject.selection, measurement, subject.rechecked),
		Err(GenesisRefusal::MeasurementBinding),
	);

	let mut rechecked = subject.rechecked;
	rechecked[1].as_mut().unwrap().observation.scope.name = other_name;
	assert_eq!(
		admit(subject.selection, subject.measurements, rechecked),
		Err(GenesisRefusal::StaleRecheck),
	);
}

fn component(bytes: &'static [u8]) -> UnixComponent<'static> {
	UnixComponent::new(bytes).expect("fixture contains one valid raw component")
}
