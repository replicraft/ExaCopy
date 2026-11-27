use std::fs;

use exacopy_endpoint::UnixComponent;

use super::{WitnessPublicationName, WitnessPublicationNames};
use crate::linux::ReadRoot;
use crate::scratch::Scratch;

#[test]
fn namespace_agreement_requires_known_and_unchanged_evidence_for_every_name() {
	use WitnessPublicationName::{Absent, Regular, Unobserved};

	let scratch = Scratch::new();
	fs::write(scratch.path("target"), b"original").unwrap();
	fs::hard_link(scratch.path("target"), scratch.path("witness")).unwrap();
	fs::write(scratch.path("other"), b"original").unwrap();
	let root = ReadRoot::from_directory(scratch.open()).unwrap();
	let target = UnixComponent::new(b"target").unwrap();
	let witness = UnixComponent::new(b"witness").unwrap();
	let target_file = root.open_regular(target).unwrap();
	let witness_file = root.open_regular(witness).unwrap();
	let first = target_file.observation();
	let first_witness = witness_file.observation();
	let unchanged_target = root.open_regular(target).unwrap().observation();
	let unchanged_witness = root.open_regular(witness).unwrap().observation();
	assert_eq!(first.identity(), first_witness.identity());
	assert_eq!(first.link_count(), 2);
	let other = root
		.open_regular(UnixComponent::new(b"other").unwrap())
		.unwrap();
	let other = other.observation();
	assert_eq!(first.len(), other.len());
	assert_ne!(first.identity(), other.identity());

	fs::write(scratch.path("target"), b"new and longer").unwrap();
	let changed = root.open_regular(target).unwrap().observation();
	assert_eq!(first.identity(), changed.identity());
	assert_ne!(first.len(), changed.len());

	let before = WitnessPublicationNames {
		private_stage: Absent,
		protected_witness: Regular(first_witness),
		public_target: Regular(first),
	};
	let after = WitnessPublicationNames {
		private_stage: Absent,
		protected_witness: Regular(unchanged_witness),
		public_target: Regular(unchanged_target),
	};
	assert!(before.agrees(after));
	for (label, different) in [
		(
			"new private occupant",
			WitnessPublicationNames {
				private_stage: Regular(other),
				..after
			},
		),
		(
			"absent witness",
			WitnessPublicationNames {
				protected_witness: Absent,
				..after
			},
		),
		(
			"unknown target",
			WitnessPublicationNames {
				public_target: Unobserved,
				..after
			},
		),
		(
			"distinct regular target with equal length",
			WitnessPublicationNames {
				public_target: Regular(other),
				..after
			},
		),
		(
			"same inode with changed extent",
			WitnessPublicationNames {
				public_target: Regular(changed),
				..after
			},
		),
	] {
		assert!(!before.agrees(different), "{label}");
		assert!(!different.agrees(before), "{label} in reverse order");
	}
	let unknown_target = WitnessPublicationNames {
		public_target: Unobserved,
		..after
	};
	assert!(!unknown_target.agrees(unknown_target));
}
