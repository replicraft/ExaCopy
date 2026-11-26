//! Whole-pass capacity against independently enumerated phase paths.

use std::num::NonZeroU16;

use exacopy_journal::StreamLength;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassBudgetError as Error, WitnessedPassProgress as Progress,
	WitnessedRetirementPhase as RetiredFrom,
};

const PLANS: &str = include_str!("../verification/remote_download/witness_budget/plan_vectors.tsv");
const PHASES: &str =
	include_str!("../verification/remote_download/witness_budget/phase_vectors.tsv");

const RANGES: &str =
	include_str!("../verification/remote_download/witness_budget/range_vectors.tsv");

fn length(raw: u64) -> StreamLength {
	StreamLength::new(raw).unwrap()
}

fn ordinal(raw: u16) -> NonZeroU16 {
	NonZeroU16::new(raw).unwrap()
}

fn anchor(offset: u64, sequence: u64, byte: u8) -> RemoteReplayBoundary {
	let head = if sequence == 0 {
		ChainHead::start()
	} else {
		ChainHead::after(sequence, [byte; 32]).unwrap()
	};
	RemoteReplayBoundary { head, offset }
}

fn error(name: &str) -> Error {
	match name {
		"Boundary" => Error::Boundary,
		"SourceExtent" => Error::SourceExtent,
		"CheckpointLimit" => Error::CheckpointLimit,
		"RunLimit" => Error::RunLimit,
		"SegmentLimit" => Error::SegmentLimit,
		"SequenceLimit" => Error::SequenceLimit,
		_ => panic!("unexpected fixture error {name}"),
	}
}

fn assert_plan_vectors() {
	for line in PLANS.lines().skip(1) {
		let fields = line.split('\t').collect::<Vec<_>>();
		let label = fields[0];
		let number = |index: usize| fields[index].parse::<u64>().unwrap();
		let boundary = anchor(number(1), number(2), 0x11);
		let planned = WitnessedPassBudget::plan(
			boundary,
			length(number(3)),
			length(number(4)),
			ordinal(number(5).try_into().unwrap()),
		);
		if fields[6] != "Accept" {
			assert_eq!(planned, Err(error(fields[6])), "{label}");
			continue;
		}
		let plan = planned.unwrap_or_else(|problem| panic!("{label}: {problem}"));
		assert_eq!(plan.boundary(), boundary, "{label}");
		assert_eq!(plan.retained_end(), length(number(3)), "{label}");
		assert_eq!(plan.fresh_source_length(), length(number(4)), "{label}");
		assert_eq!(u64::from(plan.checkpoint_count()), number(7), "{label}");
		assert_eq!(u64::from(plan.new_run().get()), number(8), "{label}");
		assert_eq!(
			plan.allows_fresh_retirement(),
			fields[9].parse::<bool>().unwrap(),
			"{label}"
		);
		assert_eq!(plan.reserved_end(), number(10), "{label}");
		assert_eq!(u64::from(plan.reserved_frames()), number(11), "{label}");
		assert_eq!(u64::from(plan.receipt_bytes()), number(12), "{label}");
		let before = plan
			.recheck_remaining(boundary, Progress::BeforeContinuation)
			.unwrap();
		assert_eq!(
			before.journal_bytes(),
			number(10) - boundary.offset,
			"{label}"
		);
		assert_eq!(before.journal_frames(), plan.reserved_frames(), "{label}");
		assert_eq!(before.receipt_bytes(), plan.receipt_bytes(), "{label}");
		let mut next = number(3);
		for checkpoint in 1..=plan.checkpoint_count() {
			let range = plan.checkpoint_range(ordinal(checkpoint)).unwrap();
			assert_eq!(range.start, next, "{label} checkpoint {checkpoint}");
			assert!((1..=64 * 1024 * 1024).contains(&(range.end - range.start)));
			if checkpoint < plan.checkpoint_count() {
				assert_eq!(range.end - range.start, 64 * 1024 * 1024);
			}
			next = range.end;
		}
		assert_eq!(next, number(4), "{label}");
		assert!(
			plan.checkpoint_range(ordinal(plan.checkpoint_count() + 1))
				.is_none()
		);
	}
}

fn assert_range_vectors() {
	for line in RANGES.lines().skip(1) {
		let fields = line.split('\t').collect::<Vec<_>>();
		let number = |index: usize| fields[index].parse::<u64>().unwrap();
		let plan = WitnessedPassBudget::plan(
			anchor(512, 5, 0x11),
			length(number(1)),
			length(number(2)),
			ordinal(62),
		)
		.unwrap();
		let actual = plan.checkpoint_range(ordinal(number(3).try_into().unwrap()));
		let expected = (fields[4] != "-").then(|| number(4)..number(5));
		assert_eq!(actual, expected, "{line}");
	}
}

fn phase(name: &str) -> (Progress, u64) {
	let from = RetiredFrom::MetadataReady;
	match name {
		"coverage" => (
			Progress::Continued {
				completed_checkpoints: 0,
			},
			1,
		),
		"witness_intent" => (Progress::WitnessIntent, 2),
		"seal" => (Progress::Sealed, 3),
		"verify" => (Progress::Verified, 4),
		"metadata" => (Progress::MetadataReady, 5),
		"publish_intent" => (Progress::PublishIntent, 6),
		"published_observed" => (Progress::PublishedObserved, 7),
		"durable" => (Progress::Durable, 8),
		"receipt_ready" => (Progress::ReceiptReady, 9),
		"terminal" => (Progress::ReceiptCommitted, 10),
		"retired" => (Progress::Retired { from }, 6),
		"fresh_allocated" => (Progress::FreshAllocated { from }, 7),
		"fresh_prepared" => (Progress::FreshPrepared { from }, 8),
		_ => panic!("unexpected fixture phase {name}"),
	}
}

fn assert_phase_vectors() {
	let origin = anchor(512, 5, 0x11);
	for line in PHASES.lines().skip(1) {
		let fields = line.split('\t').collect::<Vec<_>>();
		let (progress, frames_used) = phase(fields[1]);
		let fresh = fields[0].parse::<bool>().unwrap();
		let plan = WitnessedPassBudget::plan(
			origin,
			length(17),
			length(17),
			ordinal(if fresh { 62 } else { 63 }),
		)
		.unwrap();
		let observed = anchor(origin.offset + 200 * frames_used, 5 + frames_used, 0x22);
		let remaining = plan.recheck_remaining(observed, progress).unwrap();
		assert_eq!(
			remaining.journal_bytes(),
			fields[2].parse().unwrap(),
			"{line}"
		);
		assert_eq!(
			remaining.journal_frames(),
			fields[3].parse().unwrap(),
			"{line}"
		);
		assert_eq!(remaining.receipt_bytes(), 6144, "{line}");
	}
}

fn assert_boundaries() {
	let origin = anchor(512, u64::MAX - 12, 0x11);
	let extent = 17 + 2 * 64 * 1024 * 1024;
	let plan = WitnessedPassBudget::plan(origin, length(17), length(extent), ordinal(62)).unwrap();
	let continued = Progress::Continued {
		completed_checkpoints: 0,
	};
	let one_checkpoint = Progress::Continued {
		completed_checkpoints: 1,
	};
	let crossed_continuation = anchor(origin.offset + 1116, origin.head.sequence() + 1, 0x22);
	let crossed_one_checkpoint =
		anchor(origin.offset + 1116 + 860, origin.head.sequence() + 2, 0x33);
	let after_40 = plan
		.recheck_remaining(crossed_continuation, continued)
		.unwrap();
	let after_one = plan
		.recheck_remaining(crossed_one_checkpoint, one_checkpoint)
		.unwrap();
	assert_eq!(after_40.journal_bytes(), 6022 + 2 * 860);
	assert_eq!(after_one.journal_bytes(), 6022 + 860);
	assert_eq!(after_40.journal_frames(), 11);
	assert_eq!(after_one.journal_frames(), 10);
	assert_eq!(
		plan.required_after_checkpoint(
			crossed_continuation,
			ordinal(1),
			crossed_one_checkpoint.offset
		),
		Ok(after_one),
	);
	assert_eq!(
		plan.required_after_checkpoint(
			crossed_continuation,
			ordinal(1),
			crossed_one_checkpoint.offset + 1
		),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.required_after_checkpoint(
			crossed_continuation,
			ordinal(2),
			crossed_one_checkpoint.offset
		),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.required_after_checkpoint(
			crossed_continuation,
			ordinal(3),
			crossed_one_checkpoint.offset
		),
		Err(Error::Progress),
	);
	assert_eq!(
		plan.recheck_remaining(
			RemoteReplayBoundary {
				offset: crossed_continuation.offset + 1,
				..crossed_continuation
			},
			continued,
		),
		Err(Error::ReservationExceeded),
	);
	assert_eq!(
		plan.recheck_remaining(
			anchor(origin.offset, origin.head.sequence(), 0x44),
			Progress::BeforeContinuation,
		),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.recheck_remaining(
			anchor(origin.offset + 1116, origin.head.sequence() + 2, 0x22),
			continued,
		),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.recheck_remaining(
			anchor(origin.offset + 91, origin.head.sequence() + 1, 0x22),
			continued,
		),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.recheck_remaining(crossed_one_checkpoint, Progress::WitnessIntent),
		Err(Error::Boundary),
	);
	assert_eq!(
		plan.recheck_remaining(
			crossed_one_checkpoint,
			Progress::Continued {
				completed_checkpoints: 3
			},
		),
		Err(Error::Progress),
	);
	let early = Progress::Retired {
		from: RetiredFrom::Continued {
			completed_checkpoints: 1,
		},
	};
	let early_boundary = anchor(origin.offset + 1116 + 860 + 886, u64::MAX - 9, 0x44);
	let remaining = plan.recheck_remaining(early_boundary, early).unwrap();
	assert_eq!(remaining.journal_bytes(), 2580);
	assert_eq!(remaining.journal_frames(), 3);
	let final_run =
		WitnessedPassBudget::plan(origin, length(17), length(extent), ordinal(63)).unwrap();
	assert_eq!(
		final_run.recheck_remaining(early_boundary, early),
		Err(Error::Progress)
	);

	let origin = anchor(512, 5, 0x11);
	let plan = WitnessedPassBudget::plan(origin, length(17), length(17), ordinal(62)).unwrap();
	let metadata_end = 512 + 1116 + 697 + 635 + 567 + 546;
	let retired = Progress::Retired {
		from: RetiredFrom::MetadataReady,
	};
	let longest_bytes = anchor(metadata_end + 997, 11, 0x22);
	let remainder = plan.recheck_remaining(longest_bytes, retired).unwrap();
	assert_eq!(
		longest_bytes.offset + remainder.journal_bytes(),
		plan.reserved_end()
	);
	let longest_slots = anchor(metadata_end + 1014, 11, 0x33);
	let remainder = plan
		.recheck_remaining(longest_slots, Progress::PublishIntent)
		.unwrap();
	assert_eq!(
		longest_slots.head.sequence() + u64::from(remainder.journal_frames()),
		15
	);
	assert!(longest_slots.offset + remainder.journal_bytes() < plan.reserved_end());
}

#[test]
fn witnessed_whole_pass_matches_independent_capacity_paths() {
	assert_plan_vectors();
	assert_range_vectors();
	assert_phase_vectors();
	assert_boundaries();
}
