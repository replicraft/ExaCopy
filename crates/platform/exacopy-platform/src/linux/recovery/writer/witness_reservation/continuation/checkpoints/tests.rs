use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::num::NonZeroU64;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_endpoint::{ReadView as _, UnixComponent};
use exacopy_model::retained_prefix::{
	BudgetReservation, Checkpoint, Continuation, Guard, Head, History, Live, Pass, PrefixProof,
	Prior,
};

use crate::linux::job::{FIRST_SEGMENT, JOURNAL, STAGE};
use crate::linux::{
	ContinuationReservationError, DestinationRoot, RemoteDestinationEligibility,
	RetainedPrefixSelection, StageError, SuffixEffect, WitnessReservationAuthority,
	WitnessReservationEffect, WitnessReservationObservationError, WitnessReservationPlan,
	observe_remote_destination,
};
use crate::scratch::Scratch;

const JOB: &str = "checkpoint-component-job";
const PART: &str = "retained-part";
const TARGET: &str = "public-target";
const PREFIX: &[u8; 4] = b"ABCD";
const FULL: &[u8; 5] = b"ABCDE";
const ADOPTED_END: u64 = 4;
const SOURCE_END: u64 = 5;
const OLD_END: usize = 1624;
const CONTINUED_END: usize = 2575;
const CHECKPOINT_END: usize = 2860;

const OLD_TRANSCRIPT: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/verification/witnessed_components_ext4/fixtures/checkpoint-journal.hex"
));
const CHECKPOINT_FRAME: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/verification/witnessed_components_ext4/fixtures/checkpoint-successor.hex"
));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Case {
	Accepted,
	OutOfBounds,
	AdmissionRefused,
	RereadRefused,
}

#[derive(Debug, Eq, PartialEq)]
enum Refusal {
	Authority,
	Successor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
	Prior,
	Enter,
	Release,
	Reread,
}

struct AppendGuard<'a>(&'a RefCell<Vec<Step>>);

impl Drop for AppendGuard<'_> {
	fn drop(&mut self) {
		self.0.borrow_mut().push(Step::Release);
	}
}

/// Runs within the existing owned, unprivileged whole-ext4 component selector.
pub(super) fn exercise() {
	let frames = Frames::new();
	for case in [
		Case::Accepted,
		Case::OutOfBounds,
		Case::AdmissionRefused,
		Case::RereadRefused,
	] {
		exercise_checkpoint(&frames, case);
	}
}

struct Frames {
	journal: Vec<u8>,
	checkpoint: Vec<u8>,
	prior: Head,
	continued: Head,
	successor: Head,
}

impl Frames {
	fn new() -> Self {
		let journal = hex(OLD_TRANSCRIPT);
		let checkpoint = hex(CHECKPOINT_FRAME);
		assert_eq!(journal.len(), CONTINUED_END);
		assert_eq!(checkpoint.len(), CHECKPOINT_END - CONTINUED_END);
		let prior = boundary(5, OLD_END, &journal[..OLD_END]);
		let continued = boundary(6, CONTINUED_END, &journal);
		let successor = boundary(7, CHECKPOINT_END, &checkpoint);
		assert_eq!(&journal[OLD_END + 24..OLD_END + 56], &prior.digest);
		assert_eq!(&checkpoint[24..56], &continued.digest);
		Self {
			journal,
			checkpoint,
			prior,
			continued,
			successor,
		}
	}
}

fn hex(text: &str) -> Vec<u8> {
	let compact: String = text.split_ascii_whitespace().collect();
	let (pairs, remainder) = compact.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn boundary(sequence: u64, end: usize, frame_or_transcript: &[u8]) -> Head {
	Head {
		sequence,
		end: u64::try_from(end).unwrap(),
		digest: frame_or_transcript[frame_or_transcript.len() - 32..]
			.try_into()
			.unwrap(),
	}
}

fn exercise_checkpoint(frames: &Frames, case: Case) {
	let (prior_bytes, continuation) = frames.journal.split_at(OLD_END);
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let select = |value: &'static str| UnixComponent::new(value.as_bytes()).unwrap();
	let source_path = scratch.path("expected-source");
	let incumbent_path = scratch.path("unselected-incumbent");
	let stage_path = scratch.path(JOB).join(STAGE).join(PART);
	let journal_path = scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT);
	plant(&source_path, FULL);
	plant(&incumbent_path, b"do not replace");
	let source = fs::read(&source_path).unwrap();
	let source_id = identity(&source_path);
	let incumbent_id = identity(&incumbent_path);
	{
		let job = root.create_job_directory(select(JOB)).unwrap();
		job.create_stage_directory().unwrap();
		plant(&stage_path, PREFIX);
		fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o600)).unwrap();
		let directory = job.create_journal_directory().unwrap();
		let mut segment = directory.create_first_segment().unwrap();
		segment.write_all(prior_bytes).unwrap();
	}
	let stage_id = identity(&stage_path);
	let segment_id = identity(&journal_path);

	// The ext4 fixture supplies the actual current eligibility facts. The
	// archived codec vector and authority callbacks are component inputs.
	let qualification =
		RemoteDestinationQualification::new(observe_remote_destination(&root).unwrap(), [0x35; 32])
			.unwrap();
	let eligible = RemoteDestinationEligibility::admit(&root, Some(&qualification)).unwrap();
	let job_id = root.open_recovery_job(select(JOB)).unwrap().identity();
	let lease = root.try_recovery_write_lease(select(JOB), job_id).unwrap();
	let job = lease.job();
	let expected = job.open_first_segment().unwrap();
	let inventory = job.inventory(select(PART), select(TARGET)).unwrap();
	let selection = RetainedPrefixSelection {
		stage: select(PART),
		target: select(TARGET),
		directory: inventory.stage_directory_identity().unwrap().into(),
		file: inventory.stage().unwrap().identity().into(),
	};
	let stage = lease.read_retained_prefix(&inventory, selection).unwrap();
	assert_eq!(stage.length(), ADOPTED_END);
	let plan =
		WitnessReservationPlan::new(frames.prior, frames.prior.end + 8192, nonzero(16)).unwrap();
	let authority = WitnessReservationAuthority {
		qualification: qualification.digest(),
		base_grant: [0x79; 32],
		retention_approval: [0x80; 32],
	};
	let mut reserved = None;
	let pending = lease
		.reserve_witness_closeout(&eligible, &stage, &expected, plan, authority, |request| {
			if request.effect == WitnessReservationEffect::JournalAllocate {
				reserved = Some((request.journal_directory, request.receipt.unwrap()));
			}
			Ok::<_, Refusal>(())
		})
		.unwrap();
	let (journal_directory, receipt) = reserved.unwrap();
	let synced = stage
		.sync_adopted(ADOPTED_END, |actual, effect| {
			assert_eq!(actual, selection);
			assert_eq!(effect, SuffixEffect::PrefixBarrier { end: ADOPTED_END });
			Ok::<_, Refusal>(())
		})
		.unwrap();
	let mut active = pending
		.append_continuation(
			&synced,
			frames.continued,
			continuation,
			|read| {
				exact(read, &[prior_bytes]);
				Ok(())
			},
			|_| Ok::<_, Refusal>(()),
			|read| {
				exact(read, &[&frames.journal]);
				Ok(())
			},
		)
		.unwrap();
	active.check_before_suffix(&synced).unwrap();
	let mut writer = synced
		.open_suffix_writer(SOURCE_END, |actual, range| {
			assert_eq!(actual, selection);
			assert_eq!(range, ADOPTED_END..SOURCE_END);
			Ok::<_, Refusal>(())
		})
		.unwrap();
	active.check_capture_writer(&writer).unwrap();

	let (mut model, pass, live) = continued_model(frames);
	let permit = model
		.permit_tail(
			live,
			ADOPTED_END,
			1,
			BudgetReservation {
				live,
				tail_end: SOURCE_END,
				checkpoint_end: frames.successor.end,
				closing_bytes: nonzero(2048),
				closing_frames: nonzero(9),
				receipt_bytes: nonzero(active.receipt_capacity()),
				receipt_capacity: active.receipt_capacity(),
			},
		)
		.unwrap();
	writer
		.begin_range(&permit, |_| Ok::<_, Refusal>(()))
		.unwrap();
	writer
		.write_next(&source[PREFIX.len()..], |actual, effect| {
			assert_eq!(actual, selection);
			assert_eq!(
				effect,
				SuffixEffect::Write {
					offset: ADOPTED_END,
					length: 1,
				}
			);
			Ok::<_, Refusal>(())
		})
		.unwrap();
	assert_eq!(
		writer
			.sync_range(|actual, effect| {
				assert_eq!(actual, selection);
				assert_eq!(effect, SuffixEffect::CheckpointBarrier { end: SOURCE_END });
				Ok::<_, Refusal>(())
			})
			.unwrap(),
		SOURCE_END
	);
	let completed = Live {
		local_end: SOURCE_END,
		..live
	};
	model.complete_tail(completed, permit).unwrap();

	let proof = writer.checkpoint_proof().unwrap();
	assert_eq!(proof.range(), &(ADOPTED_END..SOURCE_END));
	let trace = RefCell::new(Vec::new());
	let mut successor = frames.successor;
	if case == Case::OutOfBounds {
		successor.end += 1;
	}
	let outcome = active.append_checkpoint(
		&proof,
		successor,
		&frames.checkpoint,
		|read| {
			exact(read, &[&frames.journal]);
			trace.borrow_mut().push(Step::Prior);
			Ok(())
		},
		|request| {
			assert_eq!(request.previous, frames.continued);
			assert_eq!(request.successor, frames.successor);
			assert_eq!(request.plan, plan);
			assert_eq!(request.stage, selection);
			assert_eq!(request.segment, expected.identity());
			assert_eq!(request.destination, root.identity());
			assert_eq!(request.job, job_id);
			assert_eq!(request.journal_directory, journal_directory);
			assert_eq!(request.receipt, receipt);
			assert_eq!(request.authority, authority);
			trace.borrow_mut().push(Step::Enter);
			if case == Case::AdmissionRefused {
				return Err(Refusal::Authority);
			}
			Ok(AppendGuard(&trace))
		},
		|read| {
			assert_eq!(*trace.borrow(), [Step::Prior, Step::Enter, Step::Release]);
			exact(read, &[&frames.journal, &frames.checkpoint]);
			trace.borrow_mut().push(Step::Reread);
			if case == Case::RereadRefused {
				return Err(Refusal::Successor);
			}
			Ok(())
		},
	);
	match case {
		Case::Accepted => {
			outcome.unwrap();
			assert_eq!(active.head(), frames.successor);
			active.check_active().unwrap();
		}
		Case::OutOfBounds => assert!(matches!(outcome, Err(ContinuationReservationError::Bounds))),
		Case::AdmissionRefused => assert!(matches!(
			outcome,
			Err(ContinuationReservationError::Admission(Refusal::Authority))
		)),
		Case::RereadRefused => assert!(matches!(
			outcome,
			Err(ContinuationReservationError::SuccessorReplay(
				Refusal::Successor
			))
		)),
	}
	let all = [Step::Prior, Step::Enter, Step::Release, Step::Reread];
	let expected_steps = match case {
		Case::Accepted | Case::RereadRefused => &all[..],
		Case::AdmissionRefused => &all[..2],
		Case::OutOfBounds => &all[..0],
	};
	assert_eq!(trace.borrow().as_slice(), expected_steps);

	if case == Case::Accepted {
		model
			.checkpoint(
				Live {
					head: active.head(),
					..completed
				},
				Checkpoint {
					lineage: frames.continued,
					predecessor: frames.continued,
					ordinal: 1,
					head: frames.successor,
					pass,
					guard: live.guard,
					start: ADOPTED_END,
					end: SOURCE_END,
				},
			)
			.unwrap();
		writer
			.confirm_checkpoint(|end| {
				assert_eq!(end, SOURCE_END);
				assert_eq!(active.head(), frames.successor);
				Ok::<_, Refusal>(())
			})
			.unwrap();
		let readback = writer.finish().unwrap();
		let mut actual = [0; FULL.len()];
		readback.read_exact_at(0, &mut actual).unwrap();
		assert_eq!(&actual, FULL);
		assert_eq!(readback.length(), SOURCE_END);
		readback.recheck_observation().unwrap();
	} else {
		assert_eq!(active.head(), frames.continued);
		assert!(matches!(
			active.append_checkpoint(
				&proof,
				frames.successor,
				&frames.checkpoint,
				|_| -> Result<(), Refusal> { panic!("retired reservation replayed prior bytes") },
				|_| -> Result<(), Refusal> { panic!("retired reservation reached append gate") },
				|_| -> Result<(), Refusal> {
					panic!("retired reservation replayed successor bytes")
				},
			),
			Err(ContinuationReservationError::Preflight(
				WitnessReservationObservationError::Native(StageError::PriorBarrierFailure)
			))
		));
		assert!(matches!(writer.finish(), Err(StageError::Unflushed)));
	}

	let observed = job.open_first_segment().unwrap();
	assert_eq!(observed.identity(), expected.identity());
	let mut literal = vec![frames.journal.as_slice()];
	if matches!(case, Case::Accepted | Case::RereadRefused) {
		literal.push(&frames.checkpoint);
	}
	exact(File::open(&journal_path).unwrap(), &literal);
	for (path, id, content) in [
		(&stage_path, stage_id, FULL.as_slice()),
		(&source_path, source_id, FULL.as_slice()),
		(&incumbent_path, incumbent_id, b"do not replace"),
	] {
		assert_eq!(identity(path), id);
		assert_eq!(fs::read(path).unwrap().as_slice(), content);
	}
	assert_eq!(identity(&journal_path), segment_id);
	assert_eq!(
		fs::symlink_metadata(scratch.path(TARGET))
			.unwrap_err()
			.kind(),
		io::ErrorKind::NotFound
	);
}

fn continued_model(frames: &Frames) -> (Continuation, Pass, Live) {
	let guard = Guard {
		authority: [1; 32],
		stage: [2; 32],
		lease: [3; 32],
	};
	let pass = Pass {
		run: nonzero(2),
		source: nonzero(9),
	};
	let prior = Prior {
		guard,
		head: frames.prior,
		preparation: boundary(4, 1339, &frames.journal[..1339]),
		pass: Pass {
			run: nonzero(1),
			source: nonzero(7),
		},
		checkpoint_end: 2,
		authorized_end: ADOPTED_END,
		history: History::CleanCapture,
		writer_quiesced: true,
	};
	let proof = PrefixProof {
		local_end: ADOPTED_END,
		compared_end: ADOPTED_END,
		rehashed_end: 2,
		digest: hex("f3dd21f0f2a842321e46fd8656d154b5eb1edda694a962399b683b9fb21a58df")
			.try_into()
			.unwrap(),
	};
	let mut state = Continuation::begin(prior, pass, proof, SOURCE_END).unwrap();
	let live = Live {
		guard,
		head: frames.prior,
		source: pass.source,
		local_end: ADOPTED_END,
	};
	state.prefix_barrier(live, state.basis()).unwrap();
	let live = Live {
		head: frames.continued,
		..live
	};
	state
		.continued(live, state.basis(), frames.continued)
		.unwrap();
	(state, pass, live)
}

fn nonzero(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}

fn plant(path: &Path, content: &[u8]) {
	File::create_new(path).unwrap().write_all(content).unwrap();
}

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::symlink_metadata(path).unwrap();
	assert!(metadata.is_file());
	(metadata.dev(), metadata.ino())
}

fn exact(mut read: impl Read, parts: &[&[u8]]) {
	for part in parts {
		let mut bytes = vec![0; part.len()];
		read.read_exact(&mut bytes).unwrap();
		assert_eq!(bytes.as_slice(), *part);
	}
	assert_eq!(read.read(&mut [0]).unwrap(), 0);
}
