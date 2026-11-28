use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use exacopy_endpoint::ReadView as _;
use exacopy_model::retained_prefix::Head;

use crate::linux::{
	ActiveWitnessReservation, ContinuationReservationError, ProtectedWitnessEffect,
	ReservedContinuationRequest, SealedProtectedWitness, StageError, WitnessLinkCandidate,
	WitnessPrepublicationAppend, WitnessPrepublicationPhase as Phase,
	WitnessReservationObservationError,
};

// The codec and grant issuer are outside this native component fixture.
const WITNESS_NAME: [u8; 40] = *b"witness.0102030405060708090a0b0c0d0e0f10";
const WITNESS_FRAME: &[u8] = &[0x41; 128];
const SEAL_FRAME: &[u8] = &[0x04; 128];
const VERIFY_FRAME: &[u8] = &[0x05; 128];
const METADATA_FRAME: &[u8] = &[0x06; 128];
const INTENT_FRAME: &[u8] = &[0x07; 128];

pub(super) enum Outcome {
	Accepted,
	SuccessorRefused,
}

pub(super) struct WitnessFixture<'a> {
	pub(super) binding: ReservedContinuationRequest<'a>,
	pub(super) journal_prefix: &'a [&'a [u8]],
	pub(super) expected_bytes: &'a [u8],
	pub(super) stage_path: &'a Path,
	pub(super) journal_path: &'a Path,
	pub(super) target_path: &'a Path,
}

#[derive(Debug)]
enum Refusal {
	Admission,
	Successor,
}

#[derive(Clone, Copy)]
enum AppendOutcome {
	Accepted,
	AdmissionRefused,
	SuccessorRefused,
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

/// Exercises the native witness using the actual completed positive-tail writer.
pub(super) fn exercise<'view, 'lease>(
	active: ActiveWitnessReservation<'lease>,
	stage: WitnessLinkCandidate<'view, 'lease>,
	fixture: WitnessFixture<'_>,
	outcome: Outcome,
) {
	let stage_name = fs::symlink_metadata(fixture.stage_path).unwrap();
	assert!(stage_name.is_file());
	assert_eq!(stage_name.nlink(), 1);
	assert_eq!(
		stage_name.len(),
		u64::try_from(fixture.expected_bytes.len()).unwrap()
	);
	let journal_name = fs::symlink_metadata(fixture.journal_path).unwrap();
	assert!(journal_name.is_file());
	let witness_path = fixture
		.stage_path
		.parent()
		.unwrap()
		.parent()
		.unwrap()
		.join(OsStr::from_bytes(&WITNESS_NAME));
	absent(&witness_path);
	absent(fixture.target_path);

	let previous = active.head();
	assert_eq!(previous, fixture.binding.previous);
	let witness = proposed(previous, WITNESS_FRAME);
	let mut journal_bytes = fixture.journal_prefix.to_vec();
	exact(active.replay_for_witness(&stage).unwrap(), &journal_bytes);
	journal_bytes.push(WITNESS_FRAME);
	let pending = active
		.append_witness_intent(
			stage,
			witness.successor,
			witness.encoded,
			WITNESS_NAME,
			|request| {
				check_request(request, fixture.binding, witness);
				Ok::<_, Refusal>(())
			},
			|read| {
				exact(read, &journal_bytes);
				Ok(WITNESS_NAME)
			},
		)
		.unwrap();

	let mut link_effects = Vec::new();
	let mut sealed = pending
		.link_protected_witness(|head, effect| {
			assert_eq!(head, witness.successor);
			link_effects.push(effect);
			Ok::<_, Refusal>(())
		})
		.unwrap();
	assert_eq!(
		link_effects,
		[
			ProtectedWitnessEffect::Link,
			ProtectedWitnessEffect::FileBarrier,
			ProtectedWitnessEffect::JobBarrier,
		]
	);
	assert_eq!(sealed.head(), witness.successor);
	assert_eq!(sealed.plan(), fixture.binding.plan);
	assert_eq!(sealed.authority(), fixture.binding.authority);
	exact(
		sealed.read_prepublication(witness.successor).unwrap(),
		&journal_bytes,
	);

	let seal = proposed(witness.successor, SEAL_FRAME);
	assert!(matches!(
		forbid_callbacks(&mut sealed, Phase::Verify, seal),
		Err(ContinuationReservationError::Preflight(
			WitnessReservationObservationError::Native(StageError::IdentityChanged)
		))
	));
	assert!(matches!(
		append(
			&mut sealed,
			Phase::Seal,
			seal,
			&journal_bytes,
			fixture.binding,
			AppendOutcome::AdmissionRefused
		),
		Err(ContinuationReservationError::Admission(Refusal::Admission))
	));
	assert_eq!(sealed.head(), witness.successor);
	exact(
		sealed.read_prepublication(witness.successor).unwrap(),
		&journal_bytes,
	);
	exact(File::open(fixture.journal_path).unwrap(), &journal_bytes);

	match outcome {
		Outcome::Accepted => {
			for (phase, frame) in [
				(Phase::Seal, SEAL_FRAME),
				(Phase::Verify, VERIFY_FRAME),
				(Phase::Metadata, METADATA_FRAME),
				(Phase::Intent, INTENT_FRAME),
			] {
				let next = proposed(sealed.head(), frame);
				if phase == Phase::Metadata {
					let metadata = sealed.check_witnessed_metadata(next.previous).unwrap();
					assert_eq!(metadata.identity().inode(), stage_name.ino());
					assert_eq!(metadata.mode(), stage_name.mode() & 0o7777);
					assert_eq!(metadata.owner(), stage_name.uid());
					assert_eq!(metadata.group(), stage_name.gid());
					assert_eq!(metadata.len(), stage_name.len());
					assert_eq!(metadata.link_count(), 2);
				}
				append(
					&mut sealed,
					phase,
					next,
					&journal_bytes,
					fixture.binding,
					AppendOutcome::Accepted,
				)
				.unwrap();
				assert_eq!(sealed.head(), next.successor);
				journal_bytes.push(frame);
			}
			let head = sealed.head();
			exact(sealed.read_prepublication(head).unwrap(), &journal_bytes);
			assert!(matches!(
				forbid_callbacks(&mut sealed, Phase::Intent, proposed(head, INTENT_FRAME)),
				Err(ContinuationReservationError::Preflight(
					WitnessReservationObservationError::Native(StageError::IdentityChanged)
				))
			));
		}
		Outcome::SuccessorRefused => {
			assert!(matches!(
				append(
					&mut sealed,
					Phase::Seal,
					seal,
					&journal_bytes,
					fixture.binding,
					AppendOutcome::SuccessorRefused
				),
				Err(ContinuationReservationError::SuccessorReplay(
					Refusal::Successor
				))
			));
			journal_bytes.push(SEAL_FRAME);
			assert_eq!(sealed.head(), witness.successor);
			assert!(matches!(
				sealed.read_prepublication(witness.successor),
				Err(WitnessReservationObservationError::Native(
					StageError::PriorBarrierFailure
				))
			));
			assert!(matches!(
				forbid_callbacks(&mut sealed, Phase::Seal, seal),
				Err(ContinuationReservationError::Preflight(
					WitnessReservationObservationError::Native(StageError::PriorBarrierFailure)
				))
			));
		}
	}

	sealed.stage().recheck_observation().unwrap();
	assert_eq!(sealed.stage().length(), stage_name.len());
	let mut readback = vec![0; fixture.expected_bytes.len()];
	sealed.stage().read_exact_at(0, &mut readback).unwrap();
	assert_eq!(readback, fixture.expected_bytes);
	for path in [fixture.stage_path, &witness_path] {
		let name = fs::symlink_metadata(path).unwrap();
		assert!(name.is_file());
		assert_eq!(
			(name.dev(), name.ino()),
			(stage_name.dev(), stage_name.ino())
		);
		assert_eq!(name.nlink(), 2);
		assert_eq!(name.mode(), stage_name.mode());
		assert_eq!(fs::read(path).unwrap(), fixture.expected_bytes);
	}
	let journal = fs::symlink_metadata(fixture.journal_path).unwrap();
	assert_eq!(
		(journal.dev(), journal.ino()),
		(journal_name.dev(), journal_name.ino())
	);
	exact(File::open(fixture.journal_path).unwrap(), &journal_bytes);
	absent(fixture.target_path);
}

fn proposed(previous: Head, encoded: &[u8]) -> WitnessPrepublicationAppend<'_> {
	WitnessPrepublicationAppend {
		previous,
		successor: Head {
			sequence: previous.sequence + 1,
			digest: [encoded[0]; 32],
			end: previous.end + u64::try_from(encoded.len()).unwrap(),
		},
		encoded,
	}
}

fn check_request(
	actual: ReservedContinuationRequest<'_>,
	binding: ReservedContinuationRequest<'_>,
	proposed: WitnessPrepublicationAppend<'_>,
) {
	assert_eq!(
		actual,
		ReservedContinuationRequest {
			previous: proposed.previous,
			successor: proposed.successor,
			..binding
		}
	);
}

fn forbid_callbacks(
	sealed: &mut SealedProtectedWitness<'_, '_>,
	phase: Phase,
	proposed: WitnessPrepublicationAppend<'_>,
) -> Result<(), ContinuationReservationError<Refusal>> {
	sealed.append_prepublication(
		phase,
		proposed,
		|_| panic!("refused phase reached prior replay"),
		|_| -> Result<(), Refusal> { panic!("refused phase reached the append gate") },
		|_| panic!("refused phase reached successor replay"),
	)
}

fn append(
	sealed: &mut SealedProtectedWitness<'_, '_>,
	phase: Phase,
	proposed: WitnessPrepublicationAppend<'_>,
	prior: &[&[u8]],
	binding: ReservedContinuationRequest<'_>,
	outcome: AppendOutcome,
) -> Result<(), ContinuationReservationError<Refusal>> {
	let trace = RefCell::new(Vec::new());
	let mut successor = prior.to_vec();
	successor.push(proposed.encoded);
	let result = sealed.append_prepublication(
		phase,
		proposed,
		|read| {
			exact(read, prior);
			trace.borrow_mut().push(Step::Prior);
			Ok(())
		},
		|request| {
			assert_eq!(*trace.borrow(), [Step::Prior]);
			check_request(request, binding, proposed);
			trace.borrow_mut().push(Step::Enter);
			if matches!(outcome, AppendOutcome::AdmissionRefused) {
				return Err(Refusal::Admission);
			}
			Ok(AppendGuard(&trace))
		},
		|read| {
			assert_eq!(*trace.borrow(), [Step::Prior, Step::Enter, Step::Release]);
			exact(read, &successor);
			trace.borrow_mut().push(Step::Reread);
			if matches!(outcome, AppendOutcome::SuccessorRefused) {
				return Err(Refusal::Successor);
			}
			Ok(())
		},
	);
	let steps = [Step::Prior, Step::Enter, Step::Release, Step::Reread];
	let expected = match outcome {
		AppendOutcome::AdmissionRefused => &steps[..2],
		AppendOutcome::Accepted | AppendOutcome::SuccessorRefused => &steps[..],
	};
	assert_eq!(trace.borrow().as_slice(), expected);
	result
}

fn exact(mut read: impl Read, parts: &[&[u8]]) {
	for part in parts {
		let mut bytes = vec![0; part.len()];
		read.read_exact(&mut bytes).unwrap();
		assert_eq!(bytes.as_slice(), *part);
	}
	assert_eq!(read.read(&mut [0]).unwrap(), 0);
}

fn absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).unwrap_err().kind(),
		ErrorKind::NotFound
	);
}
