//! Verify semantic admission on actual integrity-chained frames.

use std::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameProblem, FrameReadError, FrameWriter};
use exacopy_journal::remote_download::replay::{
	MAX_REMOTE_REPLAY_ATTEMPTS, RemoteReplayBoundary, RemoteReplayIssue as Issue,
	RemoteReplayMismatch as Mismatch, RemoteReplayState as State, replay_remote_download,
};
use exacopy_journal::remote_download::{
	RemoteDownloadBody as Body, RemoteDownloadContext, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteEpochs, RemoteScopeDigest, RemoteSourceObservation,
	RemoteUncertainBoundary as Boundary,
};
use exacopy_journal::{LinuxFileIdentity, OwnerDigest, OwnerProfileId, StreamDigest, StreamLength};

struct Transcript {
	owner: RemoteDownloadOwnerRecord,
	bytes: Vec<u8>,
	head: ChainHead,
	context: RemoteDownloadContext,
}

impl Transcript {
	fn new() -> Self {
		let text = include_str!("remote_download/owner.hex");
		let ascii = text.split_ascii_whitespace().collect::<String>();
		let (pairs, remainder) = ascii.as_bytes().as_chunks::<2>();
		assert!(remainder.is_empty(), "fixture must contain complete octets");
		let bytes: Vec<u8> = pairs
			.iter()
			.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
			.collect();
		let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
		let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
		let owner = RemoteDownloadOwnerRecord::decode(&bytes, profile, &key).unwrap();
		let context = RemoteDownloadContext {
			owner: owner.digest(),
			job: owner.manifest().job,
			entry: owner.manifest().scope.entry,
		};
		Self {
			owner,
			bytes: Vec::new(),
			head: ChainHead::start(),
			context,
		}
	}

	fn append(&mut self, body: Body<'_>) -> ChainHead {
		let mut writer = FrameWriter::new(&mut self.bytes, self.head);
		self.head = append(&mut writer, self.context, body);
		self.head
	}

	fn job(&mut self) -> ChainHead {
		self.append(Body::JobPrepared {
			scope: self.owner.manifest().scope.digest().unwrap(),
		})
	}

	fn allocation(&mut self, run: u64, nonce: u8) -> ChainHead {
		self.append(allocate(
			run.checked_sub(1).filter(|run| *run > 0).map(epochs),
			run,
			format!("attempt-{nonce}").as_bytes(),
			nonce,
			11,
		))
	}

	fn offset(&self) -> u64 {
		u64::try_from(self.bytes.len()).unwrap()
	}

	fn bytes(self) -> Vec<u8> {
		self.bytes
	}

	fn assert_refusal(&mut self, body: Body<'_>, expected: Mismatch) {
		let accepted = RemoteReplayBoundary {
			head: self.head,
			offset: u64::try_from(self.bytes.len()).unwrap(),
		};
		self.append(body);
		let replay = replay_remote_download(self.bytes.as_slice(), &self.owner).unwrap();
		assert_eq!(replay.boundary(), accepted);
		assert!(
			matches!(
				replay.state(),
				State::ReconciliationRequired(Issue::Record { problem, .. }) if *problem == expected
			),
			"{:?}",
			replay.state()
		);
	}
}

fn append(
	writer: &mut FrameWriter<impl std::io::Write>,
	context: RemoteDownloadContext,
	body: Body<'_>,
) -> ChainHead {
	let predecessor = writer.head();
	let payload = RemoteDownloadRecord::new(
		context,
		(predecessor != ChainHead::start()).then_some(predecessor),
		body,
	)
	.unwrap()
	.encode()
	.unwrap();
	writer.append(body.kind(), &payload).unwrap()
}

fn epochs(run: u64) -> RemoteEpochs {
	RemoteEpochs {
		run: NonZeroU64::new(run).unwrap(),
		source: NonZeroU64::new(run + 21).unwrap(),
	}
}

fn allocate(
	previous: Option<RemoteEpochs>,
	run: u64,
	name: &[u8],
	nonce: u8,
	extent: u64,
) -> Body<'_> {
	Body::StageAllocated {
		previous,
		next: epochs(run),
		name: UnixComponent::new(name).unwrap(),
		nonce: [nonce; 16],
		source: RemoteSourceObservation::new(StreamLength::new(extent).unwrap(), 0o100644, 15)
			.unwrap(),
	}
}

fn prepared(
	allocation: ChainHead,
	run: u64,
	nonce: u8,
	directory: u64,
	file: u64,
) -> Body<'static> {
	Body::EntryPrepared {
		allocation,
		epochs: epochs(run),
		nonce: [nonce; 16],
		stage_directory: LinuxFileIdentity::new(7, directory),
		stage: LinuxFileIdentity::new(7, file),
	}
}

fn checkpoint(
	prepared: ChainHead,
	run: u64,
	ordinal: u16,
	offset: u64,
	length: u64,
) -> Body<'static> {
	Body::RangeCheckpoint {
		prepared,
		epochs: epochs(run),
		ordinal,
		offset,
		length,
		digest: StreamDigest::from_bytes([0xb7; 32]),
	}
}

#[test]
fn framed_replay_burns_allocations_and_keeps_only_exact_active_progress() {
	let mut transcript = Transcript::new();
	let job = transcript.job();
	let superseded = transcript.allocation(1, 1);
	let prior = transcript.allocation(2, 2);
	let prior_prepared = transcript.append(prepared(prior, 2, 2, 12, 13));
	transcript.append(checkpoint(prior_prepared, 2, 1, 0, 4));
	let active = transcript.allocation(3, 3);
	let active_prepared = transcript.append(prepared(active, 3, 3, 12, 14));
	transcript.append(checkpoint(active_prepared, 3, 1, 0, 7));
	let end = transcript.append(checkpoint(active_prepared, 3, 2, 7, 4));
	let owner = transcript.owner.clone();
	let bytes = transcript.bytes();

	let replay = replay_remote_download(bytes.as_slice(), &owner).unwrap();
	assert_eq!(replay.job_prepared(), Some(job));
	assert_eq!(
		replay.boundary(),
		RemoteReplayBoundary {
			head: end,
			offset: bytes.len() as u64
		}
	);
	assert!(matches!(replay.state(), State::StageBound));
	let [first, second, third] = replay.attempts() else {
		panic!("exactly three consumed allocations")
	};
	assert_eq!(
		(first.allocation(), first.prepared(), first.covered_extent()),
		(superseded, None, 0)
	);
	assert_eq!(second.prepared().unwrap().head, prior_prepared);
	assert_eq!((second.checkpoint_count(), second.covered_extent()), (1, 4));
	assert_eq!(third.prepared().unwrap().head, active_prepared);
	assert_eq!((third.checkpoint_count(), third.covered_extent()), (2, 11));
	assert_eq!(third.source().length().get(), 11);
	assert_eq!(third.name(), b"attempt-3");
	assert_eq!(third.nonce(), &[3; 16]);
	assert_eq!(third.epochs(), epochs(3));
}

#[test]
fn all_byte_cuts_retain_only_complete_semantic_boundaries() {
	let mut transcript = Transcript::new();
	let job = transcript.job();
	let job_offset = transcript.offset();
	let allocation = transcript.allocation(1, 1);
	let allocation_offset = transcript.offset();
	let prepared = transcript.append(prepared(allocation, 1, 1, 12, 13));
	let prepared_offset = transcript.offset();
	let covered = transcript.append(checkpoint(prepared, 1, 1, 0, 7));
	let covered_offset = transcript.offset();
	let failed = transcript.append(Body::FailureRecorded {
		attempt: prepared,
		epochs: epochs(1),
		boundary: Boundary::CheckpointAppend,
	});
	let failed_offset = transcript.offset();
	let owner = transcript.owner.clone();
	let bytes = transcript.bytes();
	let exact_cuts = [
		(0, ChainHead::start()),
		(job_offset, job),
		(allocation_offset, allocation),
		(prepared_offset, prepared),
		(covered_offset, covered),
		(failed_offset, failed),
	];

	for cut in 0..=bytes.len() {
		let scan = replay_remote_download(&bytes[..cut], &owner).unwrap();
		let cut = cut as u64;
		let (offset, head) = *exact_cuts
			.iter()
			.rev()
			.find(|(offset, _)| *offset <= cut)
			.unwrap();
		assert_eq!(scan.boundary(), RemoteReplayBoundary { head, offset });
		if cut > offset {
			assert!(
				matches!(scan.state(), State::ReconciliationRequired(Issue::Framing(
				FrameReadError::TornTail { offset: torn, bytes_read })
			) if *torn == offset && *bytes_read as u64 == cut - offset)
			);
		} else {
			assert!(match scan.state() {
				State::Empty => cut == 0,
				State::JobPrepared => cut == job_offset,
				State::AllocationUnbound => cut == allocation_offset,
				State::StageBound => cut == prepared_offset || cut == covered_offset,
				State::ReconciliationRequired(Issue::RecordedUncertainty) => cut == failed_offset,
				_ => false,
			});
		}
		assert_eq!(scan.recorded_uncertainty().is_some(), cut == failed_offset);
	}
}

#[test]
fn rejects_forged_predecessor_sequence_even_when_digest_matches() {
	let mut transcript = Transcript::new();
	let job = transcript.job();
	let offset = transcript.offset();
	let owner = transcript.owner.clone();
	let context = transcript.context;
	let mut bytes = transcript.bytes();
	let forged = ChainHead::after(job.sequence() + 1, job.digest()).unwrap();
	let mut suffix = FrameWriter::new(Vec::new(), forged);
	append(&mut suffix, context, allocate(None, 1, b"fresh", 1, 11));
	bytes.extend(suffix.into_inner());
	let replay = replay_remote_download(bytes.as_slice(), &owner).unwrap();
	assert_eq!(
		replay.boundary(),
		RemoteReplayBoundary { head: job, offset }
	);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::Record {
			problem: Mismatch::Predecessor,
			..
		})
	));
}

#[test]
fn authenticated_scope_and_consumed_allocations_gate_every_new_attempt() {
	let mut foreign = Transcript::new();
	foreign.context.owner = OwnerDigest::from_bytes([0x83; 32]);
	let scope = foreign.owner.manifest().scope.digest().unwrap();
	foreign.assert_refusal(Body::JobPrepared { scope }, Mismatch::Context);
	Transcript::new().assert_refusal(
		Body::JobPrepared {
			scope: RemoteScopeDigest::from_bytes([0x55; 32]),
		},
		Mismatch::Scope,
	);

	let mut outside_scope = Transcript::new();
	outside_scope.job();
	let over = outside_scope.owner.manifest().scope.maximum_extent.get() + 1;
	outside_scope.assert_refusal(allocate(None, 1, b"first", 1, over), Mismatch::Allocation);

	for (previous, run, name, nonce) in [
		(Some(epochs(1)), 2, b"untouched".as_slice(), 3),
		(Some(epochs(2)), 3, b"attempt-1".as_slice(), 3),
		(Some(epochs(2)), 3, b"untouched".as_slice(), 1),
	] {
		let mut transcript = Transcript::new();
		transcript.job();
		transcript.allocation(1, 1);
		transcript.allocation(2, 2);
		transcript.assert_refusal(
			allocate(previous, run, name, nonce, 11),
			Mismatch::Allocation,
		);
	}
}

#[test]
fn rejects_rebound_local_objects_and_unrelated_stage_epoch() {
	for (run, nonce, directory, file) in [
		(1, 2, 12, 13),
		(2, 1, 12, 13),
		(1, 1, 9, 13),
		(1, 1, 11, 13),
		(1, 1, 12, 9),
		(1, 1, 12, 11),
	] {
		let mut transcript = Transcript::new();
		transcript.job();
		let allocation = transcript.allocation(1, 1);
		transcript.assert_refusal(
			prepared(allocation, run, nonce, directory, file),
			Mismatch::StageBinding,
		);
	}
	for (directory, file) in [(12, 13), (14, 15)] {
		let mut transcript = Transcript::new();
		transcript.job();
		let first = transcript.allocation(1, 1);
		transcript.append(prepared(first, 1, 1, 12, 13));
		let next = transcript.allocation(2, 2);
		transcript.assert_refusal(
			prepared(next, 2, 2, directory, file),
			Mismatch::StageBinding,
		);
	}
}

#[test]
fn rejects_wrong_checkpoint_anchor_epoch_ordinal_gap_overlap_and_extent() {
	for (ordinal, offset, length) in [(2, 3, 4), (2, 5, 4), (2, 4, 8), (3, 4, 4)] {
		let mut transcript = Transcript::new();
		transcript.job();
		let allocation = transcript.allocation(1, 1);
		let bound = transcript.append(prepared(allocation, 1, 1, 12, 13));
		transcript.append(checkpoint(bound, 1, 1, 0, 4));
		transcript.assert_refusal(
			checkpoint(bound, 1, ordinal, offset, length),
			Mismatch::Checkpoint,
		);
	}
	for (wrong_anchor, run) in [(true, 1), (false, 2)] {
		let mut transcript = Transcript::new();
		transcript.job();
		let allocation = transcript.allocation(1, 1);
		let bound = transcript.append(prepared(allocation, 1, 1, 12, 13));
		let anchor = if wrong_anchor {
			ChainHead::after(bound.sequence() - 1, [0x36; 32]).unwrap()
		} else {
			bound
		};
		transcript.assert_refusal(checkpoint(anchor, run, 1, 0, 4), Mismatch::Checkpoint);
	}
}

#[test]
fn recorded_uncertainty_is_phase_bound_and_latched_across_bad_suffixes() {
	let mut wrong = Transcript::new();
	wrong.job();
	let allocation = wrong.allocation(1, 1);
	wrong.assert_refusal(
		Body::FailureRecorded {
			attempt: allocation,
			epochs: epochs(1),
			boundary: Boundary::TerminalSource,
		},
		Mismatch::FailureBinding,
	);

	let mut transcript = Transcript::new();
	transcript.job();
	let allocation = transcript.allocation(1, 1);
	let failure = transcript.append(Body::FailureRecorded {
		attempt: allocation,
		epochs: epochs(1),
		boundary: Boundary::Creation,
	});
	let boundary = RemoteReplayBoundary {
		head: failure,
		offset: transcript.offset(),
	};
	transcript.allocation(2, 2);
	let owner = transcript.owner.clone();
	let mut bytes = transcript.bytes();
	let replay = replay_remote_download(bytes.as_slice(), &owner).unwrap();
	assert_eq!(replay.boundary(), boundary);
	assert_eq!(replay.recorded_uncertainty().unwrap().attempt, allocation);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::Record {
			problem: Mismatch::AfterUncertainty,
			..
		})
	));

	let kind_offset = usize::try_from(boundary.offset).unwrap() + 10;
	bytes[kind_offset..kind_offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
	let replay = replay_remote_download(bytes.as_slice(), &owner).unwrap();
	assert_eq!(replay.boundary(), boundary);
	assert_eq!(replay.recorded_uncertainty().unwrap().head, failure);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::Framing(FrameReadError::Corrupt {
			problem: FrameProblem::UnsupportedKind(u16::MAX),
			..
		}))
	));
}

#[test]
fn alien_kinds_and_attempt_limit_stop_before_the_rejected_record() {
	let mut alien = Transcript::new();
	let job = alien.job();
	FrameWriter::new(&mut alien.bytes, job)
		.append(FrameKind::PublishIntent, &[0])
		.unwrap();
	let owner = alien.owner.clone();
	let replay = replay_remote_download(alien.bytes().as_slice(), &owner).unwrap();
	assert_eq!(replay.boundary().head, job);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::Record {
			problem: Mismatch::UnsupportedKind,
			..
		})
	));

	let mut bounded = Transcript::new();
	bounded.job();
	for run in 1..=MAX_REMOTE_REPLAY_ATTEMPTS {
		bounded.allocation(run as u64, u8::try_from(run).unwrap());
	}
	let last_admitted = bounded.head;
	let extra = MAX_REMOTE_REPLAY_ATTEMPTS + 1;
	bounded.allocation(extra as u64, u8::try_from(extra).unwrap());
	let owner = bounded.owner.clone();
	let replay = replay_remote_download(bounded.bytes().as_slice(), &owner).unwrap();
	assert_eq!(replay.boundary().head, last_admitted);
	assert_eq!(replay.attempts().len(), MAX_REMOTE_REPLAY_ATTEMPTS);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::AttemptLimit)
	));
}
