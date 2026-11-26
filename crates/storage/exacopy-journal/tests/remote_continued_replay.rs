//! Independent continued replay vectors and historical refusal controls.

use std::cell::Cell;
use std::io::{self, Read};
use std::num::NonZeroU64;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind, FrameProblem, FrameReadError, FrameReader,
	FrameWriter,
};
use exacopy_journal::remote_download::continuation::checkpoint::{
	RemoteContinuedCheckpoint, RemoteContinuedRange,
};
use exacopy_journal::remote_download::continuation::replay::{
	RemoteContinuationReplay, RemoteContinuationSelection, RemoteContinuationState,
	replay_remote_continuation,
};
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	VerifiedRemoteContinuationQualification, verify_remote_continuation_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass as Route, RemoteQualificationScope,
};
use exacopy_journal::remote_download::replay::{
	RemoteReplayBoundary, RemoteReplayIssue, RemoteReplayMismatch,
};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadBody, RemoteDownloadError as Error,
	RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteEpochs, RemoteUncertainBoundary,
};
use exacopy_journal::{OwnerDigest, OwnerProfileId, StreamDigest};

#[path = "remote_continuation/replay_controls.rs"]
mod replay_controls;

const LEGACY_QUALIFICATION: [u8; 32] = [0x71; 32];
const GRANT: [u8; 32] = [0x72; 32];
const QUALIFICATION: &str = include_str!("remote_continuation/replay_qualification.hex");

fn hex(text: &str) -> Vec<u8> {
	let text = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn qualification(
	fixture: &str,
	route: Route,
	owner: &VerifyingKey,
) -> VerifiedRemoteContinuationQualification {
	let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
	verify_remote_continuation_qualification(
		&hex(fixture),
		&RemoteContinuationQualificationTrust {
			attestor: [0x31; 16],
			attestor_key: &attestor,
			owner_key: owner,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: [0x61; 32],
					route,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendV1,
				coverage: RemoteContinuationCoverageProfile::RetainedAppendProcessCrashV1,
			},
		},
	)
	.unwrap()
}

struct Fixture {
	owner: RemoteDownloadOwnerRecord,
	key: VerifyingKey,
	profile: OwnerProfileId,
	qualification: VerifiedRemoteContinuationQualification,
	bytes: Vec<u8>,
	frames: Vec<(Frame, RemoteReplayBoundary)>,
}

impl Fixture {
	fn new() -> Self {
		let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
		let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
		let owner = RemoteDownloadOwnerRecord::decode(
			&hex(include_str!("remote_finalization/owner.hex")),
			profile,
			&key,
		)
		.unwrap();
		let qualification = qualification(QUALIFICATION, Route::EmbeddedWireGuardTcpV1, &key);
		let bytes = hex(include_str!("remote_continuation/replay_journal.hex"));
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		let mut frames = Vec::new();
		while let Some(frame) = reader.next_frame().unwrap() {
			let end = RemoteReplayBoundary {
				head: frame.head(),
				offset: reader.offset(),
			};
			frames.push((frame, end));
		}
		assert_eq!(frames.len(), 8);
		Self {
			owner,
			key,
			profile,
			qualification,
			bytes,
			frames,
		}
	}

	fn trust(&self) -> RemoteBootstrapTrust<'_> {
		RemoteBootstrapTrust::new(&self.owner, self.profile, &self.key).unwrap()
	}

	fn selection(&self) -> RemoteContinuationSelection<'_> {
		RemoteContinuationSelection {
			legacy_qualification: LEGACY_QUALIFICATION,
			qualification: &self.qualification,
			grant_digest: GRANT,
		}
	}

	fn replay(&self, input: impl Read) -> RemoteContinuationReplay {
		replay_remote_continuation(input, &self.trust(), &self.selection()).unwrap()
	}

	fn boundary(&self, sequence: usize) -> RemoteReplayBoundary {
		self.frames[sequence - 1].1
	}

	fn bytes_through(&self, sequence: usize) -> &[u8] {
		&self.bytes[..usize::try_from(self.boundary(sequence).offset).unwrap()]
	}

	fn append(&self, sequence: usize, kind: FrameKind, bytes: &[u8]) -> Vec<u8> {
		let mut writer = FrameWriter::new(
			self.bytes_through(sequence).to_vec(),
			self.boundary(sequence).head,
		);
		writer.append(kind, bytes).unwrap();
		writer.into_inner()
	}

	fn assert_refused(
		&self,
		bytes: &[u8],
		accepted_sequence: usize,
		mismatch: RemoteReplayMismatch,
	) {
		let scan = self.replay(bytes);
		assert_eq!(scan.boundary(), self.boundary(accepted_sequence));
		assert!(
			matches!(
				scan.state(),
				RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Record { problem, .. })
					if *problem == mismatch
			),
			"{:?}",
			scan.state()
		);
	}
}

#[test]
fn independent_history_keeps_aggregate_original_lineage_and_suffix_distinct() {
	let fixture = Fixture::new();
	let scan = fixture.replay(fixture.bytes.as_slice());
	assert_eq!(scan.boundary(), fixture.boundary(8));
	assert_eq!(scan.attempts().len(), 1);
	let original = &scan.attempts()[0];
	assert_eq!(original.epochs().run.get(), 1);
	assert_eq!(original.epochs().source.get(), 7);
	assert_eq!(original.covered_extent(), 2);
	assert_eq!(original.allocation(), fixture.boundary(3).head);
	assert_eq!(original.prepared().unwrap().head, fixture.boundary(4).head);
	let RemoteContinuationState::Continued(active) = scan.state() else {
		panic!("{:?}", scan.state());
	};
	assert_eq!(active.frame().payload(), fixture.frames[5].0.payload());
	assert_eq!(active.admitted_at(), fixture.boundary(6));
	assert_eq!(active.epochs().run.get(), 2);
	assert_eq!(active.epochs().source.get(), 9);
	assert_eq!(active.source().length().get(), 7);
	let (adopted, digest) = active.adopted_prefix();
	assert_eq!(adopted.get(), 4);
	assert_eq!(digest.as_bytes(), blake3::hash(b"ABCD").as_bytes());
	assert_eq!(active.covered_end(), 7);
	let ranges = active.checkpoints();
	assert_eq!(ranges.len(), 2);
	assert_eq!(
		(ranges[0].ordinal(), ranges[0].offset(), ranges[0].length()),
		(1, 4, 1)
	);
	assert_eq!(
		(ranges[1].ordinal(), ranges[1].offset(), ranges[1].length()),
		(2, 5, 2)
	);
	assert_eq!(ranges[1].head(), fixture.boundary(8).head);
	let old = replay_remote_finalization(
		fixture.bytes.as_slice(),
		&fixture.trust(),
		LEGACY_QUALIFICATION,
		None,
	)
	.unwrap();
	assert_eq!(old.boundary(), fixture.boundary(5));
	assert!(old.issue().is_some());
}

#[test]
fn empty_suffix_is_clear_and_every_partial_frame_retains_exact_prior_boundary() {
	let fixture = Fixture::new();
	let zero_tail = hex(include_str!("remote_continuation/replay_zero_tail.hex"));
	let zero = fixture.replay(zero_tail.as_slice());
	let RemoteContinuationState::Continued(active) = zero.state() else {
		panic!("{:?}", zero.state());
	};
	assert_eq!(active.source().length().get(), active.covered_end());
	assert!(active.checkpoints().is_empty());
	for sequence in 5..=7 {
		let start = fixture.bytes_through(sequence).len();
		let end = fixture.bytes_through(sequence + 1).len();
		for cut in start + 1..end {
			let replay = fixture.replay(&fixture.bytes[..cut]);
			assert_eq!(replay.boundary(), fixture.boundary(sequence), "cut {cut}");
			assert!(matches!(
				replay.state(),
				RemoteContinuationState::ReconciliationRequired(_)
			));
		}
	}
}

#[test]
fn signed_wrong_stage_and_external_authority_substitutions_refuse() {
	let fixture = Fixture::new();
	let wrong_stage = hex(include_str!("remote_continuation/replay_wrong_stage.hex"));
	let bytes = fixture.append(5, FrameKind::RemoteCaptureContinued, &wrong_stage);
	fixture.assert_refused(&bytes, 5, RemoteReplayMismatch::StageBinding);

	let trust = fixture.trust();
	let wrong_grant = RemoteContinuationSelection {
		grant_digest: [0x44; 32],
		..fixture.selection()
	};
	let scan = replay_remote_continuation(fixture.bytes.as_slice(), &trust, &wrong_grant).unwrap();
	assert_eq!(scan.boundary(), fixture.boundary(5));
	assert!(matches!(
		scan.state(),
		RemoteContinuationState::ReconciliationRequired(_)
	));

	let other_owner_key = SigningKey::from_bytes(&[0x53; 32]).verifying_key();
	for attestation in [
		qualification(
			include_str!("remote_continuation/replay_wrong_parent.hex"),
			Route::EmbeddedWireGuardTcpV1,
			&fixture.key,
		),
		qualification(
			include_str!("remote_continuation/replay_wrong_route.hex"),
			Route::DirectPinnedTcpV1,
			&fixture.key,
		),
		qualification(
			QUALIFICATION,
			Route::EmbeddedWireGuardTcpV1,
			&other_owner_key,
		),
	] {
		let refused = RemoteContinuationSelection {
			qualification: &attestation,
			..fixture.selection()
		};
		assert!(matches!(
			replay_remote_continuation(PanicRead, &trust, &refused),
			Err(Error::Binding),
		));
	}
	let different_v1 = RemoteContinuationSelection {
		legacy_qualification: *fixture.qualification.digest().as_bytes(),
		..fixture.selection()
	};
	assert!(matches!(
		replay_remote_continuation(PanicRead, &trust, &different_v1),
		Err(Error::Binding),
	));
}

#[test]
fn continued_checkpoint_requires_actual_active_lineage_epochs_context_and_geometry() {
	let fixture = Fixture::new();
	let record = RemoteContinuedCheckpoint::from_frame(&fixture.frames[7].0).unwrap();
	let range = record.range();
	let stale_head = ChainHead::after(record.continuation().sequence(), [0xab; 32]).unwrap();
	let stale_epochs = RemoteEpochs {
		source: NonZeroU64::new(7).unwrap(),
		..record.epochs()
	};
	let mut foreign_context = record.context();
	foreign_context.owner = OwnerDigest::from_bytes([0xa1; 32]);
	for (context, active, epochs, range, reason) in [
		(
			foreign_context,
			record.continuation(),
			record.epochs(),
			range,
			RemoteReplayMismatch::Context,
		),
		(
			record.context(),
			stale_head,
			record.epochs(),
			range,
			RemoteReplayMismatch::Checkpoint,
		),
		(
			record.context(),
			record.continuation(),
			stale_epochs,
			range,
			RemoteReplayMismatch::Checkpoint,
		),
		(
			record.context(),
			record.continuation(),
			record.epochs(),
			RemoteContinuedRange { offset: 4, ..range },
			RemoteReplayMismatch::Checkpoint,
		),
		(
			record.context(),
			record.continuation(),
			record.epochs(),
			RemoteContinuedRange { offset: 6, ..range },
			RemoteReplayMismatch::Checkpoint,
		),
		(
			record.context(),
			record.continuation(),
			record.epochs(),
			RemoteContinuedRange { length: 3, ..range },
			RemoteReplayMismatch::Checkpoint,
		),
	] {
		let payload =
			RemoteContinuedCheckpoint::new(context, record.predecessor(), active, epochs, range)
				.unwrap()
				.encode()
				.unwrap();
		let bytes = fixture.append(7, FrameKind::RangeCheckpoint, &payload);
		fixture.assert_refused(&bytes, 7, reason);
	}
}

#[test]
fn exact_recorded_failure_latches_and_other_suffixes_remain_reconciliation_cases() {
	let fixture = Fixture::new();
	let checkpoint = RemoteContinuedCheckpoint::from_frame(&fixture.frames[6].0).unwrap();
	let head = fixture.boundary(6).head;
	let payload = |attempt, boundary| {
		RemoteDownloadRecord::new(
			checkpoint.context(),
			Some(head),
			RemoteDownloadBody::FailureRecorded {
				attempt,
				epochs: checkpoint.epochs(),
				boundary,
			},
		)
		.unwrap()
		.encode()
		.unwrap()
	};
	let failure = RemoteUncertainBoundary::TerminalSource;
	let bytes = fixture.append(6, FrameKind::FailureRecorded, &payload(head, failure));
	let scan = fixture.replay(bytes.as_slice());
	assert_eq!(scan.boundary().head.sequence(), 7);
	assert_eq!(scan.recorded_uncertainty().unwrap().boundary, failure);
	assert!(matches!(
		scan.state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::RecordedUncertainty),
	));
	let mut writer = FrameWriter::new(bytes, scan.boundary().head);
	writer.append(FrameKind::RangeCheckpoint, &[]).unwrap();
	let bytes = writer.into_inner();
	let refused = fixture.replay(bytes.as_slice());
	assert_eq!(refused.boundary(), scan.boundary());
	assert!(matches!(
		refused.state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::AfterUncertainty,
			..
		})
	));
	for (attempt, kind) in [
		(head, RemoteUncertainBoundary::Creation),
		(fixture.boundary(4).head, failure),
	] {
		let bytes = fixture.append(6, FrameKind::FailureRecorded, &payload(attempt, kind));
		fixture.assert_refused(&bytes, 6, RemoteReplayMismatch::FailureBinding);
	}
	for kind in [
		FrameKind::RemoteCaptureContinued,
		FrameKind::RemoteStageAllocated,
		FrameKind::RemoteCaptureRetired,
		FrameKind::StageSealed,
		FrameKind::PublishIntent,
	] {
		let bytes = fixture.append(6, kind, &[]);
		fixture.assert_refused(&bytes, 6, RemoteReplayMismatch::UnsupportedKind);
	}
}

struct PanicRead;

impl Read for PanicRead {
	fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
		panic!("refused selection must not read");
	}
}

struct CountRead<'a> {
	bytes: &'a [u8],
	consumed: &'a Cell<usize>,
}

impl Read for CountRead<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		let count = self.bytes.read(output)?;
		self.consumed.set(self.consumed.get() + count);
		Ok(count)
	}
}

#[test]
fn kind_40_oversize_header_is_refused_before_any_payload_read() {
	let fixture = Fixture::new();
	let bytes = fixture.append(5, FrameKind::RemoteCaptureContinued, &[0; 1025]);
	let consumed = Cell::new(0);
	let scan = fixture.replay(CountRead {
		bytes: &bytes,
		consumed: &consumed,
	});
	assert_eq!(scan.boundary(), fixture.boundary(5));
	let trailer_bytes = 4 + StreamDigest::from_bytes([0; 32]).as_bytes().len();
	assert_eq!(
		consumed.get(),
		fixture.bytes_through(5).len() + FRAME_OVERHEAD_BYTES - trailer_bytes,
	);
	assert!(matches!(
		scan.state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Framing(
			FrameReadError::Corrupt {
				problem: FrameProblem::PayloadTooLarge(1025),
				..
			}
		))
	));
}
