//! Exercise boundary ordering for a fresh private remote restart.
#![cfg(any(
	target_os = "linux",
	all(target_os = "macos", feature = "experimental-apfs-copy")
))]

use std::{
	future::Future,
	pin::pin,
	task::{Context, Poll, Waker},
};

use exacopy_journal::{JournalEpoch, frame::ChainHead};
use exacopy_transfer::remote_capture::{CaptureError, StageStep};
use exacopy_transfer::remote_resume::{
	RemoteScopeDigest, ReplayState, RestartCheckpointError, RestartError, RestartRefusal,
	TargetState, plan_restart, restart_live,
};

#[path = "remote_resume/fixture.rs"]
mod fixture;

use fixture::{CONTENT, Fault, NEW, OLD, Step, admission, epoch, head, history, plan, setup};

fn ready<F: Future>(future: F) -> F::Output {
	match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
		Poll::Ready(result) => result,
		Poll::Pending => panic!("fixture unexpectedly suspended"),
	}
}

#[test]
fn replay_admits_only_the_same_authorized_clean_preintent_job() {
	let prior = history();
	let current = admission(prior.scope);
	for state in [
		ReplayState::IntentRecorded,
		ReplayState::Published,
		ReplayState::Uncertain,
	] {
		let mut blocked = prior;
		blocked.state = state;
		assert_eq!(
			plan_restart(blocked, current).expect_err("unsafe replay"),
			RestartRefusal::Reconcile(state)
		);
	}
	let mut changed = current;
	changed.scope.approved_scope = RemoteScopeDigest::from_bytes([99; 32]);
	assert_eq!(
		plan_restart(prior, changed).expect_err("different endpoint"),
		RestartRefusal::ScopeChanged
	);
	changed = current;
	changed.source = prior.previous.source;
	assert_eq!(
		plan_restart(prior, changed).expect_err("old live pass"),
		RestartRefusal::StaleSource
	);
	for (target, expected) in [
		(TargetState::Occupied, RestartRefusal::TargetOccupied),
		(TargetState::Unknown, RestartRefusal::TargetUnknown),
	] {
		changed = current;
		changed.target = target;
		assert_eq!(
			plan_restart(prior, changed).expect_err("unusable target"),
			expected
		);
	}
	for boundary in [ChainHead::start(), head(u64::MAX)] {
		let mut blocked = prior;
		blocked.predecessor = boundary;
		assert_eq!(
			plan_restart(blocked, current).expect_err("invalid chain"),
			RestartRefusal::JournalBoundary
		);
	}
	for epoch in [0, u64::MAX] {
		let mut blocked = prior;
		blocked.previous.run = JournalEpoch::new(epoch);
		assert_eq!(
			plan_restart(blocked, current).expect_err("invalid run epoch"),
			RestartRefusal::RunEpoch
		);
	}
}

#[test]
fn restart_commits_new_stage_before_reading_every_byte_from_zero() {
	let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, Fault::None);
	let capture = ready(restart_live(
		plan(),
		&mut source,
		stage,
		&mut journal,
		&mut [0; 8],
	))
	.expect("full private restart");
	let (closed, stream, synced) = capture.into_parts();
	assert_eq!(closed.bytes, CONTENT);
	assert_eq!(*bytes.borrow(), CONTENT);
	assert_eq!(closed.binding, NEW);
	assert_eq!(stream.epoch, epoch(8));
	assert_eq!(stream.length, 8);
	assert_eq!(stream.stage_digest.as_bytes(), &stream.source_digest);
	assert_eq!(synced.record.scope, history().scope);
	assert_eq!(synced.record.predecessor, history().predecessor);
	assert_eq!(synced.record.previous.stage, OLD);
	assert_eq!(synced.record.next.stage, NEW);
	assert_eq!(synced.record.next.run, JournalEpoch::new(6));
	assert_eq!(synced.head.sequence(), 7);
	assert_eq!(journal.records, [synced.record]);
	let [(stage, checkpoint)] = journal.checkpoints.as_slice() else {
		panic!("one final checkpoint expected");
	};
	assert_eq!(
		(
			*stage,
			checkpoint.epoch,
			checkpoint.offset,
			checkpoint.length
		),
		(NEW, epoch(8), 0, 8)
	);
	assert_eq!(checkpoint.digest, stream.source_digest);
	assert_eq!(
		*tape.borrow(),
		[
			Step::Held,
			Step::Restart,
			Step::CheckSource,
			Step::Read(0),
			Step::Write,
			Step::Read(3),
			Step::Write,
			Step::Read(6),
			Step::Write,
			Step::Barrier,
			Step::Checkpoint,
			Step::Close,
			Step::OpenReadBack,
			Step::ReadBack,
			Step::ReadBack,
			Step::FinishSource,
			Step::ClosedBinding,
		]
	);
}

#[test]
fn stale_oversize_or_retained_stage_stops_before_restart_record() {
	let (mut source, stage, mut journal, tape, _) = setup(CONTENT, Fault::None);
	source.epoch = epoch(7);
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Refused(RestartRefusal::StaleSource))
	));
	assert!(tape.borrow().is_empty());

	let (mut source, mut stage, mut journal, tape, bytes) = setup(CONTENT, Fault::None);
	stage.binding = OLD;
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Refused(RestartRefusal::RetainedStage))
	));
	assert_eq!(*tape.borrow(), [Step::Held]);
	assert!(bytes.borrow().is_empty() && journal.records.is_empty());

	let (mut source, stage, mut journal, tape, _) = setup(CONTENT, Fault::None);
	let mut limited = history();
	limited.scope.maximum_length = 7;
	let plan = plan_restart(limited, admission(limited.scope)).expect("authorized within limit");
	assert!(matches!(
		ready(restart_live(
			plan,
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Refused(RestartRefusal::SourceLimit {
			length: 8,
			limit: 7
		}))
	));
	assert!(tape.borrow().is_empty());
}

#[test]
fn uncertain_barrier_or_wrong_restart_ack_never_reads_or_writes() {
	for fault in [
		Fault::RestartBarrier,
		Fault::WrongRecord,
		Fault::WrongSequence,
	] {
		let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, fault);
		let result = ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8],
		));
		assert!(matches!(
			result,
			Err(RestartError::RestartRecord("restart barrier") | RestartError::RestartBinding)
		));
		assert_eq!(*tape.borrow(), [Step::Held, Step::Restart]);
		assert!(bytes.borrow().is_empty());
		assert_eq!(
			journal.records.len(),
			1,
			"the barrier may fail after writing the record"
		);
	}
	let (mut source, stage, mut journal, tape, _) = setup(CONTENT, Fault::None);
	journal.head =
		ChainHead::after(history().predecessor.sequence(), [99; 32]).expect("different digest");
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::RestartRecord("changed predecessor"))
	));
	assert_eq!(*tape.borrow(), [Step::Held, Step::Restart]);
	assert!(journal.records.is_empty());
}

#[test]
fn cancellation_and_stale_source_leave_private_evidence() {
	let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, Fault::PendingSource);
	let mut scratch = [0; 8];
	{
		let mut future = pin!(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut scratch
		));
		assert!(
			future
				.as_mut()
				.poll(&mut Context::from_waker(Waker::noop()))
				.is_pending()
		);
	}
	assert_eq!(
		*tape.borrow(),
		[Step::Held, Step::Restart, Step::CheckSource, Step::Read(0)]
	);
	assert_eq!(journal.records.len(), 1);
	assert!(journal.checkpoints.is_empty() && bytes.borrow().is_empty());

	let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, Fault::StaleSource);
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Capture(CaptureError::Epoch { .. }))
	));
	assert_eq!(
		*tape.borrow(),
		[Step::Held, Step::Restart, Step::CheckSource, Step::Read(0)]
	);
	assert!(journal.checkpoints.is_empty() && bytes.borrow().is_empty());
}

#[test]
fn checkpoint_faults_stop_before_closure_and_final_verification() {
	for fault in [
		Fault::BarrierFailure,
		Fault::WrongBarrier,
		Fault::CheckpointBarrier,
	] {
		let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, fault);
		let result = ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8],
		));
		assert!(matches!(
			result,
			Err(RestartError::Capture(
				CaptureError::Stage {
					step: StageStep::SyncPrefix { end: 8 },
					cause: "stage barrier"
				} | CaptureError::Checkpoint {
					offset: 0,
					cause: RestartCheckpointError::Binding
						| RestartCheckpointError::Journal("checkpoint barrier")
				}
			))
		));
		assert_eq!(*bytes.borrow(), CONTENT);
		assert!(!tape.borrow().contains(&Step::Close));
		assert_eq!(
			journal.checkpoints.len(),
			usize::from(matches!(fault, Fault::CheckpointBarrier))
		);
	}
}

#[test]
fn empty_files_still_confirm_stage_identity_and_independent_read_back() {
	let (mut source, stage, mut journal, tape, _) = setup(b"", Fault::None);
	let capture = ready(restart_live(
		plan(),
		&mut source,
		stage,
		&mut journal,
		&mut [],
	))
	.expect("empty file");
	let (closed, stream, synced) = capture.into_parts();
	assert!(closed.bytes.is_empty());
	assert_eq!(stream.length, 0);
	assert_eq!(synced.record.next.stage, NEW);
	assert!(journal.checkpoints.is_empty());
	assert!(tape.borrow().contains(&Step::OpenReadBack));
	assert_eq!(tape.borrow().last(), Some(&Step::ClosedBinding));

	let (mut source, stage, mut journal, _, _) = setup(b"", Fault::WrongClosedIdentity);
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut []
		)),
		Err(RestartError::ClosedStageBinding)
	));
}

#[test]
fn independent_read_back_is_required_after_the_final_checkpoint() {
	let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, Fault::CorruptReadBack);
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Capture(CaptureError::DigestMismatch))
	));
	assert_eq!(*bytes.borrow(), CONTENT);
	assert_eq!(journal.checkpoints.len(), 1);
	assert!(tape.borrow().contains(&Step::ReadBack));
	assert!(!tape.borrow().contains(&Step::ClosedBinding));
}

#[test]
fn source_finish_failure_after_local_read_back_leaves_only_private_evidence() {
	let (mut source, stage, mut journal, tape, bytes) = setup(CONTENT, Fault::FinishFailure);
	assert!(matches!(
		ready(restart_live(
			plan(),
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8]
		)),
		Err(RestartError::Capture(CaptureError::SourceFinish(
			"source finish"
		)))
	));
	assert_eq!(*bytes.borrow(), CONTENT);
	assert_eq!(journal.checkpoints.len(), 1);
	assert!(tape.borrow().contains(&Step::ReadBack));
	assert_eq!(tape.borrow().last(), Some(&Step::FinishSource));
}
