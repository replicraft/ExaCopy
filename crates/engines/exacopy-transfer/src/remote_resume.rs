//! Input- and evidence-bound restart of an interrupted live remote file capture.
//!
//! The coordinator invokes only supplied capabilities. An authenticated owner
//! and lease, a truthful replay, an authorized held read pass, and a newly
//! exclusive private stage are application responsibilities. This path rereads
//! the live source at a fresh epoch from byte zero and preserves earlier stages
//! and checkpoints. It returns private data evidence for later metadata and
//! publication work, and has no public-name effect or publication authority.

use crate::remote_capture::{
	CaptureCheckpoint, CaptureCheckpoints, CapturedReadAt, CapturedStream, CheckpointStage,
	capture_live,
};
use exacopy_content::validate_stream_input;

mod error;
mod replay;

const FIRST_ALLOCATION_SEQUENCE: u64 = 2;

pub use error::{RestartCheckpointError, RestartError, RestartRefusal};
pub use replay::{
	AllocatedCapture, CaptureAttempt, RemoteScopeDigest, ReplayState, RestartAdmission,
	RestartJournal, RestartRecord, ResumeHistory, ResumeScope, SyncedRestart, TargetState,
};

/// A fresh writer that can confirm the native stage identity before and after capture.
///
/// Binding equality must mean the same actual private object across attempts,
/// irrespective of file names, stage tokens and generations. The adapter owns
/// the exclusive create and ensures no other object can replace this handle.
pub trait RestartStage: CheckpointStage {
	/// Confirms the open writer's physical identity under the current private lease.
	/// # Errors
	/// Refuses when the file or its held private ownership cannot be confirmed.
	fn held_binding(&self) -> Result<Self::Binding, Self::Error>;

	/// Confirms the physical identity of the exact writer-closed stage.
	/// # Errors
	/// Refuses when its physical identity or private ownership cannot be confirmed.
	fn closed_binding(stage: &Self::Closed) -> Result<Self::Binding, Self::Error>;
}

/// An admitted fresh restart, consumed when it attempts to append the restart record.
#[derive(Debug)]
pub struct RestartPlan<B> {
	history: ResumeHistory<B>,
	next_sequence: u64,
}

/// Admits binding one freshly synchronized allocation in a clean pre-intent history.
///
/// # Errors
/// Refuses unresolved publication, an incumbent or unknown target, a changed
/// scope, mismatched allocation or source epoch, or an exhausted journal boundary.
/// Admission issues no effect. The current destination must still be protected
/// by qualified exclusive publication if a later workflow attempts to publish.
pub fn plan_restart<B>(
	history: ResumeHistory<B>,
	admission: RestartAdmission,
) -> Result<RestartPlan<B>, RestartRefusal> {
	if history.scope != admission.scope {
		return Err(RestartRefusal::ScopeChanged);
	}
	if history.state != ReplayState::CleanBeforeIntent {
		return Err(RestartRefusal::Reconcile(history.state));
	}
	match admission.target {
		TargetState::Absent => {}
		TargetState::Occupied => return Err(RestartRefusal::TargetOccupied),
		TargetState::Unknown => return Err(RestartRefusal::TargetUnknown),
	}
	let pending = history.pending_allocation;
	if admission.source != pending.source {
		return Err(RestartRefusal::StaleSource);
	}
	if history.predecessor != pending.head {
		return Err(RestartRefusal::JournalBoundary);
	}
	let next_sequence = pending
		.head
		.sequence()
		.checked_add(1)
		.filter(|sequence| *sequence > FIRST_ALLOCATION_SEQUENCE)
		.ok_or(RestartRefusal::JournalBoundary)?;
	validate_allocations(&history)?;
	Ok(RestartPlan {
		history,
		next_sequence,
	})
}

fn validate_allocations<B>(history: &ResumeHistory<B>) -> Result<(), RestartRefusal> {
	let pending = history.pending_allocation;
	let Some(prior) = history.previous_allocation else {
		if history.previous.is_some() {
			return Err(RestartRefusal::AllocationBinding);
		}
		if pending.head.sequence() != FIRST_ALLOCATION_SEQUENCE {
			return Err(RestartRefusal::JournalBoundary);
		}
		if pending.run.get() != 1 {
			return Err(RestartRefusal::RunEpoch);
		}
		return Ok(());
	};
	if prior.head.sequence() < FIRST_ALLOCATION_SEQUENCE
		|| prior.head.sequence() >= pending.head.sequence()
	{
		return Err(RestartRefusal::JournalBoundary);
	}
	if prior.run.get() == 0 || prior.run.get().checked_add(1) != Some(pending.run.get()) {
		return Err(RestartRefusal::RunEpoch);
	}
	if prior.source.get() >= pending.source.get() {
		return Err(RestartRefusal::StaleSource);
	}
	if let Some(bound) = &history.previous {
		let valid = match bound.run.get().cmp(&prior.run.get()) {
			std::cmp::Ordering::Less => {
				bound.run.get() != 0 && bound.source.get() < prior.source.get()
			}
			std::cmp::Ordering::Equal => bound.source == prior.source,
			std::cmp::Ordering::Greater => false,
		};
		if !valid {
			return Err(RestartRefusal::AllocationBinding);
		}
	}
	Ok(())
}

/// Independently verified private data and the synchronized restart bound to it.
#[derive(Debug)]
pub struct RestartedCapture<S, B> {
	stage: S,
	stream: CapturedStream,
	restart: SyncedRestart<B>,
}

impl<S, B> RestartedCapture<S, B> {
	/// Returns data for later destination metadata, sealing and publication work.
	#[must_use]
	pub fn into_parts(self) -> (S, CapturedStream, SyncedRestart<B>) {
		(self.stage, self.stream, self.restart)
	}
}

/// The bounded private result or an error from a restart boundary.
pub type RestartResult<S, B, R, W, J> = Result<RestartedCapture<S, B>, RestartError<R, W, J>>;

/// Starts a fresh private capture against the synchronized remote restart record.
///
/// The supplied stage is exclusively created and held under the lease. The
/// append records its actual identity before any source read or stage write.
/// `capture_live` rereads the source length in offset order under the new epoch,
/// records fresh checkpoints, closes the writer and independently reads it back.
/// Cancellation leaves prior and new private material under the job owner.
///
/// # Errors
/// Refuses stale held observations, unsafe stage bindings, unconfirmed restart
/// and capture barriers, and source, checkpoint or read-back failures.
pub async fn restart_live<R, W, J>(
	plan: RestartPlan<W::Binding>,
	source: &mut R,
	stage: W,
	journal: &mut J,
	scratch: &mut [u8],
) -> RestartResult<W::Closed, W::Binding, R::Error, W::Error, J::Error>
where
	R: CapturedReadAt,
	W: RestartStage,
	W::Binding: Eq,
	J: RestartJournal<W::Binding>,
{
	let pending = plan.history.pending_allocation;
	if source.epoch() != pending.source {
		return Err(RestartError::Refused(RestartRefusal::StaleSource));
	}
	let length = source.length();
	let limit = plan.history.scope.maximum_length;
	if length > limit {
		return Err(RestartError::Refused(RestartRefusal::SourceLimit {
			length,
			limit,
		}));
	}
	validate_stream_input(length, scratch.len()).map_err(RestartError::Input)?;
	let width = scratch
		.len()
		.min(W::MAX_CHUNK_BYTES)
		.min(source.max_window_bytes().get());
	validate_stream_input(length, width).map_err(RestartError::Input)?;
	let binding = stage.held_binding().map_err(RestartError::Stage)?;
	if plan
		.history
		.previous
		.as_ref()
		.is_some_and(|prior| binding == prior.stage)
	{
		return Err(RestartError::Refused(RestartRefusal::RetainedStage));
	}
	let stage_length = stage.unwritten_length().map_err(RestartError::Stage)?;
	if stage_length != length {
		return Err(RestartError::Refused(RestartRefusal::StageExtent {
			source_length: length,
			stage_length,
		}));
	}
	let record = RestartRecord {
		scope: plan.history.scope,
		predecessor: pending.head,
		previous: plan.history.previous,
		next: CaptureAttempt {
			run: pending.run,
			source: pending.source,
			stage: binding,
		},
		length,
	};
	let restart = journal
		.sync_restart(record)
		.map_err(RestartError::RestartRecord)?;
	if restart.record != record || restart.head.sequence() != plan.next_sequence {
		return Err(RestartError::RestartBinding);
	}
	let mut checkpoints = RestartCheckpoints {
		journal,
		attempt: record.next,
	};
	let capture = capture_live(source, pending.source, stage, &mut checkpoints, scratch)
		.await
		.map_err(RestartError::Capture)?;
	let (stage, stream) = capture.into_parts();
	if W::closed_binding(&stage).map_err(RestartError::Stage)? != binding {
		return Err(RestartError::ClosedStageBinding);
	}
	Ok(RestartedCapture {
		stage,
		stream,
		restart,
	})
}

struct RestartCheckpoints<'a, J, B> {
	journal: &'a mut J,
	attempt: CaptureAttempt<B>,
}

impl<J: CaptureCheckpoints<B>, B: Eq> CaptureCheckpoints<B> for RestartCheckpoints<'_, J, B> {
	type Error = RestartCheckpointError<J::Error>;

	fn record(&mut self, stage: B, range: CaptureCheckpoint) -> Result<(), Self::Error> {
		if stage != self.attempt.stage || range.epoch != self.attempt.source {
			return Err(RestartCheckpointError::Binding);
		}
		self.journal
			.record(stage, range)
			.map_err(RestartCheckpointError::Journal)
	}
}
