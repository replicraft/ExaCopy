//! Input- and evidence-bound restart of an interrupted live remote file capture.
//!
//! The coordinator invokes only supplied capabilities. An authenticated owner
//! and lease, a truthful replay, an authorized held read pass, and a newly
//! exclusive private stage are application responsibilities. This path rereads
//! the live source at a fresh epoch from byte zero and preserves earlier stages
//! and checkpoints. It returns private data evidence for later metadata and
//! publication work, and has no public-name effect or publication authority.

use exacopy_content::validate_stream_input;
use exacopy_journal::JournalEpoch;

use crate::remote_capture::{
	CaptureCheckpoint, CaptureCheckpoints, CapturedReadAt, CapturedStream, CheckpointStage,
	SourceEpoch, capture_live,
};

mod error;
mod replay;

pub use error::{RestartCheckpointError, RestartError, RestartRefusal};
pub use replay::{
	CaptureAttempt, RemoteScopeDigest, ReplayState, RestartAdmission, RestartJournal,
	RestartRecord, ResumeHistory, ResumeScope, SyncedRestart, TargetState,
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
	source: SourceEpoch,
	next_run: JournalEpoch,
	next_sequence: u64,
}

/// Admits a fresh restart from an authenticated, clean, pre-intent history.
///
/// # Errors
/// Refuses unresolved publication, an incumbent or unknown target, a changed
/// scope, reused source epoch, or exhausted journal and generation boundaries.
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
	if admission.source.get() <= history.previous.source.get() {
		return Err(RestartRefusal::StaleSource);
	}
	let next_sequence = history
		.predecessor
		.sequence()
		.checked_add(1)
		.filter(|sequence| *sequence > 1)
		.ok_or(RestartRefusal::JournalBoundary)?;
	let next_run = history
		.previous
		.run
		.get()
		.checked_add(1)
		.filter(|epoch| *epoch > 1)
		.map(JournalEpoch::new)
		.ok_or(RestartRefusal::RunEpoch)?;
	Ok(RestartPlan {
		history,
		source: admission.source,
		next_run,
		next_sequence,
	})
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
	if source.epoch() != plan.source {
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
	if binding == plan.history.previous.stage {
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
		predecessor: plan.history.predecessor,
		previous: plan.history.previous,
		next: CaptureAttempt {
			run: plan.next_run,
			source: plan.source,
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
	let capture = capture_live(source, plan.source, stage, &mut checkpoints, scratch)
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
