use super::prefix::WitnessPrefix;
use std::convert::Infallible;
use std::io::{Cursor, Read as _};
use std::num::{NonZeroU16, NonZeroU64};
use std::ops::Range;

use exacopy_journal::StreamDigest;
use exacopy_journal::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameWriteError, FrameWriter,
};
use exacopy_journal::remote_download::continuation::PriorPreparation;
use exacopy_journal::remote_download::continuation::checkpoint::{
	RemoteContinuedCheckpoint, RemoteContinuedRange,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassBudgetError,
};
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadContext, RemoteDownloadError, RemoteEpochs,
};
use exacopy_model::retained_prefix::{
	BudgetReservation, Checkpoint, Continuation, Head, Live, Refusal,
};
use exacopy_platform::linux::{
	ActiveWitnessReservation, ContinuationReservationError, ReservedContinuationRequest,
	RetainedPrefixSelection, RetainedSuffixWriter, StageError, SuffixEffect, SuffixError,
	WitnessReservationObservationError,
};
use exacopy_transfer::remote_capture::CapturedReadAt;
use exacopy_transfer::remote_resume::prefix::{LentRetainedSuffix, PrefixVerificationError};

use super::activation::{model_head, reservation_plan};

#[derive(Debug)]
pub(super) enum CheckpointFailure<R, E> {
	Binding,
	Format(RemoteDownloadError),
	Frame(FrameWriteError),
	Model(Refusal),
	Budget(WitnessedPassBudgetError),
	Source(PrefixVerificationError<R, Infallible>),
	Stage(SuffixError<CheckpointStageError<E>>),
	Observation(StageError),
	PreEffectObservation(E),
	Custody(WitnessReservationObservationError),
	Journal(ContinuationReservationError<CheckpointGateError<E>>),
}

#[derive(Debug)]
pub(super) enum CheckpointStageError<E> {
	Custody(WitnessReservationObservationError),
	Observation(E),
	Authority(E),
}

#[derive(Debug)]
pub(super) enum CheckpointGateError<E> {
	Binding,
	Format(RemoteDownloadError),
	Observation(E),
	Authority(E),
}

pub(super) struct CheckpointPass<'scope> {
	pub(super) trust: &'scope RemoteBootstrapTrust<'scope>,
	pub(super) selection: &'scope RemoteWitnessedReplaySelection<'scope>,
	pub(super) context: RemoteDownloadContext,
	pub(super) epochs: RemoteEpochs,
	pub(super) lineage: Head,
}

pub(super) struct CheckedRange<'context, 'writer, 'view, 'lease, 'held, 'source, R> {
	pub(super) state: &'context mut Continuation,
	pub(super) journal: &'context mut ActiveWitnessReservation<'lease>,
	pub(super) writer: &'writer mut RetainedSuffixWriter<'view, 'lease>,
	pub(super) source: &'context mut LentRetainedSuffix<'held, 'source, R, WitnessPrefix<'lease>>,
	pub(super) scratch: &'context mut [u8],
}

pub(super) struct PlannedRange {
	pub(super) budget: WitnessedPassBudget,
	pub(super) live: Live,
	pub(super) ordinal: NonZeroU16,
}

struct StopRange<'context, 'writer, 'view, 'lease, 'held, 'source, R> {
	checked: CheckedRange<'context, 'writer, 'view, 'lease, 'held, 'source, R>,
	stopping: bool,
}

impl<R> Drop for StopRange<'_, '_, '_, '_, '_, '_, R> {
	fn drop(&mut self) {
		if self.stopping {
			self.checked.state.block();
			self.checked.journal.stop();
			self.checked.writer.stop();
		}
	}
}

impl CheckpointPass<'_> {
	pub(super) async fn capture_range<R: CapturedReadAt, G, H, E>(
		&self,
		checked: CheckedRange<'_, '_, '_, '_, '_, '_, R>,
		planned: PlannedRange,
		observe: impl Fn() -> Result<(), E>,
		stage_gate: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
		journal_gate: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<H, E>,
	) -> Result<(), CheckpointFailure<R::Error, E>> {
		let mut guarded = StopRange {
			checked,
			stopping: true,
		};
		let outcome = self
			.run_range(
				&mut guarded.checked,
				planned,
				observe,
				stage_gate,
				journal_gate,
			)
			.await;
		guarded.stopping = outcome.is_err();
		outcome
	}

	async fn run_range<R: CapturedReadAt, G, H, E>(
		&self,
		checked: &mut CheckedRange<'_, '_, '_, '_, '_, '_, R>,
		planned: PlannedRange,
		observe: impl Fn() -> Result<(), E>,
		mut stage_gate: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
		journal_gate: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<H, E>,
	) -> Result<(), CheckpointFailure<R::Error, E>> {
		let CheckedRange {
			state,
			journal,
			writer,
			source,
			scratch,
		} = checked;
		use CheckpointFailure as Error;

		let PlannedRange {
			budget: plan,
			live,
			ordinal,
		} = planned;
		let range = checkpoint_range_at(plan, ordinal, live.local_end, source.next_offset())
			.ok_or(Error::Binding)?;
		let length = range.end.checked_sub(range.start).ok_or(Error::Binding)?;
		if reservation_plan(plan).ok() != Some(journal.plan()) {
			return Err(Error::Binding);
		}
		let observed_ordinal = ordinal.get();
		let model_pass = state.basis().pass();
		if self.epochs.run != model_pass.run
			|| self.epochs.source != model_pass.source
			|| !writer.matches_reader(source.reader().native())
			|| live.head != journal.head()
			|| scratch.is_empty()
		{
			return Err(Error::Binding);
		}
		journal
			.check_capture_writer(writer)
			.map_err(Error::Custody)?;
		let record =
			|digest| self.record(live.head, observed_ordinal, live.local_end, length, digest);
		let preview = record([0; 32])
			.map_err(Error::Format)?
			.encode()
			.map_err(Error::Format)?;
		let checkpoint_end = frame_end(live.head.end, preview.len()).ok_or(Error::Binding)?;
		let current = RemoteReplayBoundary {
			head: chain_head(live.head).ok_or(Error::Binding)?,
			offset: live.head.end,
		};
		let remaining = plan
			.required_after_checkpoint(current, ordinal, checkpoint_end)
			.map_err(Error::Budget)?;
		let budget = BudgetReservation {
			live,
			tail_end: range.end,
			checkpoint_end,
			closing_bytes: NonZeroU64::new(remaining.journal_bytes()).ok_or(Error::Binding)?,
			closing_frames: NonZeroU64::new(u64::from(remaining.journal_frames()))
				.ok_or(Error::Binding)?,
			receipt_bytes: NonZeroU64::new(u64::from(remaining.receipt_bytes()))
				.ok_or(Error::Binding)?,
			receipt_capacity: journal.receipt_capacity(),
		};
		let permit = state
			.permit_tail(live, live.local_end, length, budget)
			.map_err(Error::Model)?;
		writer
			.begin_range(&permit, |actual| {
				(actual.range() == (live.local_end..budget.tail_end))
					.then_some(())
					.ok_or(())
			})
			.map_err(|_| Error::Binding)?;

		let mut range_hash = blake3::Hasher::new();
		let mut remaining = length;
		while remaining != 0 {
			let width = usize::try_from(remaining)
				.unwrap_or(usize::MAX)
				.min(scratch.len());
			let bytes = source
				.read_next(&mut scratch[..width])
				.await
				.map_err(Error::Source)?
				.ok_or(Error::Binding)?;
			writer
				.write_next_observed(
					bytes,
					|| {
						journal
							.check_active()
							.map_err(CheckpointStageError::Custody)?;
						observe().map_err(CheckpointStageError::Observation)
					},
					|actual, effect| {
						stage_gate(actual, effect).map_err(CheckpointStageError::Authority)
					},
				)
				.map_err(Error::Stage)?;
			range_hash.update(bytes);
			remaining -= bytes.len() as u64;
		}
		observe().map_err(Error::PreEffectObservation)?;
		journal.check_active().map_err(Error::Custody)?;
		let physical_end = writer
			.sync_range(|actual, effect| {
				stage_gate(actual, effect).map_err(CheckpointStageError::Authority)
			})
			.map_err(Error::Stage)?;
		if physical_end != budget.tail_end {
			return Err(Error::Binding);
		}
		let completed = Live {
			local_end: physical_end,
			..live
		};
		state
			.complete_tail(completed, permit)
			.map_err(Error::Model)?;

		let canonical = record(*range_hash.finalize().as_bytes())
			.map_err(Error::Format)?
			.encode()
			.map_err(Error::Format)?;
		if frame_end(live.head.end, canonical.len()) != Some(budget.checkpoint_end) {
			return Err(Error::Binding);
		}
		let mut frame = FrameWriter::new(Vec::new(), chain_head(live.head).ok_or(Error::Binding)?);
		let head = frame
			.append(FrameKind::RangeCheckpoint, &canonical)
			.map_err(Error::Frame)?;
		let encoded = frame.into_inner();
		let successor = RemoteReplayBoundary {
			head,
			offset: budget.checkpoint_end,
		};
		let barrier = writer.checkpoint_proof().map_err(Error::Observation)?;
		journal
			.append_checkpoint(
				&barrier,
				model_head(successor),
				&encoded,
				|old| {
					self.confirm_range(
						old.chain(Cursor::new(encoded.as_slice())),
						successor,
						physical_end,
					)?;
					observe().map_err(CheckpointGateError::Observation)
				},
				|request| {
					if request.previous != live.head || request.successor != model_head(successor) {
						return Err(CheckpointGateError::Binding);
					}
					journal_gate(request).map_err(CheckpointGateError::Authority)
				},
				|actual| self.confirm_range(actual, successor, physical_end),
			)
			.map_err(Error::Journal)?;
		let checkpoint = Checkpoint {
			lineage: self.lineage,
			predecessor: live.head,
			head: journal.head(),
			pass: model_pass,
			guard: live.guard,
			start: live.local_end,
			end: physical_end,
			ordinal: observed_ordinal,
		};
		state
			.checkpoint(
				Live {
					head: checkpoint.head,
					..completed
				},
				checkpoint,
			)
			.map_err(Error::Model)?;
		writer
			.confirm_checkpoint(|end| {
				(end == physical_end && journal.head() == model_head(successor))
					.then_some(())
					.ok_or(())
			})
			.map_err(|_| Error::Binding)?;
		Ok(())
	}

	fn record(
		&self,
		previous: Head,
		ordinal: u16,
		offset: u64,
		length: u64,
		digest: [u8; 32],
	) -> Result<RemoteContinuedCheckpoint, RemoteDownloadError> {
		RemoteContinuedCheckpoint::new(
			self.context,
			chain_head(previous).ok_or(RemoteDownloadError::FrameBinding)?,
			chain_head(self.lineage).ok_or(RemoteDownloadError::FrameBinding)?,
			self.epochs,
			RemoteContinuedRange {
				ordinal,
				offset,
				length,
				digest: StreamDigest::from_bytes(digest),
			},
		)
	}

	pub(super) fn confirm_range<E>(
		&self,
		input: impl std::io::Read,
		expected: RemoteReplayBoundary,
		coverage: u64,
	) -> Result<(), CheckpointGateError<E>> {
		use CheckpointGateError as Error;
		let replay = replay_remote_witnessed_closeout(input, self.trust, self.selection)
			.map_err(Error::Format)?;
		if replay.issue().is_some()
			|| replay.phase() != RemoteWitnessedReplayPhase::ContinuedCapture
			|| replay.boundary() != expected
		{
			return Err(Error::Binding);
		}
		let history = replay.active_prefix_history().map_err(Error::Format)?;
		if history.active()
			!= PriorPreparation::Continued(chain_head(self.lineage).ok_or(Error::Binding)?)
			|| history.context() != self.context
			|| history.epochs() != self.epochs
			|| history.covered_extent() != coverage
		{
			return Err(Error::Binding);
		}
		Ok(())
	}
}

pub(super) fn checkpoint_range_at(
	plan: WitnessedPassBudget,
	ordinal: NonZeroU16,
	local_end: u64,
	source_offset: Option<u64>,
) -> Option<Range<u64>> {
	let range = plan.checkpoint_range(ordinal)?;
	// The source cursor can advance independently of the retained stage and journal.
	(range.start == local_end && source_offset == Some(range.start)).then_some(range)
}

fn chain_head(head: Head) -> Option<ChainHead> {
	ChainHead::after(head.sequence, head.digest)
}

fn frame_end(previous: u64, payload: usize) -> Option<u64> {
	u64::try_from(FRAME_OVERHEAD_BYTES.checked_add(payload)?)
		.ok()
		.and_then(|bytes| previous.checked_add(bytes))
}
