use exacopy_content::{
	CheckpointCandidate, ContentDigest, ResumeMeasureError, measure_at, resume_and_measure_at,
	validate_stream_input,
};
use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_publication::ExclusivePublication;
use exacopy_endpoint::linux_staging::{SourceMetadata, StageReader, StageWriter, StagingSource};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, DurableJournalError, JournalContext, JournalEpoch, LinuxFileIdentity,
	LiveSourceView, ObservedTimestamp, OwnerDigest, RangeResumeEvidence, RangeResumeStarted,
	ReceiptCommitted, ReceiptDigest, SourceInodeMetadata,
};
use exacopy_model::{CopyBinding, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId};

use super::super::super::CopyCheckpoint;
use super::super::super::local_copy::Publication;
use super::super::super::local_copy::records::EntryEvidence;
use super::super::super::{
	CopyReceipt, JournalBoundary, JournalReplay, JournalTail, LocalCopyPlan,
	MAX_LOCAL_JOURNAL_BYTES, ReceiptEvidence,
};
use super::super::RecoveryIssue;
use super::error::ResumeError;
use crate::linux_staging::{
	StageFailure, begin_stage_reads, check_source, complete_stage_metadata, flush_written_stage,
	observe, verify_stage_readback,
};

#[cfg(test)]
mod tests;

const PRIVATE_STAGE_MODE: u32 = 0o600;
// Reserve enough space for the bounded resume, publication and receipt recovery suffixes.
const RESUME_JOURNAL_RESERVE: u64 = 16 * 1024;

/// Holds the original job lease and inventory while opening only the captured stage.
pub trait StageDirectory<M, I> {
	/// Native operation failure.
	type Error;
	/// Native exclusive publication failure.
	type PublicationError;
	/// Reader of the held stage with released write authority.
	type Reader<'stage>: StageReader<Identity = I, Metadata = M, Error = Self::Error>
		+ ExclusivePublication<Error = Self::PublicationError>
	where
		Self: 'stage;
	/// One writer scoped to the held stage.
	type Writer<'stage>: StageWriter<Identity = I, Metadata = M, Error = Self::Error, Reader = Self::Reader<'stage>>
	where
		Self: 'stage;

	/// Returns the held directory identity.
	fn identity(&self) -> LinuxFileIdentity;
	/// Translates a held stage identity into the existing persisted domain.
	fn record_identity(identity: I) -> LinuxFileIdentity;
	/// Opens the existing admitted stage for writing.
	fn open_writer(&mut self, binding: CopyBinding) -> Result<Self::Writer<'_>, Self::Error>;
	/// Opens the unchanged metadata-ready stage independently for read-back.
	fn open_flushed_readback(
		&mut self,
		binding: CopyBinding,
		source: M,
	) -> Result<Self::Reader<'_>, Self::Error>;
}

// Reopens the exact durable prefix and writes only to the held job's receipt namespace.
pub(super) trait Records {
	type Error;

	fn resume_journal(&self, boundary: JournalBoundary) -> Result<DurableJournal, Self::Error>;
	fn sync_receipt(&self, receipt: &CopyReceipt<'_>) -> Result<(), Self::Error>;
	fn checkpoint(&self) -> fn(CopyCheckpoint) {
		|_| {}
	}
}

pub(super) struct RetainedStage<'file, R, I> {
	pub(super) reader: &'file R,
	pub(super) identity: I,
	pub(super) mode: u32,
}

pub(super) struct Evidence<'history, 'name> {
	pub(super) plan: &'history LocalCopyPlan<'name>,
	pub(super) replay: &'history JournalReplay,
	pub(super) ranges: &'history [CheckpointCandidate],
	pub(super) owner: OwnerDigest,
}

#[derive(Clone, Copy)]
enum Mode {
	Rewrite,
	ReadBack,
}

pub(super) struct Resume<'file, 'history, 'name, S: StagingSource, R> {
	evidence: Evidence<'history, 'name>,
	source: &'file S,
	retained: RetainedStage<'file, R, S::Identity>,
	mode: Mode,
	prepared_source: LiveSourceView,
	source_metadata: SourceInodeMetadata,
	accessed_at: <S::Metadata as SourceMetadata>::Timestamp,
}

type OperationResult<S, D, J> = ResumeResult<
	(),
	<S as ReadView>::Error,
	<D as StageDirectory<<S as StagingSource>::Metadata, <S as StagingSource>::Identity>>::Error,
	<D as StageDirectory<
		<S as StagingSource>::Metadata,
		<S as StagingSource>::Identity,
	>>::PublicationError,
	<J as Records>::Error,
>;

type ResumeResult<T, R, S, P, F> = Result<T, ResumeError<R, S, P, F>>;
type StreamResult<T, R, S, P, F> = ResumeResult<(T, ContentDigest), R, S, P, F>;

impl<'file, 'history, 'name, S, R> Resume<'file, 'history, 'name, S, R>
where
	S: StagingSource,
	R: ReadView<Error = S::Error>,
{
	pub(super) fn admit<E, P, F>(
		evidence: Evidence<'history, 'name>,
		source: &'file S,
		retained: RetainedStage<'file, R, S::Identity>,
		scratch_len: usize,
		timestamp: impl FnOnce(
			ObservedTimestamp,
		) -> Result<<S::Metadata as SourceMetadata>::Timestamp, S::Error>,
	) -> ResumeResult<Self, S::Error, E, P, F> {
		validate_stream_input(source.length(), scratch_len).map_err(ResumeError::Input)?;
		if evidence.replay.intent.is_some() || evidence.replay.tail != JournalTail::Clean {
			return Err(ResumeError::IncompleteEvidence);
		}
		let prepared_source = evidence
			.replay
			.source
			.ok_or(ResumeError::IncompleteEvidence)?;
		let source_metadata = evidence
			.replay
			.source_metadata
			.ok_or(ResumeError::IncompleteEvidence)?;
		let accessed_at = timestamp(prepared_source.times().accessed_at)
			.map_err(|error| ResumeError::SourcePolicy(StageFailure::Source(error)))?;
		let mode = if retained.mode == PRIVATE_STAGE_MODE {
			Mode::Rewrite
		} else if retained.mode == source_metadata.mode() {
			Mode::ReadBack
		} else {
			return Err(ResumeError::Stage(RecoveryIssue::MetadataMismatch));
		};
		if retained.reader.length() > source.length()
			|| (matches!(mode, Mode::ReadBack) && retained.reader.length() != source.length())
			|| retained.identity == source.identity()
		{
			return Err(ResumeError::Stage(RecoveryIssue::StreamMismatch));
		}
		Ok(Self {
			evidence,
			source,
			retained,
			mode,
			prepared_source,
			source_metadata,
			accessed_at,
		})
	}

	pub(super) fn execute<D, J>(
		&self,
		directory: &mut D,
		records: &J,
		scratch: &mut [u8],
	) -> OperationResult<S, D, J>
	where
		D: StageDirectory<S::Metadata, S::Identity>,
		J: Records,
	{
		validate_stream_input(self.source.length(), scratch.len()).map_err(ResumeError::Input)?;
		let stage_directory = directory.identity();
		let stage_identity = D::record_identity(self.retained.identity);
		if self.evidence.replay.stage != Some(stage_identity) {
			return Err(ResumeError::Stage(RecoveryIssue::UnrecognizedStage));
		}
		if self
			.evidence
			.replay
			.recovery_stage_directory
			.is_some_and(|id| id != stage_directory)
		{
			return Err(ResumeError::Stage(RecoveryIssue::StageDirectoryBinding));
		}
		let (context, binding) = self.next_attempt()?;
		let mut session = CopySession::new(binding);
		let (stage, digest, mut journal) = match self.mode {
			Mode::Rewrite => {
				let journal = self.start(records, context, stage_identity, stage_directory)?;
				let writer = directory
					.open_writer(binding)
					.map_err(ResumeError::Namespace)?;
				let (stage, digest) = self.rewrite_ranges(
					writer,
					scratch,
					&mut session,
					binding,
					records.checkpoint(),
				)?;
				(stage, digest, journal)
			}
			Mode::ReadBack => {
				observe(&mut session, binding, CopyEvent::RetainedStageReopened)
					.map_err(ResumeError::Model)?;
				observe(&mut session, binding, CopyEvent::WritersJoined)
					.map_err(ResumeError::Model)?;
				let stage = directory
					.open_flushed_readback(binding, self.source.metadata())
					.map_err(ResumeError::Namespace)?;
				observe(&mut session, binding, CopyEvent::DataFlushed)
					.map_err(ResumeError::Model)?;
				let digest = self.verify_retained_stage(&stage, scratch, &mut session, binding)?;
				// Refuse a changed source before appending anything or applying metadata.
				check_source(self.source).map_err(ResumeError::SourcePolicy)?;
				let journal = self.start(records, context, stage_identity, stage_directory)?;
				(stage, digest, journal)
			}
		};
		let stage =
			complete_stage_metadata(stage, self.source, self.accessed_at, &mut session, binding)
				.map_err(ResumeError::ResumeStage)?;
		(records.checkpoint())(CopyCheckpoint::RangeResumeMetadataApplied);

		self.check_identity(stage.identity())?;
		let plan = self.evidence.plan;
		let sealed = EntryEvidence::from_preparation(
			context,
			plan.attempt().entry,
			self.prepared_source,
			self.source_metadata,
			plan.destination(),
		)
		.seal_stream(stage_identity, stage.length(), digest)
		.map_err(ResumeError::Seal)?;
		let metadata = sealed.record(&mut journal).map_err(ResumeError::Seal)?;
		check_source(self.source).map_err(ResumeError::SourcePolicy)?;
		let publication = Publication {
			context,
			plan,
			binding,
			stage_directory,
		};
		let durability = publication
			.complete_with(
				&mut journal,
				&mut session,
				stage,
				&sealed,
				&metadata,
				records.checkpoint(),
			)
			.map_err(ResumeError::Publish)?;
		let receipt = CopyReceipt::from_synced_durability(
			ReceiptEvidence {
				context,
				entry: plan.attempt().entry,
				source: self.prepared_source.identity(),
				destination: plan.destination().root,
				target: plan.destination().component,
				stream: sealed.verification.stage(),
			},
			&durability,
		)
		.map_err(ResumeError::Receipt)?;
		let committed = ReceiptCommitted::new(
			publication.intent_context(),
			ReceiptDigest::from_bytes(receipt.digest()),
			durability.head(),
		)
		.map_err(ResumeError::PublicationRecord)?;
		records
			.sync_receipt(&receipt)
			.map_err(ResumeError::Records)?;
		let _ = append(
			&mut journal,
			FrameKind::ReceiptCommitted,
			&committed.encode(),
		)?;
		observe(&mut session, binding, CopyEvent::ReceiptRecorded).map_err(ResumeError::Model)?;
		Ok(())
	}

	fn check_identity<E, P, F>(
		&self,
		identity: S::Identity,
	) -> ResumeResult<(), S::Error, E, P, F> {
		if identity == self.retained.identity {
			Ok(())
		} else {
			Err(ResumeError::Stage(RecoveryIssue::UnrecognizedStage))
		}
	}

	fn next_attempt<E, P, F>(
		&self,
	) -> ResumeResult<(JournalContext, CopyBinding), S::Error, E, P, F> {
		let replay = self.evidence.replay;
		let context = JournalContext {
			epoch: JournalEpoch::new(
				replay
					.latest_epoch
					.get()
					.checked_add(1)
					.ok_or(ResumeError::EpochExhausted)?,
			),
			..self.evidence.plan.context()
		};
		let entry = self.evidence.plan.attempt().entry;
		let binding = CopyBinding::new(
			JobId::try_from_bytes(*context.job.as_bytes())
				.map_err(|_| ResumeError::IncompleteEvidence)?,
			EntryId::new(1),
			RunEpoch::new(context.epoch.get()),
			StageId::from_bytes(*entry.as_bytes()),
		);
		Ok((context, binding))
	}

	fn start<E, P, J: Records>(
		&self,
		records: &J,
		context: JournalContext,
		stage: LinuxFileIdentity,
		stage_directory: LinuxFileIdentity,
	) -> ResumeResult<DurableJournal, S::Error, E, P, J::Error> {
		let replay = self.evidence.replay;
		let boundary = replay.boundary;
		if boundary.offset > MAX_LOCAL_JOURNAL_BYTES - RESUME_JOURNAL_RESERVE {
			return Err(ResumeError::Resume(DurableJournalError::SegmentTooLarge {
				length: boundary.offset.saturating_add(RESUME_JOURNAL_RESERVE),
				limit: MAX_LOCAL_JOURNAL_BYTES,
			}));
		}
		let start = RangeResumeStarted::new(
			context,
			self.evidence.plan.attempt().entry,
			replay.latest_epoch,
			RangeResumeEvidence {
				preparation: replay
					.preparation_head
					.ok_or(ResumeError::IncompleteEvidence)?,
				preceding: boundary.head,
				stage,
				stage_directory,
				authorization: self.evidence.owner,
			},
		)
		.map_err(ResumeError::Decision)?;
		let mut journal = records
			.resume_journal(boundary)
			.map_err(ResumeError::Records)?;
		let _ = append(&mut journal, FrameKind::RecoveryStarted, &start.encode())?;
		(records.checkpoint())(CopyCheckpoint::RangeResumeStartedSynced);
		Ok(journal)
	}

	fn rewrite_ranges<W, P, F>(
		&self,
		mut writer: W,
		scratch: &mut [u8],
		session: &mut CopySession,
		binding: CopyBinding,
		checkpoint: fn(CopyCheckpoint),
	) -> StreamResult<W::Reader, S::Error, W::Error, P, F>
	where
		W: StageWriter<Identity = S::Identity, Metadata = S::Metadata>,
	{
		self.check_identity(writer.identity())?;
		writer
			.check_ownership(self.source.metadata())
			.map_err(ResumeError::Namespace)?;
		begin_stage_reads(session, binding).map_err(ResumeError::Model)?;
		let digest = resume_and_measure_at(
			self.source.length(),
			self.retained.reader.length(),
			scratch,
			self.evidence.ranges,
			|offset, bytes| self.source.read_exact_at(offset, bytes),
			|offset, bytes| self.retained.reader.read_exact_at(offset, bytes),
			|offset, bytes| writer.write_all_at(offset, bytes),
		)
		.map_err(|error| match error {
			ResumeMeasureError::SourceChanged { .. } => ResumeError::SourceMismatch,
			error => ResumeError::ResumeStage(StageFailure::Resume(error)),
		})?
		.digest;
		flush_written_stage(&mut writer, self.source.length(), session, binding)
			.map_err(ResumeError::ResumeStage)?;
		checkpoint(CopyCheckpoint::RangeResumeDataFlushed);
		let stage = writer
			.close_writes()
			.map_err(|error| ResumeError::ResumeStage(StageFailure::Stage(error)))?;
		self.check_identity(stage.identity())?;
		verify_stage_readback(
			&stage,
			self.source.length(),
			digest,
			scratch,
			session,
			binding,
		)
		.map_err(ResumeError::ResumeStage)?;
		Ok((stage, digest))
	}

	fn verify_retained_stage<T, P, F>(
		&self,
		stage: &T,
		scratch: &mut [u8],
		session: &mut CopySession,
		binding: CopyBinding,
	) -> ResumeResult<ContentDigest, S::Error, T::Error, P, F>
	where
		T: StageReader<Identity = S::Identity>,
	{
		self.check_identity(stage.identity())?;
		let digest = measure_at(self.source.length(), scratch, |offset, bytes| {
			self.source.read_exact_at(offset, bytes)
		})
		.map_err(ResumeError::MeasureSource)?;
		verify_stage_readback(
			stage,
			self.source.length(),
			digest,
			scratch,
			session,
			binding,
		)
		.map_err(ResumeError::ResumeStage)?;
		Ok(digest)
	}
}

fn append<R, S, P, F>(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> ResumeResult<exacopy_journal::SyncedFrame, R, S, P, F> {
	journal
		.append(kind, payload)
		.map_err(|source| ResumeError::Journal { kind, source })
}
