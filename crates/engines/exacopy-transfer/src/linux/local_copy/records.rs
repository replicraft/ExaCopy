use exacopy_content::ContentDigest;
use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_copy::{CopySourceObservation, InodeTimestamp};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	BasicMetadata, DurableJournal, DurableJournalError, EntryPreparation, EntryPrepared,
	JournalContext, JournalEntryId, LinuxFileIdentity, LiveSourceView, MetadataRecorded,
	ObservedTimestamp, OwnerError, OwnerTimestamp, PreparedTarget, SourceInodeMetadata,
	SourceMeasurementId, SourceTimes, StageSealed, StreamDigest, StreamEvidence, StreamLength,
	SyncedFrame, TargetObservation, VerificationRecordError, VerificationRecorded,
};

use crate::linux_staging::StageFailure;

use super::super::DestinationPlanBinding;
use super::CopyError;

pub(in crate::linux) struct EntryEvidence<'name> {
	pub(super) context: JournalContext,
	pub(super) entry: JournalEntryId,
	source: LiveSourceView,
	metadata: SourceInodeMetadata,
	target: PreparedTarget<'name>,
}

impl<'name> EntryEvidence<'name> {
	pub(super) fn new<R, S, P>(
		observation: CopySourceObservation,
		identity: LinuxFileIdentity,
		length: u64,
		context: JournalContext,
		entry: JournalEntryId,
		destination: DestinationPlanBinding<'name>,
	) -> Result<Self, CopyError<R, S, P>> {
		let time = |value: InodeTimestamp| {
			ObservedTimestamp::new(value.seconds, value.nanoseconds).map_err(CopyError::Preparation)
		};
		let source = LiveSourceView::new(
			identity,
			length,
			SourceTimes {
				accessed_at: time(observation.accessed_at)?,
				modified_at: time(observation.modified_at)?,
				changed_at: time(observation.changed_at)?,
			},
		)
		.map_err(CopyError::Preparation)?;
		let metadata = SourceInodeMetadata::no_visible_extended_attributes(
			observation.mode,
			observation.owner,
			observation.group,
			observation.links,
		)
		.map_err(CopyError::Preparation)?;
		Ok(Self::from_preparation(
			context,
			entry,
			source,
			metadata,
			destination,
		))
	}

	pub(in crate::linux) const fn from_preparation(
		context: JournalContext,
		entry: JournalEntryId,
		source: LiveSourceView,
		metadata: SourceInodeMetadata,
		destination: DestinationPlanBinding<'name>,
	) -> Self {
		Self {
			context,
			entry,
			source,
			metadata,
			target: PreparedTarget {
				root: destination.root.id,
				component: destination.component,
				observation: TargetObservation::AbsentObserved,
			},
		}
	}

	pub(super) fn record<R, S>(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
		stage: LinuxFileIdentity,
	) -> Result<SourceMeasurementId, crate::linux_staging::StageFailure<R, S>> {
		let entry = self
			.prepared(stage)
			.map_err(StageFailure::EntryPreparation)?;
		let payload = entry.encode();
		let _ = journal
			.append(FrameKind::EntryPrepared, &payload)
			.map_err(StageFailure::EntryJournal)?;
		Ok(SourceMeasurementId::from_prepared_payload(&payload))
	}

	pub(super) fn prepared(
		&self,
		stage: LinuxFileIdentity,
	) -> Result<EntryPrepared<'name>, exacopy_journal::PreparedError> {
		EntryPrepared::new(
			self.context,
			self.entry,
			EntryPreparation {
				source: self.source,
				stage,
				target: self.target,
				source_metadata: self.metadata,
			},
		)
	}

	pub(in crate::linux) fn seal_stream(
		&self,
		identity: LinuxFileIdentity,
		length: u64,
		digest: ContentDigest,
	) -> Result<SealEvidence, SealError> {
		let stage_evidence = StreamEvidence {
			identity,
			length: StreamLength::new(length).map_err(SealError::Verification)?,
			digest: StreamDigest::from_bytes(*digest.as_bytes()),
		};
		let source_evidence = StreamEvidence {
			identity: self.source.identity(),
			length: StreamLength::new(self.source.length()).map_err(SealError::Verification)?,
			// The caller established independent agreement between these streams.
			digest: stage_evidence.digest,
		};
		let verification =
			VerificationRecorded::new(self.context, self.entry, source_evidence, stage_evidence)
				.map_err(SealError::Verification)?;
		let times = self.source.times();
		let time = |value: ObservedTimestamp| {
			OwnerTimestamp::new(value.seconds(), value.nanoseconds()).map_err(SealError::Timestamp)
		};
		let metadata = BasicMetadata::new(
			self.metadata.mode(),
			self.metadata.owner(),
			self.metadata.group(),
			time(times.accessed_at)?,
			time(times.modified_at)?,
		)
		.map_err(SealError::Verification)?;
		Ok(SealEvidence {
			sealed: StageSealed {
				context: self.context,
				entry: self.entry,
				stage: stage_evidence.identity,
				length: stage_evidence.length,
			},
			verification,
			metadata: MetadataRecorded {
				context: self.context,
				entry: self.entry,
				stage: stage_evidence.identity,
				metadata,
			},
		})
	}
}

pub(in crate::linux) struct SealEvidence {
	pub(super) sealed: StageSealed,
	pub(in crate::linux) verification: VerificationRecorded,
	pub(super) metadata: MetadataRecorded,
}

pub(super) struct RecordedSeal<'seal> {
	pub(super) seal: &'seal SealEvidence,
	pub(super) verification: SyncedFrame,
	pub(super) metadata: SyncedFrame,
}

impl RecordedSeal<'_> {
	pub(super) const fn verification(&self) -> VerificationRecorded {
		self.seal.verification
	}

	pub(super) fn confirm_journal(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
	) -> Result<(), DurableJournalError> {
		journal.confirm_current_frame(&self.metadata)
	}

	pub(super) const fn heads(&self) -> (ChainHead, ChainHead) {
		(self.verification.head(), self.metadata.head())
	}
}

impl SealEvidence {
	pub(in crate::linux) fn record(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
	) -> Result<SyncedFrame, SealError> {
		Ok(self.record_with_heads(journal)?.metadata)
	}

	pub(super) fn record_with_heads(
		&self,
		journal: &mut DurableJournal<impl JournalSegment>,
	) -> Result<RecordedSeal<'_>, SealError> {
		let _ = append(journal, FrameKind::StageSealed, &self.sealed.encode())?;
		let verification = append(
			journal,
			FrameKind::VerificationRecorded,
			&self.verification.encode(),
		)?;
		let metadata = append(
			journal,
			FrameKind::MetadataRecorded,
			&self.metadata.encode(),
		)?;
		Ok(RecordedSeal {
			seal: self,
			verification,
			metadata,
		})
	}
}

#[derive(Debug)]
pub(in crate::linux) enum SealError {
	Verification(VerificationRecordError),
	Timestamp(OwnerError),
	Journal {
		kind: FrameKind,
		source: DurableJournalError,
	},
}

impl<R, S, P> From<SealError> for CopyError<R, S, P> {
	fn from(error: SealError) -> Self {
		match error {
			SealError::Verification(error) => Self::Verification(error),
			SealError::Timestamp(error) => Self::Timestamp(error),
			SealError::Journal { kind, source } => Self::Journal { kind, source },
		}
	}
}

fn append(
	journal: &mut DurableJournal<impl JournalSegment>,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, SealError> {
	journal
		.append(kind, payload)
		.map_err(|source| SealError::Journal { kind, source })
}
