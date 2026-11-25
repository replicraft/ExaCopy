use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	BasicMetadata, DurableJournal, EntryPreparation, EntryPrepared, JournalContext, JournalEntryId,
	LinuxFileIdentity, LiveSourceView, MetadataRecorded, ObservedTimestamp, OwnerTimestamp,
	PreparedError, PreparedTarget, SourceInodeMetadata, SourceMeasurementId, SourceTimes,
	StageSealed, StreamDigest, StreamEvidence, StreamLength, SyncedFrame, TargetObservation,
	VerificationRecorded,
};
use exacopy_platform::linux::{SourceObservation, SourceTimestamp};

use super::super::job::native_identity;
use super::super::{DestinationPlanBinding, StageFailure, VerifiedStage};
use super::{LocalCopyError, append};

pub(super) fn timestamp(value: SourceTimestamp) -> Result<ObservedTimestamp, PreparedError> {
	ObservedTimestamp::new(value.seconds(), value.nanoseconds())
}

pub(super) struct EntryEvidence<'name> {
	pub(super) context: JournalContext,
	pub(super) entry: JournalEntryId,
	source: LiveSourceView,
	metadata: SourceInodeMetadata,
	target: PreparedTarget<'name>,
}

impl<'name> EntryEvidence<'name> {
	pub(super) fn new(
		observation: SourceObservation,
		context: JournalContext,
		entry: JournalEntryId,
		destination: DestinationPlanBinding<'name>,
	) -> Result<Self, LocalCopyError> {
		let time = |value| timestamp(value).map_err(LocalCopyError::Preparation);
		let source = LiveSourceView::new(
			native_identity(observation.identity()),
			observation.len(),
			SourceTimes {
				accessed_at: time(observation.accessed_at())?,
				modified_at: time(observation.modified_at())?,
				changed_at: time(observation.changed_at())?,
			},
		)
		.map_err(LocalCopyError::Preparation)?;
		let metadata = SourceInodeMetadata::no_visible_extended_attributes(
			observation.mode(),
			observation.owner(),
			observation.group(),
			observation.link_count(),
		)
		.map_err(LocalCopyError::Preparation)?;
		Ok(Self {
			context,
			entry,
			source,
			metadata,
			target: PreparedTarget {
				root: destination.root.id,
				component: destination.component,
				observation: TargetObservation::AbsentObserved,
			},
		})
	}

	pub(super) fn record(
		&self,
		journal: &mut DurableJournal,
		stage: LinuxFileIdentity,
	) -> Result<SourceMeasurementId, StageFailure> {
		let entry = EntryPrepared::new(
			self.context,
			self.entry,
			EntryPreparation {
				source: self.source,
				stage,
				target: self.target,
				source_metadata: self.metadata,
			},
		)
		.map_err(StageFailure::EntryPreparation)?;
		let payload = entry.encode();
		let _ = journal
			.append(FrameKind::EntryPrepared, &payload)
			.map_err(StageFailure::EntryJournal)?;
		Ok(SourceMeasurementId::from_prepared_payload(&payload))
	}

	pub(super) fn seal(&self, stage: &VerifiedStage<'_>) -> Result<SealEvidence, LocalCopyError> {
		let stage_evidence = StreamEvidence {
			identity: native_identity(stage.identity()),
			length: StreamLength::new(stage.length()).map_err(LocalCopyError::Verification)?,
			digest: StreamDigest::from_bytes(*stage.digest().as_bytes()),
		};
		let source_evidence = StreamEvidence {
			identity: self.source.identity(),
			length: StreamLength::new(self.source.length())
				.map_err(LocalCopyError::Verification)?,
			// VerifiedStage exists only when the independently measured digests agreed.
			digest: stage_evidence.digest,
		};
		let verification =
			VerificationRecorded::new(self.context, self.entry, source_evidence, stage_evidence)
				.map_err(LocalCopyError::Verification)?;
		let times = self.source.times();
		let time = |value: ObservedTimestamp| {
			OwnerTimestamp::new(value.seconds(), value.nanoseconds())
				.map_err(LocalCopyError::Timestamp)
		};
		let metadata = BasicMetadata::new(
			self.metadata.mode(),
			self.metadata.owner(),
			self.metadata.group(),
			time(times.accessed_at)?,
			time(times.modified_at)?,
		)
		.map_err(LocalCopyError::Verification)?;
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

pub(super) struct SealEvidence {
	sealed: StageSealed,
	pub(super) verification: VerificationRecorded,
	metadata: MetadataRecorded,
}

impl SealEvidence {
	pub(super) fn record(
		&self,
		journal: &mut DurableJournal,
	) -> Result<SyncedFrame, LocalCopyError> {
		let _ = append(journal, FrameKind::StageSealed, &self.sealed.encode())?;
		let _ = append(
			journal,
			FrameKind::VerificationRecorded,
			&self.verification.encode(),
		)?;
		append(
			journal,
			FrameKind::MetadataRecorded,
			&self.metadata.encode(),
		)
	}
}
