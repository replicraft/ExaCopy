use std::num::{NonZeroU32, NonZeroU64};

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinFileIdentity, DarwinMetadataRecorded,
	DarwinNamespaceObservation, DarwinPhaseError, DarwinPublicationBarriers,
	DarwinPublicationNames, DarwinPublicationOutcome, DarwinPublishIntent, DarwinPublishObserved,
	DarwinReceiptCommitted, DarwinRequiredMetadata, DarwinStageSealed, DarwinStreamEvidence,
	DarwinVerificationRecorded, DurableJournal, JournalFileBarrier, OwnerTimestamp, StreamDigest,
	StreamLength, SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopySession, PublishNoClobber};
use exacopy_platform::macos::publication::{PublishError, PublishedFile};

use super::PreparedDarwinEntry;
use crate::macos::job::admission::native_identity;
use crate::macos::receipt::{DarwinCopyReceipt, DarwinReceiptFrames};
use crate::macos::{VerifiedBasicStage, copy_with_basic_metadata};

mod error;

pub use error::{DarwinCopyError, DarwinCopyFailure, PublicationProgress};

impl<'entry> PreparedDarwinEntry<'entry> {
	/// Copies the bound source and exclusively publishes the verified private stage.
	///
	/// Synchronizes exact intent before requesting the model authorization.
	/// Success returns the receipt after the private receipt file and its journal
	/// commitment have both passed their barriers. Achieved durability is unconfirmed.
	///
	/// # Errors
	/// Refuses changed inputs, failed verification, an incumbent, or incomplete effects.
	/// The failure identifies the retained job and the last established publication boundary.
	pub fn copy_and_publish(
		&mut self,
		scratch: &mut [u8],
	) -> Result<DarwinCopyReceipt<'entry>, DarwinCopyError> {
		let mut progress = self.progress;
		let result = self.execute(scratch, &mut progress);
		self.progress = progress;
		result.map_err(|failure| DarwinCopyError::new(self.job_name(), progress, failure))
	}

	fn execute(
		&mut self,
		scratch: &mut [u8],
		progress: &mut PublicationProgress,
	) -> Result<DarwinCopyReceipt<'entry>, DarwinCopyFailure> {
		let writer = self
			.writer
			.take()
			.ok_or(DarwinCopyFailure::AlreadyAttempted)?;
		let binding = writer.binding();
		let mut session = CopySession::new(binding);
		match session
			.apply(binding, CopyEvent::StagePrepared)
			.map_err(DarwinCopyFailure::Model)?
		{
			Some(CopyEffect::ReadSource(read)) if read.binding() == binding => {}
			_ => return Err(DarwinCopyFailure::UnexpectedEffect),
		}
		self.source
			.check_pre_read_basic_metadata()
			.map_err(DarwinCopyFailure::Source)?;
		let verified = copy_with_basic_metadata(self.source, writer, scratch)
			.map_err(DarwinCopyFailure::Transfer)?;
		for event in [
			CopyEvent::WritersJoined,
			CopyEvent::DataFlushed,
			CopyEvent::ReadbackVerified,
			CopyEvent::MetadataReady,
			CopyEvent::StageSealed,
		] {
			observe(&mut session, binding, event)?;
		}

		let phases = VerifiedPhases::new(
			&self.frame,
			self.preparation.preparation().source.identity(),
			&verified,
		)?;
		let metadata_frame = phases.record(self.journal)?;
		self.source
			.check_basic_metadata()
			.map_err(DarwinCopyFailure::Source)?;
		let intent = DarwinPublishIntent::new(
			NonZeroU64::MIN,
			&self.frame,
			&phases.seal,
			&phases.verification,
			&phases.metadata,
		)?;
		let (intent_frame, authorization) =
			authorize(self.journal, &mut session, binding, intent, progress)?;

		let published = match verified.stage.publish_no_clobber(authorization) {
			Ok(published) => published,
			Err(error) => {
				let (outcome, event) = classify(&error, progress);
				let recording = observe(&mut session, binding, event)
					.and_then(|()| {
						record_observation(
							self.journal,
							&intent_frame,
							outcome,
							incomplete_names(&error)?,
						)
						.map(|_| ())
					})
					.err()
					.map(Box::new);
				return Err(DarwinCopyFailure::Publish {
					error: Box::new(error),
					recording,
				});
			}
		};
		*progress = PublicationProgress::Renamed;
		let (observed, durability, synced) = record_success(
			self.journal,
			&metadata_frame,
			&intent_frame,
			&published,
			&mut session,
			binding,
		)?;
		let receipt = DarwinCopyReceipt::from_synced_durability(
			&self.plan,
			DarwinReceiptFrames {
				verification: &metadata_frame.verification,
				metadata: &metadata_frame.metadata,
				intent: &intent_frame,
				observed: &observed,
				durability: &durability,
			},
			&synced,
		)
		.map_err(DarwinCopyFailure::Receipt)?;
		self.job
			.create_receipt_directory()
			.and_then(|directory| directory.write_receipt(&receipt.encode()))
			.map_err(DarwinCopyFailure::PersistReceipt)?;
		let committed = DarwinReceiptCommitted::new(&durability, receipt.digest())?;
		append(
			self.journal,
			FrameKind::ReceiptCommitted,
			&committed.encode(),
		)?;
		*progress = PublicationProgress::ReceiptCommitted;
		observe(&mut session, binding, CopyEvent::ReceiptRecorded)?;
		Ok(receipt)
	}
}

struct VerifiedPhases {
	seal: DarwinStageSealed,
	verification: DarwinVerificationRecorded,
	metadata: DarwinMetadataRecorded,
}

struct VerifiedFrames {
	verification: Frame,
	metadata: Frame,
}

impl VerifiedPhases {
	fn new(
		prepared: &Frame,
		source: DarwinFileIdentity,
		verified: &VerifiedBasicStage<'_>,
	) -> Result<Self, DarwinCopyFailure> {
		let stage = native_identity(
			verified
				.stage
				.observe_identity()
				.map_err(DarwinCopyFailure::Stage)?,
		)
		.map_err(DarwinCopyFailure::Observation)?;
		let length = StreamLength::new(verified.stage.length())
			.map_err(|_| DarwinPhaseError::StreamMismatch)?;
		let seal = DarwinStageSealed::new(prepared, stage, length)?;
		let verification = DarwinVerificationRecorded::new(
			prepared,
			&seal,
			DarwinStreamEvidence {
				identity: source,
				length,
				digest: StreamDigest::from_bytes(*verified.source_digest.as_bytes()),
			},
			DarwinStreamEvidence {
				identity: stage,
				length,
				digest: StreamDigest::from_bytes(*verified.digest().as_bytes()),
			},
		)?;
		let required = verified.metadata();
		let observed = DarwinRequiredMetadata::new(
			required.mode(),
			NonZeroU32::new(required.uid()).ok_or(DarwinPhaseError::MetadataMismatch)?,
			required.gid(),
			OwnerTimestamp::new(required.atime().seconds(), required.atime().nanoseconds())
				.map_err(DarwinCopyFailure::Observation)?,
			OwnerTimestamp::new(required.mtime().seconds(), required.mtime().nanoseconds())
				.map_err(DarwinCopyFailure::Observation)?,
		)?;
		let metadata =
			DarwinMetadataRecorded::new(prepared, &seal, &verification, stage, observed)?;
		Ok(Self {
			seal,
			verification,
			metadata,
		})
	}

	fn record(&self, journal: &mut DurableJournal) -> Result<VerifiedFrames, DarwinCopyFailure> {
		append(journal, FrameKind::StageSealed, &self.seal.encode())?;
		let (verification, _) = append_frame(
			journal,
			FrameKind::VerificationRecorded,
			self.verification.encode(),
		)?;
		let (metadata, _) =
			append_frame(journal, FrameKind::MetadataRecorded, self.metadata.encode())?;
		Ok(VerifiedFrames {
			verification,
			metadata,
		})
	}
}

fn observe(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), DarwinCopyFailure> {
	if session
		.apply(binding, event)
		.map_err(DarwinCopyFailure::Model)?
		.is_some()
	{
		return Err(DarwinCopyFailure::UnexpectedEffect);
	}
	Ok(())
}

fn authorize(
	journal: &mut DurableJournal,
	session: &mut CopySession,
	binding: CopyBinding,
	intent: DarwinPublishIntent<'_>,
	progress: &mut PublicationProgress,
) -> Result<(Frame, PublishNoClobber), DarwinCopyFailure> {
	let (frame, synced) = append_frame(journal, FrameKind::PublishIntent, intent.encode())?;
	if synced.barrier() != JournalFileBarrier::DarwinFullFsync {
		return Err(DarwinCopyFailure::UnexpectedBarrier);
	}
	*progress = PublicationProgress::IntentSynchronized;
	let effect = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.map_err(DarwinCopyFailure::Model)?;
	let Some(CopyEffect::PublishNoClobber(authorization)) = effect else {
		return Err(DarwinCopyFailure::UnexpectedEffect);
	};
	Ok((frame, authorization))
}

fn classify(
	error: &PublishError,
	progress: &mut PublicationProgress,
) -> (DarwinPublicationOutcome, CopyEvent) {
	let outcome = match error {
		PublishError::Rejected { .. } => DarwinPublicationOutcome::RejectedBeforeRename,
		PublishError::Conflict { .. } => {
			return (DarwinPublicationOutcome::Conflict, CopyEvent::Conflict);
		}
		PublishError::Renamed { .. } => {
			*progress = PublicationProgress::Renamed;
			DarwinPublicationOutcome::RenameConfirmedIncomplete
		}
		_ => DarwinPublicationOutcome::UncertainRename,
	};
	(outcome, CopyEvent::OutcomeUncertain)
}

fn incomplete_names(error: &PublishError) -> Result<DarwinPublicationNames, DarwinCopyFailure> {
	if let PublishError::Renamed {
		observed_target: Some(target),
		..
	} = error
	{
		return Ok(DarwinPublicationNames {
			target: DarwinNamespaceObservation::Present(
				native_identity(*target).map_err(DarwinCopyFailure::Observation)?,
			),
			stage: DarwinNamespaceObservation::Absent,
		});
	}
	Ok(DarwinPublicationNames {
		target: DarwinNamespaceObservation::Unobserved,
		stage: DarwinNamespaceObservation::Unobserved,
	})
}

fn record_observation(
	journal: &mut DurableJournal,
	intent: &Frame,
	outcome: DarwinPublicationOutcome,
	names: DarwinPublicationNames,
) -> Result<Frame, DarwinCopyFailure> {
	let observed = DarwinPublishObserved::new(intent, outcome, names)?;
	let (frame, _) = append_frame(journal, FrameKind::PublishObserved, observed.encode())?;
	Ok(frame)
}

fn record_success(
	journal: &mut DurableJournal,
	frames: &VerifiedFrames,
	intent: &Frame,
	published: &PublishedFile,
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(Frame, Frame, SyncedFrame), DarwinCopyFailure> {
	let target =
		native_identity(published.target_identity()).map_err(DarwinCopyFailure::Observation)?;
	let observed = record_observation(
		journal,
		intent,
		DarwinPublicationOutcome::Published,
		DarwinPublicationNames {
			target: DarwinNamespaceObservation::Present(target),
			stage: DarwinNamespaceObservation::Absent,
		},
	)?;
	observe(session, binding, CopyEvent::Published)?;
	let durability = DarwinDurabilityRecorded::new(
		&frames.metadata,
		intent,
		&observed,
		DarwinPublicationBarriers {
			stage_directory: native_identity(published.synced_stage_directory())
				.map_err(DarwinCopyFailure::Observation)?,
			destination_directory: native_identity(published.synced_destination_directory())
				.map_err(DarwinCopyFailure::Observation)?,
		},
	)?;
	let (durability, synced) =
		append_frame(journal, FrameKind::DurabilityRecorded, durability.encode())?;
	observe(session, binding, CopyEvent::DirectoryFlushed)?;
	Ok((observed, durability, synced))
}

fn append_frame(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: Vec<u8>,
) -> Result<(Frame, SyncedFrame), DarwinCopyFailure> {
	journal
		.append_frame(kind, payload)
		.map_err(|error| DarwinCopyFailure::Journal { kind, error })
}

fn append(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<(), DarwinCopyFailure> {
	let _ = journal
		.append(kind, payload)
		.map_err(|error| DarwinCopyFailure::Journal { kind, error })?;
	Ok(())
}
