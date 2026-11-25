use std::num::NonZeroU32;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinPhaseError, DarwinPublicationBarriers, DarwinRequiredMetadata, DurableJournal,
	DurableJournalError, OwnerTimestamp, StreamDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::publication::PublishError;
use exacopy_platform::macos::staging::WriteStage;
use exacopy_platform::macos::staging::jobs::JobDirectory;

use crate::macos::job::admission::native_identity;
use crate::macos::{VerifiedBasicStage, copy_with_basic_metadata};

use super::DarwinCopyFailure;
use super::capabilities::{
	FailedEffect, PreparedCopy, PublicationFailure, PublicationJournal, PublishedEvidence,
	ReceiptStore, VerifiedCopy, VerifiedStreams,
};

pub(super) struct NativePreparedCopy<'entry> {
	source: &'entry ManagedRegularFile<'entry>,
	writer: WriteStage<'entry>,
}

impl<'entry> NativePreparedCopy<'entry> {
	pub(super) const fn new(
		source: &'entry ManagedRegularFile<'entry>,
		writer: WriteStage<'entry>,
	) -> Self {
		Self { source, writer }
	}
}

impl<'entry> PreparedCopy for NativePreparedCopy<'entry> {
	type Verified = NativeVerifiedCopy<'entry>;

	fn binding(&self) -> CopyBinding {
		self.writer.binding()
	}

	fn check_source_before_read(&self) -> Result<(), DarwinCopyFailure> {
		self.source
			.check_pre_read_basic_metadata()
			.map(|_| ())
			.map_err(DarwinCopyFailure::Source)
	}

	fn verify(self, scratch: &mut [u8]) -> Result<Self::Verified, DarwinCopyFailure> {
		let verified = copy_with_basic_metadata(self.source, self.writer, scratch)
			.map_err(DarwinCopyFailure::Transfer)?;
		Ok(NativeVerifiedCopy {
			source: self.source,
			verified,
		})
	}
}

pub(super) struct NativeVerifiedCopy<'entry> {
	source: &'entry ManagedRegularFile<'entry>,
	verified: VerifiedBasicStage<'entry>,
}

impl VerifiedCopy for NativeVerifiedCopy<'_> {
	fn observe_streams(&self) -> Result<VerifiedStreams, DarwinCopyFailure> {
		let stage = self
			.verified
			.stage
			.observe_identity()
			.map_err(DarwinCopyFailure::Stage)?;
		Ok(VerifiedStreams {
			stage: native_identity(stage).map_err(DarwinCopyFailure::Observation)?,
			length: self.verified.stage.length(),
			source_digest: StreamDigest::from_bytes(*self.verified.source_digest.as_bytes()),
			stage_digest: StreamDigest::from_bytes(*self.verified.digest().as_bytes()),
		})
	}

	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, DarwinCopyFailure> {
		let required = self.verified.metadata();
		Ok(DarwinRequiredMetadata::new(
			required.mode(),
			NonZeroU32::new(required.uid()).ok_or(DarwinPhaseError::MetadataMismatch)?,
			required.gid(),
			OwnerTimestamp::new(required.atime().seconds(), required.atime().nanoseconds())
				.map_err(DarwinCopyFailure::Observation)?,
			OwnerTimestamp::new(required.mtime().seconds(), required.mtime().nanoseconds())
				.map_err(DarwinCopyFailure::Observation)?,
		)?)
	}

	fn check_source_after_metadata(&self) -> Result<(), DarwinCopyFailure> {
		self.source
			.check_basic_metadata()
			.map(|_| ())
			.map_err(DarwinCopyFailure::Source)
	}

	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure> {
		let published = self
			.verified
			.stage
			.publish_no_clobber(authorization)
			.map_err(publication_failure)?;
		let barriers = || {
			Ok(DarwinPublicationBarriers {
				stage_directory: native_identity(published.synced_stage_directory())?,
				destination_directory: native_identity(published.synced_destination_directory())?,
			})
		};
		Ok(PublishedEvidence {
			target: native_identity(published.target_identity()),
			barriers: barriers(),
		})
	}
}

fn publication_failure(error: PublishError) -> PublicationFailure {
	let effect = match &error {
		PublishError::Rejected { .. } => FailedEffect::Rejected,
		PublishError::Conflict { .. } => FailedEffect::Conflict,
		PublishError::Renamed {
			observed_target, ..
		} => FailedEffect::Renamed {
			target: observed_target.map(native_identity),
		},
		_ => FailedEffect::Uncertain,
	};
	PublicationFailure {
		cause: Box::new(error),
		effect,
	}
}

impl PublicationJournal for DurableJournal {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.append_frame(kind, payload)
	}
}

impl ReceiptStore for JobDirectory<'_> {
	fn persist(&self, bytes: &[u8]) -> Result<(), DarwinCopyFailure> {
		self.create_receipt_directory()
			.and_then(|directory| directory.write_receipt(bytes))
			.map(|_| ())
			.map_err(DarwinCopyFailure::PersistReceipt)
	}
}
