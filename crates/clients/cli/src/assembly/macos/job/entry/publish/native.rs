use std::num::NonZeroU32;

use exacopy_journal::{
	DarwinPhaseError, DarwinPublicationBarriers, DarwinRequiredMetadata, OwnerError,
	OwnerTimestamp, StreamDigest,
};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_platform::macos::publication::PublishError;
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobError};
use exacopy_platform::macos::staging::{StageError, WriteStage};
use exacopy_platform::macos::{ManagedReadError, ManagedRegularFile};
use exacopy_transfer::macos::job::entry::publish::{
	CoordinatorError, CopyFailure, FailedEffect, PreparedCopy, PublicationFailure,
	PublishedEvidence, ReceiptStore, VerifiedCopy, VerifiedStreams,
};

use crate::assembly::macos::job::admission::native_identity;
use crate::assembly::macos::{StageTransferError, VerifiedBasicStage, copy_with_basic_metadata};

use super::DarwinCopyFailure;

pub(in crate::assembly::macos::job::entry) enum NativeCopyError {
	Source(ManagedReadError),
	Transfer(StageTransferError),
	Stage(StageError),
	Observation(OwnerError),
	Record(DarwinPhaseError),
}

impl From<DarwinPhaseError> for NativeCopyError {
	fn from(error: DarwinPhaseError) -> Self {
		Self::Record(error)
	}
}

impl From<CopyFailure<NativeCopyError, Box<PublishError>, JobError>> for DarwinCopyFailure {
	fn from(failure: CopyFailure<NativeCopyError, Box<PublishError>, JobError>) -> Self {
		match failure {
			CopyFailure::Adapter(error) => match error {
				NativeCopyError::Source(error) => Self::Source(error),
				NativeCopyError::Transfer(error) => Self::Transfer(error),
				NativeCopyError::Stage(error) => Self::Stage(error),
				NativeCopyError::Observation(error) => Self::Observation(error),
				NativeCopyError::Record(error) => Self::Record(error),
			},
			CopyFailure::Coordinator(error) => error.into(),
			CopyFailure::Publish { error, recording } => Self::Publish {
				error,
				recording: recording.map(|error| Box::new((*error).into())),
			},
			CopyFailure::PersistReceipt(error) => Self::PersistReceipt(error),
		}
	}
}

impl From<CoordinatorError> for DarwinCopyFailure {
	fn from(error: CoordinatorError) -> Self {
		match error {
			CoordinatorError::Observation(error) => Self::Observation(error),
			CoordinatorError::Record(error) => Self::Record(error),
			CoordinatorError::Model(error) => Self::Model(error),
			CoordinatorError::UnexpectedEffect => Self::UnexpectedEffect,
			CoordinatorError::UnexpectedBarrier => Self::UnexpectedBarrier,
			CoordinatorError::Journal { kind, error } => Self::Journal { kind, error },
			CoordinatorError::Receipt(error) => Self::Receipt(error),
		}
	}
}

#[derive(Debug)]
pub(in crate::assembly::macos::job::entry) struct NativePreparedCopy<'entry> {
	source: &'entry ManagedRegularFile<'entry>,
	writer: WriteStage<'entry>,
}

impl<'entry> NativePreparedCopy<'entry> {
	pub(in crate::assembly::macos::job::entry) const fn new(
		source: &'entry ManagedRegularFile<'entry>,
		writer: WriteStage<'entry>,
	) -> Self {
		Self { source, writer }
	}
}

impl<'entry> PreparedCopy for NativePreparedCopy<'entry> {
	type Error = NativeCopyError;
	type PublishError = Box<PublishError>;
	type Verified = NativeVerifiedCopy<'entry>;

	fn binding(&self) -> CopyBinding {
		self.writer.binding()
	}

	fn check_source_before_read(&self) -> Result<(), NativeCopyError> {
		self.source
			.check_pre_read_basic_metadata()
			.map(|_| ())
			.map_err(NativeCopyError::Source)
	}

	fn verify(self, scratch: &mut [u8]) -> Result<Self::Verified, NativeCopyError> {
		let verified = copy_with_basic_metadata(self.source, self.writer, scratch)
			.map_err(NativeCopyError::Transfer)?;
		Ok(NativeVerifiedCopy {
			source: self.source,
			verified,
		})
	}
}

pub(in crate::assembly::macos::job::entry) struct NativeVerifiedCopy<'entry> {
	source: &'entry ManagedRegularFile<'entry>,
	verified: VerifiedBasicStage<'entry>,
}

impl VerifiedCopy for NativeVerifiedCopy<'_> {
	type Error = NativeCopyError;
	type PublishError = Box<PublishError>;

	fn observe_streams(&self) -> Result<VerifiedStreams, NativeCopyError> {
		let stage = self
			.verified
			.stage
			.observe_identity()
			.map_err(NativeCopyError::Stage)?;
		Ok(VerifiedStreams {
			stage: native_identity(stage).map_err(NativeCopyError::Observation)?,
			length: self.verified.stage.length(),
			source_digest: StreamDigest::from_bytes(*self.verified.source_digest.as_bytes()),
			stage_digest: StreamDigest::from_bytes(*self.verified.digest().as_bytes()),
		})
	}

	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, NativeCopyError> {
		let required = self.verified.metadata();
		Ok(DarwinRequiredMetadata::new(
			required.mode(),
			NonZeroU32::new(required.uid()).ok_or(DarwinPhaseError::MetadataMismatch)?,
			required.gid(),
			OwnerTimestamp::new(required.atime().seconds(), required.atime().nanoseconds())
				.map_err(NativeCopyError::Observation)?,
			OwnerTimestamp::new(required.mtime().seconds(), required.mtime().nanoseconds())
				.map_err(NativeCopyError::Observation)?,
		)?)
	}

	fn check_source_after_metadata(&self) -> Result<(), NativeCopyError> {
		self.source
			.check_basic_metadata()
			.map(|_| ())
			.map_err(NativeCopyError::Source)
	}

	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure<Self::PublishError>> {
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

fn publication_failure(error: PublishError) -> PublicationFailure<Box<PublishError>> {
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

pub(super) struct NativeReceiptStore<'job>(pub(super) &'job JobDirectory<'job>);

impl ReceiptStore for NativeReceiptStore<'_> {
	type Error = JobError;

	fn persist(&self, bytes: &[u8]) -> Result<(), JobError> {
		self.0
			.create_receipt_directory()
			.and_then(|directory| directory.write_receipt(bytes))
			.map(|_| ())
	}
}
