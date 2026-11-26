use std::fmt;

use exacopy_endpoint::linux_publication::PublicationFailure;
use exacopy_journal::remote_download::RemoteDownloadContext;
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_model::PublishNoClobber;
use exacopy_platform::linux::{
	PublishError, RemoteDestinationEligibility, SelectedStreamLocation,
	SelectedStreamMetadataReady, SelectedStreamPublishError,
};
use exacopy_transfer::remote_finalization::{
	RemoteFinalizationStage, RemotePublicationAuthority, RemotePublicationFacts,
	RemotePublicationFence, RemoteReadyStage, RemoteReadyStageFacts, RemoteStageLocation,
	RemoteStageNames,
};

use super::super::remote_download::{RemoteGrant, native_authority};
use super::super::remote_journal::{Error, IntentReadback, record_identity};
use super::{
	CheckpointStage, ClosedStage, FileIdentity, FreshStage, NativeCaptureStage,
	NativeCaptureStageError, NativeClosedStage, ReadView, StageError,
};

#[derive(Clone, Copy)]
pub(in crate::assembly::linux) struct PublicationContext<'held> {
	pub(in crate::assembly::linux) job: RemoteDownloadContext,
	pub(in crate::assembly::linux) authority: RemotePublicationAuthority,
	pub(in crate::assembly::linux) grant: &'held RemoteGrant,
	pub(in crate::assembly::linux) eligibility: &'held RemoteDestinationEligibility<'held>,
	pub(in crate::assembly::linux) intent: &'held IntentReadback,
}

pub(in crate::assembly::linux) struct FinalizingCaptureStage<'stage>(
	pub(in crate::assembly::linux) NativeCaptureStage<'stage>,
	pub(in crate::assembly::linux) PublicationContext<'stage>,
);

impl<'stage> FreshStage for FinalizingCaptureStage<'stage> {
	type Error = NativeCaptureStageError;
	type Closed = FinishStage<'stage>;

	const MAX_CHUNK_BYTES: usize = NativeCaptureStage::MAX_CHUNK_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		self.0.unwritten_length()
	}

	fn write_next(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		self.0.write_next(bytes)
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		Ok(FinishStage {
			stage: self.0.sync_and_close()?,
			publication: self.1,
		})
	}
}

impl CheckpointStage for FinalizingCaptureStage<'_> {
	type Binding = FileIdentity;

	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		self.0.sync_prefix(end)
	}
}

pub(in crate::assembly::linux) struct FinishStage<'stage> {
	stage: NativeClosedStage<'stage>,
	publication: PublicationContext<'stage>,
}

impl<'stage> ClosedStage for FinishStage<'stage> {
	type Error = NativeCaptureStageError;
	type Reader<'reader>
		= <NativeClosedStage<'stage> as ClosedStage>::Reader<'reader>
	where
		Self: 'reader;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.stage.open_read_back()
	}
}

impl<'stage> RemoteFinalizationStage for FinishStage<'stage> {
	type Error = StageFinalizationError;
	type Ready = ReadyStage<'stage>;

	fn inspect_location(&self) -> Result<RemoteStageLocation<'_>, Self::Error> {
		self.stage.open_read_back()?.recheck_observation()?;
		let checked = self.stage.closed.inspect_selected_stream_location()?;
		if (checked.names.stage, checked.names.target) != self.stage.names {
			return Err(StageError::IdentityChanged.into());
		}
		Ok(project(checked))
	}

	fn prepare_metadata(self, length: u64) -> Result<Self::Ready, Self::Error> {
		let observed = self.inspect_location()?;
		let names = RemoteStageNames {
			stage: self.stage.names.0,
			target: self.stage.names.1,
		};
		let expected = RemoteStageLocation {
			binding: observed.binding,
			stage: observed.stage,
			directory: observed.directory,
			parent: observed.parent,
			names,
		};
		// Hold independently bound raw component slices while consuming the same original stage.
		let native = self.stage.closed.prepare_selected_stream_metadata(length)?;
		Ok(ReadyStage {
			native,
			expected,
			publication: self.publication,
		})
	}
}

fn project(location: SelectedStreamLocation<'_>) -> RemoteStageLocation<'_> {
	RemoteStageLocation {
		binding: location.binding,
		stage: record_identity(location.stage),
		directory: record_identity(location.directory),
		parent: record_identity(location.destination),
		names: RemoteStageNames {
			stage: location.names.stage,
			target: location.names.target,
		},
	}
}

pub(in crate::assembly::linux) struct ReadyStage<'stage> {
	native: SelectedStreamMetadataReady<'stage>,
	expected: RemoteStageLocation<'stage>,
	publication: PublicationContext<'stage>,
}

impl RemoteReadyStage for ReadyStage<'_> {
	type Error = StageFinalizationError;

	fn names(&self) -> RemoteStageNames<'_> {
		self.expected.names
	}

	fn recheck(&self) -> Result<RemoteReadyStageFacts, Self::Error> {
		self.native.recheck()?;
		let names = self.native.names()?;
		let observed = self.native.observed();
		if (names.stage, names.target) != (self.expected.names.stage, self.expected.names.target) {
			return Err(StageError::IdentityChanged.into());
		}
		Ok(RemoteReadyStageFacts {
			binding: observed.binding(),
			stage: record_identity(observed.stage()),
			directory: record_identity(observed.stage_directory()),
			parent: record_identity(observed.destination()),
			length: observed.length(),
			mode: u16::try_from(observed.mode()).map_err(|_| StageError::IdentityChanged)?,
			metadata: RemoteLocalMetadata {
				uid: observed.owner(),
				gid: observed.group(),
			},
		})
	}

	fn publish(
		self,
		permit: PublishNoClobber,
		fence: RemotePublicationFence,
	) -> Result<RemotePublicationFacts, PublicationFailure<Self::Error>> {
		let publication = self.publication;
		let authority = fence.authority();
		if publication.job != fence.context() || publication.authority != authority {
			return Err(PublicationFailure::Uncertain(StageFinalizationError::Gate(
				Error::Binding,
			)));
		}
		let selected = native_authority(fence)
			.map_err(|cause| PublicationFailure::Uncertain(StageFinalizationError::Gate(cause)))?;
		let expected = self.expected;
		let outcome =
			self.native
				.publish_no_clobber(publication.eligibility, selected, permit, |request| {
					if request.authority != selected || project(request.location) != expected {
						return Err(Error::Binding);
					}
					let intent = publication.intent.consume(fence)?;
					if intent.stage != expected.stage {
						return Err(Error::Binding);
					}
					publication.grant.enter(authority.scope, authority.grant)
				});
		let facts = match outcome {
			Ok(facts) => facts,
			Err(cause @ SelectedStreamPublishError::Native(PublishError::Conflict)) => {
				return Err(PublicationFailure::Conflict(
					StageFinalizationError::Publish(cause),
				));
			}
			Err(cause) => {
				return Err(PublicationFailure::Uncertain(
					StageFinalizationError::Publish(cause),
				));
			}
		};
		Ok(RemotePublicationFacts {
			target: record_identity(facts.target()),
			directory: record_identity(facts.stage_directory()),
			parent: record_identity(facts.destination()),
		})
	}
}

#[derive(Debug)]
pub enum StageFinalizationError {
	Capture(NativeCaptureStageError),
	Native(StageError),
	Gate(Error),
	Publish(SelectedStreamPublishError<Error>),
}

impl fmt::Display for StageFinalizationError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Capture(cause) => cause.fmt(out),
			Self::Native(cause) => cause.fmt(out),
			Self::Gate(cause) => cause.fmt(out),
			Self::Publish(cause) => cause.fmt(out),
		}
	}
}

impl std::error::Error for StageFinalizationError {}

impl From<NativeCaptureStageError> for StageFinalizationError {
	fn from(cause: NativeCaptureStageError) -> Self {
		Self::Capture(cause)
	}
}

impl From<StageError> for StageFinalizationError {
	fn from(cause: StageError) -> Self {
		Self::Native(cause)
	}
}
