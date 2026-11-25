use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::{
	CheckpointPages, CopyDestinationView, CopySource, CopySourceObservation, CopySourceRoot,
	CopyWorkspace, InodeTimestamp, PublishableStageDirectory, TargetObservation,
};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_publication::{ExclusivePublication, PublicationFailure};
use exacopy_model::PublishNoClobber;

use super::{
	CheckpointDirectory, ClosedStage, DestinationRoot, FileIdentity, JobDirectory, PublishError,
	ReadError, ReadRoot, SourceFile, SourceObservation, SourceTimestamp, StageDirectory,
	StageError,
};

impl CopySourceRoot for ReadRoot {
	type Error = ReadError;
	type Source = SourceFile;

	fn identity(&self) -> JobFileIdentity {
		inode_identity(ReadRoot::identity(self))
	}

	fn open_regular(&self, name: UnixComponent<'_>) -> Result<Self::Source, Self::Error> {
		ReadRoot::open_regular(self, name)
	}
}

impl CopySource for SourceFile {
	fn copy_observation(&self) -> CopySourceObservation {
		self.observation().into()
	}
}

impl From<SourceObservation> for CopySourceObservation {
	fn from(observation: SourceObservation) -> Self {
		Self {
			mode: observation.mode(),
			owner: observation.owner(),
			group: observation.group(),
			links: observation.link_count(),
			accessed_at: timestamp(observation.accessed_at()),
			modified_at: timestamp(observation.modified_at()),
			changed_at: timestamp(observation.changed_at()),
		}
	}
}

impl CopyDestinationView for DestinationRoot {
	type Error = StageError;

	fn identity(&self) -> JobFileIdentity {
		inode_identity(DestinationRoot::identity(self))
	}

	fn observe_target(&self, target: UnixComponent<'_>) -> Result<TargetObservation, Self::Error> {
		self.target_status(target)
	}
}

fn inode_identity(identity: FileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: identity.device(),
		inode: identity.inode(),
	}
}

fn timestamp(value: SourceTimestamp) -> InodeTimestamp {
	InodeTimestamp {
		seconds: value.seconds(),
		nanoseconds: value.nanoseconds(),
	}
}

impl From<FileIdentity> for JobFileIdentity {
	fn from(identity: FileIdentity) -> Self {
		inode_identity(identity)
	}
}

impl CopyWorkspace for JobDirectory<'_> {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;
	type PublishError = PublishError;
	type Stage<'job>
		= StageDirectory<'job>
	where
		Self: 'job;
	type Checkpoints<'job>
		= CheckpointDirectory<'job>
	where
		Self: 'job;

	fn create_stage_directory(&self) -> Result<Self::Stage<'_>, StageError> {
		JobDirectory::create_stage_directory(self)
	}

	fn create_checkpoint_directory(&self) -> Result<Self::Checkpoints<'_>, StageError> {
		JobDirectory::create_checkpoint_directory(self)
	}
}

impl PublishableStageDirectory for StageDirectory<'_> {
	type PublishError = PublishError;

	fn identity(&self) -> JobFileIdentity {
		inode_identity(StageDirectory::identity(self))
	}

	fn publish<'stage>(
		&'stage self,
		stage: ClosedStage<'stage>,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::PublishError>>
	where
		Self: 'stage,
	{
		ExclusivePublication::publish_no_clobber(stage, authorization)
	}
}

impl CheckpointPages for CheckpointDirectory<'_> {
	type Error = StageError;

	fn persist_page(&self, ordinal: u32, bytes: &[u8]) -> Result<(), Self::Error> {
		self.write_page(ordinal, bytes)
	}
}
