use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinFileIdentity, DarwinPublicationBarriers, DarwinRequiredMetadata, DurableJournalError,
	OwnerError, StreamDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, PublishNoClobber};

/// A single unwritten stage bound to a strictly admitted source.
pub(super) trait PreparedCopy {
	type Error;
	type PublishError;
	type Verified: VerifiedCopy<Error = Self::Error, PublishError = Self::PublishError>;

	fn binding(&self) -> CopyBinding;
	fn check_source_before_read(&self) -> Result<(), Self::Error>;
	fn verify(self, scratch: &mut [u8]) -> Result<Self::Verified, Self::Error>;
}

/// The same stage after writer closure, independent read-back and required metadata.
pub(super) trait VerifiedCopy {
	type Error;
	type PublishError;

	fn observe_streams(&self) -> Result<VerifiedStreams, Self::Error>;
	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, Self::Error>;
	fn check_source_after_metadata(&self) -> Result<(), Self::Error>;
	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure<Self::PublishError>>;
}

pub(super) struct VerifiedStreams {
	pub(super) stage: DarwinFileIdentity,
	pub(super) length: u64,
	pub(super) source_digest: StreamDigest,
	pub(super) stage_digest: StreamDigest,
}

pub(super) struct PublishedEvidence {
	pub(super) target: Result<DarwinFileIdentity, OwnerError>,
	pub(super) barriers: Result<DarwinPublicationBarriers, OwnerError>,
}

pub(super) struct PublicationFailure<E> {
	pub(super) cause: E,
	pub(super) effect: FailedEffect,
}

pub(super) enum FailedEffect {
	Rejected,
	Conflict,
	Uncertain,
	Renamed {
		target: Option<Result<DarwinFileIdentity, OwnerError>>,
	},
}

/// Appends the exact frame and returns its completed file-barrier evidence.
pub(super) trait PublicationJournal {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError>;
}

/// Persists one immutable receipt in the leased private job.
pub(super) trait ReceiptStore {
	type Error;

	fn persist(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}
