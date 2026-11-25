use exacopy_endpoint::JournalSegment;
use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinFileIdentity, DarwinPublicationBarriers, DarwinRequiredMetadata, DurableJournal,
	DurableJournalError, OwnerError, StreamDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, PublishNoClobber};

/// A single unwritten stage bound to a strictly admitted source.
pub trait PreparedCopy {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The adapter's original failure when attempting exclusive publication.
	type PublishError;
	/// The same stage after writer closure, independent verification, and required metadata.
	type Verified: VerifiedCopy<Error = Self::Error, PublishError = Self::PublishError>;

	/// Returns the immutable model association of the unwritten stage.
	fn binding(&self) -> CopyBinding;
	/// Rechecks source metadata before the first payload read.
	fn check_source_before_read(&self) -> Result<(), Self::Error>;
	/// Consumes the sole writer and verifies read-back with required metadata applied.
	fn verify(self, scratch: &mut [u8]) -> Result<Self::Verified, Self::Error>;
}

/// The same stage after writer closure, independent read-back and required metadata.
pub trait VerifiedCopy {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The adapter's original failure when attempting exclusive publication.
	type PublishError;

	/// Observes the live stage identity and the recorded source and read-back digests.
	fn observe_streams(&self) -> Result<VerifiedStreams, Self::Error>;
	/// Returns required metadata verified after the stage file barrier.
	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, Self::Error>;
	/// Confirms source binding and required metadata immediately before intent.
	fn check_source_after_metadata(&self) -> Result<(), Self::Error>;
	/// Consumes model authority to attempt one exclusive publication of the verified stage.
	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure<Self::PublishError>>;
}

/// Read-back and source stream evidence associated with the current sealed stage.
#[derive(Debug)]
pub struct VerifiedStreams {
	/// The freshly observed identity of the verified private stage.
	pub stage: DarwinFileIdentity,
	/// The logical length of the unnamed stream in bytes.
	pub length: u64,
	/// The digest measured from the copied source stream.
	pub source_digest: StreamDigest,
	/// The digest measured during independent stage read-back.
	pub stage_digest: StreamDigest,
}

/// The observations after the adapter confirmed exclusive rename.
#[derive(Debug)]
pub struct PublishedEvidence {
	/// The checked public target identity or its representation error.
	pub target: Result<DarwinFileIdentity, OwnerError>,
	/// Evidence of both required namespace barriers or a representation error.
	pub barriers: Result<DarwinPublicationBarriers, OwnerError>,
}

/// An unsuccessful or incomplete publication attempt and the established effect.
#[derive(Debug)]
pub struct PublicationFailure<E> {
	/// The original adapter failure.
	pub cause: E,
	/// The strongest namespace observation established by the adapter.
	pub effect: FailedEffect,
}

/// The namespace effect that the adapter can report after a failed attempt.
#[derive(Debug)]
pub enum FailedEffect {
	/// The adapter rejected the operation before rename.
	Rejected,
	/// The exclusive rename refused an occupied target.
	Conflict,
	/// The attempt cannot establish a definitive namespace outcome.
	Uncertain,
	/// Rename succeeded and subsequent required evidence is incomplete.
	Renamed {
		/// The public target identity if available, with representation errors preserved.
		target: Option<Result<DarwinFileIdentity, OwnerError>>,
	},
}

/// Appends the exact frame and returns its completed file-barrier evidence.
pub trait PublicationJournal {
	/// Appends the requested kind and payload with the configured file barrier.
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError>;
}

/// Persists one immutable receipt in the leased private job.
pub trait ReceiptStore {
	/// The adapter failure retained for diagnostics.
	type Error;

	/// Creates and synchronizes the immutable private receipt.
	fn persist(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}

impl<T: JournalSegment> PublicationJournal for DurableJournal<T> {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.append_frame(kind, payload)
	}
}
