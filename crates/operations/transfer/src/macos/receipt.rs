//! Canonical private receipts for single-file copies in owner-managed APFS directories.

use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinFileIdentity, DarwinMetadataRecorded, DarwinPublishIntent,
	DarwinRequiredMetadata, DarwinStreamEvidence, DarwinVerificationRecorded, JournalContext,
	JournalEntryId, JournalFileBarrier, ObservedTimestamp, OwnerTimestamp, SyncedFrame,
};

use super::plan::{DarwinCopyPlan, DestinationPlanBinding};

mod error;
mod wire;

#[cfg(test)]
mod tests;

pub use error::DarwinCopyReceiptError;
pub use wire::MAX_DARWIN_COPY_RECEIPT_BYTES;

/// Observations represented by the private successful managed APFS copy artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinCopyReceiptEvidence<'name> {
	/// The planned job, run epoch, and canonical plan digest.
	pub context: JournalContext,
	/// The sole entry selected for publication.
	pub entry: JournalEntryId,
	/// The native file observed during the source stream measurement.
	pub source: DarwinFileIdentity,
	/// The selected public name and the native parent synchronized after publication.
	pub destination: DestinationPlanBinding<'name>,
	/// The published identity and its independently verified logical stream.
	pub stream: DarwinStreamEvidence,
	/// Strict basic metadata matched to the source before exclusive publication.
	pub metadata: DarwinRequiredMetadata,
	/// The former private stage parent synchronized after publication.
	pub stage_directory: DarwinFileIdentity,
}

/// The exact journal records used to associate a receipt with one accepted publication.
#[derive(Clone, Copy, Debug)]
pub struct DarwinReceiptFrames<'frame> {
	/// Kind 5, with the matched, complete source and stage measurements.
	pub verification: &'frame Frame,
	/// Kind 6, with the read-back of required metadata and the stage file barrier.
	pub metadata: &'frame Frame,
	/// Kind 7, authorizing the same stage and target.
	pub intent: &'frame Frame,
	/// Kind 8, reporting a confirmed exclusive rename of the stage.
	pub observed: &'frame Frame,
	/// Kind 9, recording both post-rename directory barriers.
	pub durability: &'frame Frame,
}

/// A private managed APFS preserve-mode success artifact.
///
/// The fixed profile records a live-observed, retained source, independent logical writes,
/// complete BLAKE3-256 hash read-back of the unnamed data stream, strict basic metadata,
/// and exclusive publication with both directory barriers. Read-back may use kernel cache.
/// Achieved durability is unconfirmed. To interpret decoded bytes as execution evidence,
/// associate them with the authoritative journal and its committed receipt digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinCopyReceipt<'name> {
	evidence: DarwinCopyReceiptEvidence<'name>,
	durability_frame: ChainHead,
}

impl<'name> DarwinCopyReceipt<'name> {
	/// Creates a receipt for the exact kind-9 frame synchronized with Darwin `F_FULLFSYNC`.
	///
	/// The caller supplies a plan and integrity-checked frames from one semantically accepted
	/// journal prefix under the independently authorized owner and roots.
	///
	/// # Errors
	/// Rejects another synchronization profile, a mismatched frame token, or inconsistent evidence.
	pub fn from_synced_durability(
		plan: &DarwinCopyPlan<'name>,
		frames: DarwinReceiptFrames<'_>,
		synced: &SyncedFrame,
	) -> Result<Self, DarwinCopyReceiptError> {
		if synced.kind() != FrameKind::DurabilityRecorded
			|| synced.barrier() != JournalFileBarrier::DarwinFullFsync
			|| synced.head() != frames.durability.head()
		{
			return Err(DarwinCopyReceiptError::InvalidDurabilityFrame);
		}
		Self::from_journal(plan, frames)
	}

	/// Checks that the receipt reproduces the plan and observations from an accepted journal.
	///
	/// The caller authenticates the journal prefix and compares the digest with its exact
	/// committed receipt record before treating the artifact as historical execution evidence.
	///
	/// # Errors
	/// Rejects any difference from the expected plan, exact frame reference, or observations.
	pub fn validate_evidence(
		&self,
		plan: &DarwinCopyPlan<'_>,
		frames: DarwinReceiptFrames<'_>,
	) -> Result<(), DarwinCopyReceiptError> {
		let expected = DarwinCopyReceipt::from_journal(plan, frames)?;
		if *self != expected {
			return Err(DarwinCopyReceiptError::BindingMismatch);
		}
		Ok(())
	}

	/// Returns the plan and native observations recorded by the receipt.
	#[must_use]
	pub const fn evidence(&self) -> DarwinCopyReceiptEvidence<'name> {
		self.evidence
	}

	/// Returns the exact synchronized kind-9 journal frame reference.
	#[must_use]
	pub const fn durability_frame(&self) -> ChainHead {
		self.durability_frame
	}

	fn from_journal(
		plan: &DarwinCopyPlan<'name>,
		frames: DarwinReceiptFrames<'_>,
	) -> Result<Self, DarwinCopyReceiptError> {
		let durability = DarwinDurabilityRecorded::from_frame(frames.durability)?;
		durability.validate_evidence(frames.metadata, frames.intent, frames.observed)?;
		let verification = DarwinVerificationRecorded::from_frame(frames.verification)?;
		let intent = DarwinPublishIntent::from_frame(frames.intent)?;
		let metadata = DarwinMetadataRecorded::from_frame(frames.metadata)?.metadata();
		let binding = durability.binding();
		let source = plan.source();
		let destination = plan.destination();
		let stream = verification.stage();
		let barriers = durability.barriers();
		if binding.context != plan.context()
			|| binding.entry != plan.attempt().entry
			|| verification.binding() != binding
			|| frames.verification.head().sequence() >= frames.metadata.head().sequence()
			|| verification.record_digest() != intent.verification_digest()
			|| verification.source().identity != source.file_identity
			|| stream.identity != intent.target().stage
			|| stream.identity.may_alias(source.root_identity)
			|| barriers.stage_directory.may_alias(source.root_identity)
			|| stream.length.get() != source.length
			|| barriers.destination_directory != destination.root_identity
			|| intent.target().component != destination.component
			|| !metadata_matches(plan, metadata)
		{
			return Err(DarwinCopyReceiptError::BindingMismatch);
		}
		Self::from_evidence(
			DarwinCopyReceiptEvidence {
				context: binding.context,
				entry: binding.entry,
				source: source.file_identity,
				destination,
				stream,
				metadata,
				stage_directory: barriers.stage_directory,
			},
			frames.durability.head(),
		)
	}

	fn from_evidence(
		evidence: DarwinCopyReceiptEvidence<'name>,
		durability_frame: ChainHead,
	) -> Result<Self, DarwinCopyReceiptError> {
		if durability_frame == ChainHead::start() {
			return Err(DarwinCopyReceiptError::InvalidDurabilityFrame);
		}
		let published = evidence.stream.identity;
		let stage = evidence.stage_directory;
		let destination = evidence.destination.root_identity;
		if published.volume() != stage.volume()
			|| published.volume() != destination.volume()
			|| published.may_alias(stage)
			|| published.may_alias(destination)
			|| stage.may_alias(destination)
			|| [published, stage, destination]
				.into_iter()
				.any(|identity| identity.may_alias(evidence.source))
		{
			return Err(DarwinCopyReceiptError::IdentityMismatch);
		}
		Ok(Self {
			evidence,
			durability_frame,
		})
	}
}

fn metadata_matches(plan: &DarwinCopyPlan<'_>, metadata: DarwinRequiredMetadata) -> bool {
	let source = plan.source().metadata;
	let permissions = metadata.permissions();
	permissions.mode() == u32::from(source.mode())
		&& permissions.owner() == source.uid()
		&& permissions.group() == source.gid()
		&& same_time(metadata.accessed_at, source.accessed_at())
		&& same_time(metadata.modified_at, source.modified_at())
}

fn same_time(owner: OwnerTimestamp, observed: ObservedTimestamp) -> bool {
	owner.seconds() == observed.seconds() && owner.nanoseconds() == observed.nanoseconds()
}
