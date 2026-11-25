use std::num::NonZeroU64;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::{
	JournalEntryId, JournalJobId, LinuxFileIdentity, OwnerDigest, StreamDigest, StreamLength,
};

use super::{RemoteDownloadError as Error, RemoteScopeDigest};

mod wire;

/// Maximum bounded payload size for one remote-download journal frame.
pub const MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES: usize = 768;
/// Largest source range represented by one prefix checkpoint.
pub const MAX_REMOTE_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
/// Largest checkpoint ordinal for a single private capture attempt.
pub const MAX_REMOTE_CHECKPOINTS: u16 = 4096;

const FILE_TYPE: u32 = 0o170000;
const REGULAR: u32 = 0o100000;
const PERMISSIONS: u32 = 0o7777;

/// Signed owner and single-entry context repeated by the private frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteDownloadContext {
	/// Exact signed owner envelope digest.
	pub owner: OwnerDigest,
	/// Durable job UUID.
	pub job: JournalJobId,
	/// Private entry UUID.
	pub entry: JournalEntryId,
}

/// Distinct nonzero job run and held live source-pass labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteEpochs {
	/// Job-local allocation generation.
	pub run: NonZeroU64,
	/// Source pass reserved for one open held remote handle.
	pub source: NonZeroU64,
}

/// The SFTP v3 regular file attributes observed at this pass's admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteSourceObservation {
	length: StreamLength,
	mode: u32,
	modified: u32,
}

impl RemoteSourceObservation {
	/// Records bounded server-reported extent, raw regular-file mode and seconds.
	/// # Errors
	/// Refuses unsupported mode bits and non-regular source attributes.
	pub fn new(length: StreamLength, mode: u32, modified: u32) -> Result<Self, Error> {
		if mode & FILE_TYPE != REGULAR || mode & !(FILE_TYPE | PERMISSIONS) != 0 {
			return Err(Error::Binding);
		}
		Ok(Self {
			length,
			mode,
			modified,
		})
	}

	/// Returns the observed logical extent.
	#[must_use]
	pub const fn length(self) -> StreamLength {
		self.length
	}

	/// Returns the observed raw SFTP v3 mode including the file type.
	#[must_use]
	pub const fn mode(self) -> u32 {
		self.mode
	}

	/// Returns the observed modification time at SFTP v3 resolution.
	#[must_use]
	pub const fn modified_seconds(self) -> u32 {
		self.modified
	}
}

/// A private boundary whose outcome needs later independent reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteUncertainBoundary {
	/// Exclusive stage creation or its outcome observation failed.
	Creation,
	/// Synchronization of the held stage failed or could not be confirmed.
	StageBarrier,
	/// Checkpoint append or its durability could not be confirmed.
	CheckpointAppend,
	/// Final source observation, EOF or closure could not be confirmed.
	TerminalSource,
}

/// Phase-specific contents of the bounded private remote-download profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteDownloadBody<'name> {
	/// Establishes the authenticated scope on the job's first frame.
	JobPrepared {
		/// Digest of the exact canonical remote scope.
		scope: RemoteScopeDigest,
	},
	/// Write-ahead authorization for one fresh private filename.
	StageAllocated {
		/// Last consumed allocation's labels, including abandoned allocations.
		previous: Option<RemoteEpochs>,
		/// Reserved labels for this exclusive creation and source pass.
		next: RemoteEpochs,
		/// Exact validated private basename.
		name: UnixComponent<'name>,
		/// Independently generated, nonzero stage nonce.
		nonce: [u8; 16],
		/// Fresh server-reported live observations of the held source.
		source: RemoteSourceObservation,
	},
	/// Physical stage binding after exclusive creation and directory synchronization.
	EntryPrepared {
		/// Exact preceding filename allocation.
		allocation: ChainHead,
		/// Reserved labels from that allocation.
		epochs: RemoteEpochs,
		/// Stage nonce from that allocation.
		nonce: [u8; 16],
		/// Held local private stage directory.
		stage_directory: LinuxFileIdentity,
		/// Independently observed local stage file.
		stage: LinuxFileIdentity,
	},
	/// Bounded inline digest evidence for one private contiguous source range.
	RangeCheckpoint {
		/// Exact physical binding of the stage and pass.
		prepared: ChainHead,
		/// The corresponding active run and held source epoch.
		epochs: RemoteEpochs,
		/// Nonzero checkpoint number within this attempt.
		ordinal: u16,
		/// Inclusive start offset in bytes.
		offset: u64,
		/// Positive covered length in bytes.
		length: u64,
		/// Ordinary BLAKE3 digest for the exact range.
		digest: StreamDigest,
	},
	/// Retains an unconfirmed boundary for read-only reconciliation.
	FailureRecorded {
		/// Related allocation or physical binding, selected by the boundary.
		attempt: ChainHead,
		/// The applicable run and source epoch.
		epochs: RemoteEpochs,
		/// The boundary that could not be confirmed.
		boundary: RemoteUncertainBoundary,
	},
}

impl RemoteDownloadBody<'_> {
	/// Returns the exact outer journal frame kind for these fields.
	#[must_use]
	pub const fn kind(&self) -> FrameKind {
		match self {
			Self::JobPrepared { .. } => FrameKind::JobPrepared,
			Self::StageAllocated { .. } => FrameKind::RemoteStageAllocated,
			Self::EntryPrepared { .. } => FrameKind::EntryPrepared,
			Self::RangeCheckpoint { .. } => FrameKind::RangeCheckpoint,
			Self::FailureRecorded { .. } => FrameKind::FailureRecorded,
		}
	}
}

/// A canonical remote-download assertion, with structural frame links.
///
/// Full replay verifies authenticated scope and earlier active frame identities.
/// This value does not establish completion, durability, or publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteDownloadRecord<'name> {
	context: RemoteDownloadContext,
	predecessor: Option<ChainHead>,
	body: RemoteDownloadBody<'name>,
}

impl<'name> RemoteDownloadRecord<'name> {
	/// Constructs a bounded declaration with the appropriate predecessor shape.
	/// # Errors
	/// Refuses invalid identifiers, attempts, stage identities and range geometry.
	pub fn new(
		context: RemoteDownloadContext,
		predecessor: Option<ChainHead>,
		body: RemoteDownloadBody<'name>,
	) -> Result<Self, Error> {
		if context.owner.as_bytes() == &[0; 32] || context.entry.as_bytes() == &[0; 16] {
			return Err(Error::Binding);
		}
		match (predecessor, body) {
			(None, RemoteDownloadBody::JobPrepared { .. }) => {}
			(Some(head), record)
				if head != ChainHead::start() && head.sequence().checked_add(1).is_some() =>
			{
				validate_body(head, record)?;
			}
			_ => return Err(Error::FrameBinding),
		}
		Ok(Self {
			context,
			predecessor,
			body,
		})
	}

	/// Encodes this canonical assertion into one bounded frame payload.
	/// # Errors
	/// Refuses an unsupported encoding length.
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		wire::encode(self)
	}

	/// Decodes an exact canonical payload without establishing frame provenance.
	/// # Errors
	/// Refuses malformed, oversized or unsupported payloads and fields.
	pub fn decode(bytes: &'name [u8]) -> Result<Self, Error> {
		wire::decode(bytes)
	}

	/// Decodes and checks the enclosing kind, exact predecessor digest and sequence.
	/// # Errors
	/// Refuses a foreign, malformed or incorrectly linked frame.
	pub fn from_frame(frame: &'name Frame) -> Result<Self, Error> {
		let record = Self::decode(frame.payload())?;
		let predecessor = record.predecessor.unwrap_or_else(ChainHead::start);
		if record.body.kind() != frame.kind()
			|| predecessor.sequence().checked_add(1) != Some(frame.head().sequence())
			|| predecessor.digest() != frame.previous_digest()
		{
			return Err(Error::FrameBinding);
		}
		Ok(record)
	}

	/// Returns the declared context.
	#[must_use]
	pub const fn context(&self) -> RemoteDownloadContext {
		self.context
	}

	/// Returns the declared immediate predecessor, absent for the first frame.
	#[must_use]
	pub const fn predecessor(&self) -> Option<ChainHead> {
		self.predecessor
	}

	/// Returns the bounded phase fields.
	#[must_use]
	pub const fn body(&self) -> RemoteDownloadBody<'name> {
		self.body
	}
}

fn validate_body(head: ChainHead, body: RemoteDownloadBody<'_>) -> Result<(), Error> {
	match body {
		RemoteDownloadBody::JobPrepared { .. } => Err(Error::FrameBinding),
		RemoteDownloadBody::StageAllocated {
			previous,
			next,
			nonce,
			..
		} => {
			let valid_epochs = match previous {
				None => next.run.get() == 1,
				Some(prior) => {
					prior.run.get().checked_add(1) == Some(next.run.get())
						&& next.source > prior.source
				}
			};
			(valid_epochs && nonce != [0; 16])
				.then_some(())
				.ok_or(Error::Binding)
		}
		RemoteDownloadBody::EntryPrepared {
			allocation,
			nonce,
			stage_directory,
			stage,
			..
		} => {
			if allocation != head {
				return Err(Error::FrameBinding);
			}
			(nonce != [0; 16]
				&& stage_directory != stage
				&& stage_directory.device() == stage.device())
			.then_some(())
			.ok_or(Error::Binding)
		}
		RemoteDownloadBody::RangeCheckpoint {
			prepared,
			ordinal,
			offset,
			length,
			..
		} => {
			check_reference(head, prepared)?;
			((1..=MAX_REMOTE_CHECKPOINTS).contains(&ordinal)
				&& (1..=MAX_REMOTE_CHECKPOINT_BYTES).contains(&length)
				&& (ordinal == 1) == (offset == 0)
				&& offset
					.checked_add(length)
					.is_some_and(|end| end <= MAX_FILE_LENGTH))
			.then_some(())
			.ok_or(Error::Binding)
		}
		RemoteDownloadBody::FailureRecorded { attempt, .. } => check_reference(head, attempt),
	}
}

fn check_reference(head: ChainHead, reference: ChainHead) -> Result<(), Error> {
	(reference != ChainHead::start()
		&& (reference == head || reference.sequence() < head.sequence()))
	.then_some(())
	.ok_or(Error::FrameBinding)
}
