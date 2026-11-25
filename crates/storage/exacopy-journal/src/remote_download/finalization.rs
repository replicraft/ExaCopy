//! Bounded remote publication declarations for the explicit SFTP data policy.

use exacopy_endpoint::UnixComponent;

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::{
	LinuxFileIdentity, NamespaceObservation, RootCapabilityId, StreamDigest, StreamLength,
};

use super::{RemoteDownloadContext, RemoteDownloadError as Error, RemoteEpochs};

mod receipt;
mod wire;

pub use receipt::{
	MAX_REMOTE_RECEIPT_BYTES, RemoteDownloadReceipt, RemoteReceiptDigest, RemoteReceiptFrames,
	RemoteReceiptOutcome,
};

/// Maximum canonical bytes of any remote finalization payload.
pub const MAX_REMOTE_FINALIZATION_BYTES: usize = 768;

/// Exact capture attempt identified by the authenticated owner and prepared frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteFinalizationBinding {
	/// Owner, job and entry from the admitted remote profile.
	pub context: RemoteDownloadContext,
	/// Exact prepared frame resolving the allocation and native stage.
	pub prepared: ChainHead,
	/// Run and source pass carried by that preparation.
	pub epochs: RemoteEpochs,
	/// Actual native private file.
	pub stage: LinuxFileIdentity,
}

/// Checked local metadata of the data-only stage.
///
/// The selected profile fixes mode 0600, empty visible attributes and ACLs, and a
/// full file barrier. These values describe the checked local UID and GID only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteLocalMetadata {
	/// Effective local owner observed on the held stage.
	pub uid: u32,
	/// Local group admitted by the destination directory policy.
	pub gid: u32,
}

/// Exact authorized create-new location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePublishTarget<'name> {
	/// Destination capability selected by the signed scope.
	pub root: RootCapabilityId,
	/// Local native destination directory identity.
	pub parent: LinuxFileIdentity,
	/// Raw authorized target basename.
	pub component: UnixComponent<'name>,
}

/// Local publication observations of a single approved attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemotePublicationObservation {
	/// The exact target inode was observed and the former private name was absent.
	Published(LinuxFileIdentity),
	/// The exclusive rename refused an incumbent.
	Conflict,
	/// The native result requires read-only reconciliation.
	Uncertain {
		/// Target name observation, if established.
		target: NamespaceObservation,
		/// Former private stage name observation, if established.
		stage: NamespaceObservation,
	},
}

/// Phase-specific assertions for the remote finalization profile.
///
/// References are validated structurally here. A replay or live coordinator
/// separately proves that the precise original record and native effect exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteFinalizationBody<'name> {
	/// Full file barrier and writer closure after complete capture.
	StageSealed {
		/// Private directory holding the observed stage.
		directory: LinuxFileIdentity,
		/// Exact extent of this closed stage.
		length: StreamLength,
	},
	/// Matching whole-stream measurements, with both EOFs and terminal source closure.
	VerificationRecorded {
		/// Exact matched logical extent.
		length: StreamLength,
		/// Ordinary BLAKE3 digest measured on the held SFTP pass.
		source: StreamDigest,
		/// Ordinary BLAKE3 digest from independent local buffered read-back.
		stage: StreamDigest,
	},
	/// Required local policy checks and completed full stage file barrier.
	MetadataRecorded(RemoteLocalMetadata),
	/// Synchronize this declaration before consuming the exclusive publication permit.
	PublishIntent {
		/// Exact earlier seal.
		seal: ChainHead,
		/// Exact independently measured verification frame.
		verification: ChainHead,
		/// Native private staging directory identity.
		directory: LinuxFileIdentity,
		/// Exact authorized create-new target.
		target: RemotePublishTarget<'name>,
		/// Separately admitted native destination qualification record digest.
		qualification: [u8; 32],
	},
	/// Observation for the exact immediately preceding intent.
	PublishObserved(RemotePublicationObservation),
	/// Finished full stage file and both affected directory barriers.
	DurabilityRecorded {
		/// Exact earlier metadata frame.
		metadata: ChainHead,
		/// Native private staging directory identity.
		directory: LinuxFileIdentity,
		/// Native destination directory identity.
		parent: LinuxFileIdentity,
		/// Exact process-crash qualification digest in the intent.
		qualification: [u8; 32],
	},
	/// Committed receipt artifact after its file and namespace barriers.
	ReceiptCommitted {
		/// Domain-separated digest over canonical remote receipt bytes.
		digest: RemoteReceiptDigest,
	},
}

impl RemoteFinalizationBody<'_> {
	/// Returns the exact outer frame kind.
	#[must_use]
	pub const fn kind(self) -> FrameKind {
		match self {
			Self::StageSealed { .. } => FrameKind::StageSealed,
			Self::VerificationRecorded { .. } => FrameKind::VerificationRecorded,
			Self::MetadataRecorded(_) => FrameKind::MetadataRecorded,
			Self::PublishIntent { .. } => FrameKind::PublishIntent,
			Self::PublishObserved(_) => FrameKind::PublishObserved,
			Self::DurabilityRecorded { .. } => FrameKind::DurabilityRecorded,
			Self::ReceiptCommitted { .. } => FrameKind::ReceiptCommitted,
		}
	}
}

/// A structurally checked finalization declaration. Decoding supplies no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteFinalizationRecord<'name> {
	binding: RemoteFinalizationBinding,
	predecessor: ChainHead,
	body: RemoteFinalizationBody<'name>,
}

impl<'name> RemoteFinalizationRecord<'name> {
	/// Builds a bounded declaration with nonzero scope and checked phase references.
	///
	/// # Errors
	/// Refuses invalid identities, measurements or structurally inconsistent links.
	pub fn new(
		binding: RemoteFinalizationBinding,
		predecessor: ChainHead,
		body: RemoteFinalizationBody<'name>,
	) -> Result<Self, Error> {
		binding.validate()?;
		if predecessor.sequence() < binding.prepared.sequence()
			|| predecessor.sequence().checked_add(1).is_none()
			|| (predecessor.sequence() == binding.prepared.sequence()
				&& (predecessor != binding.prepared
					|| !matches!(body, RemoteFinalizationBody::StageSealed { .. })))
		{
			return Err(Error::FrameBinding);
		}
		body.validate(binding.stage, binding.prepared, predecessor)?;
		Ok(Self {
			binding,
			predecessor,
			body,
		})
	}

	/// Returns the exact prepared attempt binding.
	#[must_use]
	pub const fn binding(&self) -> RemoteFinalizationBinding {
		self.binding
	}

	/// Returns the declared immediate predecessor.
	#[must_use]
	pub const fn predecessor(&self) -> ChainHead {
		self.predecessor
	}

	/// Returns the bounded phase declaration.
	#[must_use]
	pub const fn body(&self) -> RemoteFinalizationBody<'name> {
		self.body
	}

	/// Encodes a canonical bounded payload.
	///
	/// # Errors
	/// Refuses an unsupported encoding length.
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		wire::encode(self)
	}

	/// Decodes one canonical bounded payload.
	///
	/// # Errors
	/// Refuses unsupported versions and fields or any noncanonical bytes.
	pub fn decode(bytes: &'name [u8]) -> Result<Self, Error> {
		wire::decode(bytes)
	}

	/// Checks a framed declaration's kind and exact immediate predecessor.
	///
	/// # Errors
	/// Refuses a framing mismatch or malformed payload.
	pub fn from_frame(frame: &'name Frame) -> Result<Self, Error> {
		let record = Self::decode(frame.payload())?;
		if record.body.kind() != frame.kind()
			|| record.predecessor.sequence().checked_add(1) != Some(frame.head().sequence())
			|| record.predecessor.digest() != frame.previous_digest()
		{
			return Err(Error::FrameBinding);
		}
		Ok(record)
	}
}

impl RemoteFinalizationBinding {
	fn validate(self) -> Result<(), Error> {
		if self.context.owner.as_bytes() == &[0; 32]
			|| self.context.entry.as_bytes() == &[0; 16]
			|| self.prepared.sequence() == 0
		{
			return Err(Error::Binding);
		}
		Ok(())
	}
}

impl RemoteFinalizationBody<'_> {
	fn validate(
		self,
		stage: LinuxFileIdentity,
		prepared: ChainHead,
		prior: ChainHead,
	) -> Result<(), Error> {
		use RemoteFinalizationBody as Body;

		let valid = match self {
			Body::StageSealed { directory, .. } => same_device_distinct(stage, directory),
			Body::VerificationRecorded { source, stage, .. } => source == stage,
			Body::MetadataRecorded(_) => true,
			Body::PublishIntent {
				seal,
				verification,
				directory,
				target,
				qualification,
			} => {
				if prepared.sequence() >= seal.sequence()
					|| seal.sequence().checked_add(1) != Some(verification.sequence())
					|| verification.sequence().checked_add(1) != Some(prior.sequence())
				{
					return Err(Error::FrameBinding);
				}
				valid_names(stage, directory, target.parent) && qualification != [0; 32]
			}
			Body::PublishObserved(RemotePublicationObservation::Published(target)) => {
				target == stage
			}
			Body::PublishObserved(_) => true,
			Body::DurabilityRecorded {
				metadata,
				directory,
				parent,
				qualification,
			} => {
				if metadata.sequence() <= prepared.sequence()
					|| metadata.sequence().checked_add(2) != Some(prior.sequence())
				{
					return Err(Error::FrameBinding);
				}
				valid_names(stage, directory, parent) && qualification != [0; 32]
			}
			Body::ReceiptCommitted { digest } => digest.as_bytes() != &[0; 32],
		};
		valid.then_some(()).ok_or(Error::Binding)
	}
}

fn same_device_distinct(first: LinuxFileIdentity, second: LinuxFileIdentity) -> bool {
	first.device() == second.device() && first != second
}

fn valid_names(
	stage: LinuxFileIdentity,
	directory: LinuxFileIdentity,
	parent: LinuxFileIdentity,
) -> bool {
	same_device_distinct(stage, directory)
		&& same_device_distinct(stage, parent)
		&& directory != parent
}
