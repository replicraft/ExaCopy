use std::io;

use exacopy_endpoint::JournalFileBarrier;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::SyncedFrame;
use crate::frame::{ChainHead, Frame, FrameKind, FrameWriter};
use crate::owner::codec::encoded_bytes;

use super::super::finalization_policy::{SftpDataOnlyV1, SftpOmission};
use super::super::wire::{
	array, fixed, key, map, read_head, read_version, write_head, write_version,
};
use super::super::{
	RemoteDownloadBody, RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteScopeDigest,
};
use super::wire::{VERSION, read_omissions, write_omissions};
use super::{
	Error, RemoteFinalizationBinding, RemoteFinalizationBody as Body, RemoteFinalizationRecord,
	RemotePublicationObservation,
};

const DOMAIN: &[u8] = b"ExaCopy/linux-remote-download-receipt/v1\0";
const PUBLISHED_WITH_OMISSIONS: u8 = 2;
const PHASES: usize = 6;
const KINDS: [FrameKind; PHASES] = [
	FrameKind::StageSealed,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::PublishIntent,
	FrameKind::PublishObserved,
	FrameKind::DurabilityRecorded,
];

/// Maximum bytes of one canonical private remote-download receipt.
pub const MAX_REMOTE_RECEIPT_BYTES: usize = 5_120;

type Buffer = Cursor<[u8; MAX_REMOTE_RECEIPT_BYTES]>;

/// Domain-specific digest of the complete canonical remote-download receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteReceiptDigest([u8; 32]);

impl RemoteReceiptDigest {
	/// Wraps the exact digest bytes from a receipt commitment.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the exact digest byte representation.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Exact completion frames selected from the authoritative held journal.
#[derive(Clone, Copy, Debug)]
pub struct RemoteReceiptFrames<'history> {
	/// Exact consumed allocation containing the live source observation.
	pub allocation: &'history Frame,
	/// Exact physical stage binding for this allocation.
	pub prepared: &'history Frame,
	/// Closed stage and data barrier.
	pub seal: &'history Frame,
	/// Independent read-back.
	pub verification: &'history Frame,
	/// Observed policy compliance.
	pub metadata: &'history Frame,
	/// Synchronized exclusive intent.
	pub intent: &'history Frame,
	/// Confirmed publication of the intended inode.
	pub observed: &'history Frame,
	/// File and namespace durability barriers.
	pub durability: &'history Frame,
}

impl<'history> RemoteReceiptFrames<'history> {
	const fn ordered(self) -> [&'history Frame; PHASES] {
		[
			self.seal,
			self.verification,
			self.metadata,
			self.intent,
			self.observed,
			self.durability,
		]
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordedPhase<'history> {
	head: ChainHead,
	record: RemoteFinalizationRecord<'history>,
}

/// Completion claim represented by a remote-download receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteReceiptOutcome {
	/// The selected unnamed stream was published with the policy's explicit omissions.
	PublishedWithOmissions,
}

/// Canonical receipt for a published SFTP unnamed stream with explicit omissions.
///
/// It embeds the exact finalization declarations and heads. A decoded artifact
/// is historical recorded evidence that must match the selected owner, journal,
/// physical observations and commitment before it supports an execution claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteDownloadReceipt<'history> {
	scope: RemoteScopeDigest,
	allocation: ChainHead,
	phases: [RecordedPhase<'history>; PHASES],
}

impl<'history> RemoteDownloadReceipt<'history> {
	/// Reconstructs a receipt candidate from selected owner and finalization frames.
	///
	/// Supply all selected frames from one validated held journal prefix.
	/// The caller must verify the bootstrap, qualification and any intervening
	/// checkpoint chain between preparation and sealing.
	///
	/// # Errors
	/// Refuses incompatible bindings, heads, outcome, policy or selected scope.
	pub fn from_frames(
		owner: &RemoteDownloadOwnerRecord,
		frames: RemoteReceiptFrames<'history>,
	) -> Result<Self, Error> {
		let first = decode_frame(frames.seal)?;
		let mut phases = [first; PHASES];
		for (phase, frame) in phases[1..].iter_mut().zip(frames.ordered()[1..].iter()) {
			*phase = decode_frame(frame)?;
		}
		let receipt = Self {
			scope: owner.manifest().scope.digest()?,
			allocation: frames.allocation.head(),
			phases,
		};
		receipt.validate()?;
		receipt.validate_owner(owner)?;
		receipt.validate_preparation(frames.allocation, frames.prepared)?;
		Ok(receipt)
	}

	/// Constructs a receipt after the matching Linux journal file barrier.
	///
	/// The frame selection must satisfy the same prefix requirements as
	/// [Self::from_frames].
	///
	/// # Errors
	/// Refuses a mismatched frame/barrier or inconsistent owner and history.
	pub fn from_synced_durability(
		owner: &RemoteDownloadOwnerRecord,
		frames: RemoteReceiptFrames<'history>,
		synced: &SyncedFrame,
	) -> Result<Self, Error> {
		if synced.kind() != FrameKind::DurabilityRecorded
			|| synced.head() != frames.durability.head()
			|| synced.barrier() != JournalFileBarrier::SyncAll
		{
			return Err(Error::FrameBinding);
		}
		Self::from_frames(owner, frames)
	}

	/// Returns the independently selected owner scope digest.
	#[must_use]
	pub const fn scope(&self) -> RemoteScopeDigest {
		self.scope
	}

	/// Returns the exact owner, entry and native stage binding.
	#[must_use]
	pub const fn binding(&self) -> RemoteFinalizationBinding {
		self.phases[0].record.binding()
	}

	/// Returns the exact consumed allocation associated with this receipt.
	#[must_use]
	pub const fn allocation(&self) -> ChainHead {
		self.allocation
	}

	/// Returns the exact intended durability frame.
	#[must_use]
	pub const fn durability(&self) -> ChainHead {
		self.phases[PHASES - 1].head
	}

	/// Returns the non-clean result for the explicitly selected SFTP stream.
	#[must_use]
	pub const fn outcome(&self) -> RemoteReceiptOutcome {
		RemoteReceiptOutcome::PublishedWithOmissions
	}

	/// Returns the fixed waiver codes for reporting this non-clean result.
	#[must_use]
	pub const fn omissions(&self) -> &'static [SftpOmission] {
		SftpDataOnlyV1::omissions()
	}

	/// Returns the recorded phase heads and declarations in completion order.
	pub fn records(
		&self,
	) -> impl ExactSizeIterator<Item = (ChainHead, RemoteFinalizationRecord<'history>)> + '_ {
		self.phases.iter().map(|phase| (phase.head, phase.record))
	}

	/// Encodes this receipt in its exact bounded canonical representation.
	///
	/// # Errors
	/// Refuses an unsupported encoding length.
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		Ok(encoded_bytes(&self.encode_into()?).to_vec())
	}

	/// Computes the receipt commitment domain over the complete canonical artifact.
	///
	/// # Errors
	/// Refuses an unsupported encoding length.
	pub fn digest(&self) -> Result<RemoteReceiptDigest, Error> {
		let bytes = self.encode_into()?;
		Ok(RemoteReceiptDigest::from_bytes(
			*blake3::Hasher::new()
				.update(DOMAIN)
				.update(encoded_bytes(&bytes))
				.finalize()
				.as_bytes(),
		))
	}

	/// Rejects incompatible canonical bytes or inconsistent internal declarations.
	///
	/// # Errors
	/// Refuses unsupported format, size, phases, links and metadata policy.
	pub fn decode(bytes: &'history [u8]) -> Result<Self, Error> {
		if bytes.len() > MAX_REMOTE_RECEIPT_BYTES {
			return Err(Error::Length);
		}
		let mut decoder = Decoder::new(bytes);
		map(&mut decoder, 7)?;
		key(&mut decoder, 0)?;
		read_version(&mut decoder, VERSION)?;
		key(&mut decoder, 1)?;
		let scope = RemoteScopeDigest::from_bytes(fixed(&mut decoder)?);
		key(&mut decoder, 2)?;
		array(&mut decoder, 6)?;
		let first = decode_phase(&mut decoder)?;
		let mut phases = [first; PHASES];
		for phase in &mut phases[1..] {
			*phase = decode_phase(&mut decoder)?;
		}
		key(&mut decoder, 3)?;
		if fixed::<32>(&mut decoder)? != SftpDataOnlyV1::digest() {
			return Err(Error::Binding);
		}
		key(&mut decoder, 4)?;
		read_omissions(&mut decoder)?;
		key(&mut decoder, 5)?;
		key(&mut decoder, PUBLISHED_WITH_OMISSIONS)?;
		key(&mut decoder, 6)?;
		let allocation = read_head(&mut decoder)?;
		let receipt = Self {
			scope,
			allocation,
			phases,
		};
		receipt.validate()?;
		if encoded_bytes(&receipt.encode_into()?) != bytes {
			return Err(Error::NonCanonical);
		}
		Ok(receipt)
	}

	/// Checks exact equality to the selected authoritative history and commitment.
	///
	/// Use the prefix validated for [Self::from_frames] and its exact commit.
	///
	/// # Errors
	/// Refuses a foreign owner, historic substitution, or different artifact digest.
	pub fn validate_evidence(
		&self,
		owner: &RemoteDownloadOwnerRecord,
		frames: RemoteReceiptFrames<'_>,
		commitment: &Frame,
	) -> Result<(), Error> {
		let expected = RemoteDownloadReceipt::from_frames(owner, frames)?;
		if *self != expected {
			return Err(Error::Binding);
		}
		let commitment = RemoteFinalizationRecord::from_frame(commitment)?;
		if commitment.binding() != self.binding()
			|| commitment.predecessor() != self.durability()
			|| commitment.body()
				!= (Body::ReceiptCommitted {
					digest: self.digest()?,
				}) {
			return Err(Error::FrameBinding);
		}
		Ok(())
	}

	fn encode_into(&self) -> Result<Buffer, Error> {
		let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_RECEIPT_BYTES]));
		out.map(7)?.u8(0)?;
		write_version(&mut out, VERSION)?;
		out.u8(1)?.bytes(self.scope.as_bytes())?.u8(2)?.array(6)?;
		for phase in &self.phases {
			out.array(2)?;
			write_head(&mut out, phase.head)?;
			out.bytes(&phase.record.encode()?)?;
		}
		out.u8(3)?.bytes(&SftpDataOnlyV1::digest())?.u8(4)?;
		write_omissions(&mut out)?;
		out.u8(5)?.u8(PUBLISHED_WITH_OMISSIONS)?.u8(6)?;
		write_head(&mut out, self.allocation)?;
		Ok(out.into_writer())
	}

	fn validate(&self) -> Result<(), Error> {
		if self.scope.as_bytes() == &[0; 32] {
			return Err(Error::Binding);
		}
		if self.allocation.sequence().checked_add(1) != Some(self.binding().prepared.sequence()) {
			return Err(Error::FrameBinding);
		}
		let mut framing = FrameWriter::new(io::sink(), self.phases[0].record.predecessor());
		for (phase, kind) in self.phases.iter().zip(KINDS) {
			if phase.record.binding() != self.binding()
				|| phase.record.body().kind() != kind
				|| phase.record.predecessor() != framing.head()
				|| framing
					.append(kind, &phase.record.encode()?)
					.map_err(|_| Error::FrameBinding)?
					!= phase.head
			{
				return Err(Error::FrameBinding);
			}
		}
		self.validate_outcome()
	}

	fn validate_outcome(&self) -> Result<(), Error> {
		let [seal, verification, metadata, intent, observed, durable] = self.phases;
		let Body::StageSealed { directory, length } = seal.record.body() else {
			return Err(Error::FrameBinding);
		};
		let Body::VerificationRecorded {
			length: verified_length,
			..
		} = verification.record.body()
		else {
			return Err(Error::FrameBinding);
		};
		let Body::PublishIntent {
			seal: expected_seal,
			verification: expected_verification,
			directory: intent_directory,
			target,
			qualification,
		} = intent.record.body()
		else {
			return Err(Error::FrameBinding);
		};
		let Body::DurabilityRecorded {
			metadata: expected_metadata,
			directory: durable_directory,
			parent,
			qualification: durable_qualification,
		} = durable.record.body()
		else {
			return Err(Error::FrameBinding);
		};
		if expected_seal != seal.head
			|| expected_verification != verification.head
			|| expected_metadata != metadata.head
		{
			return Err(Error::FrameBinding);
		}
		if verified_length != length
			|| intent_directory != directory
			|| durable_directory != directory
			|| target.parent != parent
			|| qualification != durable_qualification
			|| observed.record.body()
				!= Body::PublishObserved(RemotePublicationObservation::Published(
					self.binding().stage,
				)) {
			return Err(Error::Binding);
		}
		Ok(())
	}

	fn validate_preparation(&self, allocation: &Frame, prepared: &Frame) -> Result<(), Error> {
		let binding = self.binding();
		if allocation.head() != self.allocation || prepared.head() != binding.prepared {
			return Err(Error::FrameBinding);
		}
		let allocated = RemoteDownloadRecord::from_frame(allocation)?;
		let prepared = RemoteDownloadRecord::from_frame(prepared)?;
		let RemoteDownloadBody::StageAllocated {
			next,
			nonce,
			source,
			..
		} = allocated.body()
		else {
			return Err(Error::FrameBinding);
		};
		let RemoteDownloadBody::EntryPrepared {
			allocation,
			epochs,
			nonce: prepared_nonce,
			stage_directory,
			stage,
		} = prepared.body()
		else {
			return Err(Error::FrameBinding);
		};
		let Body::StageSealed { directory, length } = self.phases[0].record.body() else {
			return Err(Error::FrameBinding);
		};
		if prepared.predecessor() != Some(self.allocation) || allocation != self.allocation {
			return Err(Error::FrameBinding);
		}
		if allocated.context() != binding.context
			|| prepared.context() != binding.context
			|| next != binding.epochs
			|| epochs != binding.epochs
			|| nonce != prepared_nonce
			|| stage != binding.stage
			|| directory != stage_directory
			|| length != source.length()
		{
			return Err(Error::Binding);
		}
		Ok(())
	}

	fn validate_owner(&self, owner: &RemoteDownloadOwnerRecord) -> Result<(), Error> {
		let manifest = owner.manifest();
		let scope = &manifest.scope;
		let [seal, _, _, intent, _, _] = self.phases;
		let binding = self.binding();
		let Body::StageSealed { directory, length } = seal.record.body() else {
			return Err(Error::FrameBinding);
		};
		let Body::PublishIntent { target, .. } = intent.record.body() else {
			return Err(Error::FrameBinding);
		};
		if owner.digest() != binding.context.owner
			|| manifest.job != binding.context.job
			|| scope.entry != binding.context.entry
			|| scope.metadata_policy != SftpDataOnlyV1::digest()
			|| scope.destination.root() != target.root
			|| scope.destination.parent() != target.parent
			|| scope.destination.target() != target.component.as_bytes()
			|| [binding.stage, directory].contains(&manifest.job_directory)
			|| length.get() > scope.maximum_extent.get()
		{
			return Err(Error::Binding);
		}
		Ok(())
	}
}

fn decode_frame(frame: &Frame) -> Result<RecordedPhase<'_>, Error> {
	Ok(RecordedPhase {
		head: frame.head(),
		record: RemoteFinalizationRecord::from_frame(frame)?,
	})
}

fn decode_phase<'history>(
	decoder: &mut Decoder<'history>,
) -> Result<RecordedPhase<'history>, Error> {
	array(decoder, 2)?;
	let head = read_head(decoder)?;
	let record = RemoteFinalizationRecord::decode(decoder.bytes()?)?;
	Ok(RecordedPhase { head, record })
}
