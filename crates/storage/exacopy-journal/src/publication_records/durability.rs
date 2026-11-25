use minicbor::Decoder;

use super::codec::{
	Writer, decode_frame, decode_record, encode_record, encoded_bytes, read_reference,
	require_before, require_reference, write_reference,
};
use super::{PublicationOutcome, PublicationRecordError, PublishObserved};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_identity, write_identity};
use crate::{LinuxFileIdentity, MetadataRecorded, PublishIntentContext};

const CROSS_DIRECTORY_LINUX_RENAME_NO_REPLACE: u64 = 1;
const DURABILITY_UNCONFIRMED: u64 = 0;

/// The local barrier evidence for a cross-directory exclusive Linux rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxPublicationBarriers {
	/// Exact kind-6 frame describing the pre-rename full stage-file barrier.
	pub metadata: ChainHead,
	/// The original stage name's parent, successfully synchronized after rename.
	pub stage_directory: LinuxFileIdentity,
	/// The destination name's parent, successfully synchronized after rename.
	pub destination_directory: LinuxFileIdentity,
}

/// A kind-9 record for the local Linux profile after both namespace barriers succeed.
///
/// The local scope records completed file and directory sync calls with achieved
/// durability level `unconfirmed`. The calls alone carry no crash qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurabilityRecorded {
	context: PublishIntentContext,
	observed: ChainHead,
	barriers: LinuxPublicationBarriers,
}

impl DurabilityRecorded {
	/// Constructs evidence describing a successful pair of directory synchronizations.
	///
	/// # Errors
	///
	/// Rejects initial chain anchors, unordered references, and directories that
	/// alias or reside on different devices.
	pub fn new(
		context: PublishIntentContext,
		observed: ChainHead,
		barriers: LinuxPublicationBarriers,
	) -> Result<Self, PublicationRecordError> {
		require_reference(observed)?;
		require_reference(barriers.metadata)?;
		require_before(barriers.metadata, observed)?;
		if barriers.stage_directory == barriers.destination_directory
			|| barriers.stage_directory.device() != barriers.destination_directory.device()
		{
			return Err(PublicationRecordError::InvalidBarrierScope);
		}
		Ok(Self {
			context,
			observed,
			barriers,
		})
	}

	/// Returns the publication effect's context.
	#[must_use]
	pub const fn context(&self) -> PublishIntentContext {
		self.context
	}

	/// Returns the exact kind-8 observation reference.
	#[must_use]
	pub const fn observed(&self) -> ChainHead {
		self.observed
	}

	/// Returns the recorded file barrier reference and directory barrier identities.
	#[must_use]
	pub const fn barriers(&self) -> LinuxPublicationBarriers {
		self.barriers
	}

	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encoded_bytes(&self.encode_bounded()).to_vec()
	}

	/// Decodes a complete canonical kind-9 payload.
	///
	/// # Errors
	///
	/// Rejects malformed or unsupported evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, PublicationRecordError> {
		decode_record(payload, Self::read_body, Self::encode_bounded)
	}

	/// Decodes the frame and checks that the referenced evidence precedes it.
	///
	/// # Errors
	///
	/// Rejects a wrong kind, malformed payload or out-of-order reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, PublicationRecordError> {
		decode_frame(
			frame,
			FrameKind::DurabilityRecorded,
			Self::decode,
			Self::observed,
		)
	}

	/// Checks the referenced frames from the verified chain for matching publication evidence.
	///
	/// The caller also binds the stage directory identity to the job's trusted stage directory.
	///
	/// # Errors
	///
	/// Rejects unordered or incorrect references, mismatched context or local identities,
	/// and any observation without successful publication.
	pub fn validate_evidence(
		&self,
		metadata_frame: &Frame,
		intent_frame: &Frame,
		observed_frame: &Frame,
	) -> Result<(), PublicationRecordError> {
		if self.barriers.metadata != metadata_frame.head() || self.observed != observed_frame.head()
		{
			return Err(PublicationRecordError::BindingMismatch);
		}
		require_before(metadata_frame.head(), intent_frame.head())?;
		let observed = PublishObserved::from_frame(observed_frame)?;
		let intent = observed.bound_intent(intent_frame)?;
		let PublicationOutcome::Published { target } = observed.outcome() else {
			return Err(PublicationRecordError::InconsistentObservation);
		};
		let metadata = MetadataRecorded::from_frame(metadata_frame)
			.map_err(PublicationRecordError::Metadata)?;
		if observed.context() != self.context
			|| metadata.context.job != self.context.job
			|| metadata.context.epoch != self.context.epoch
			|| metadata.context.plan_digest != self.context.plan_digest
			|| metadata.entry != self.context.entry
			|| metadata.stage != target
			|| self.barriers.destination_directory != intent.target.parent
		{
			return Err(PublicationRecordError::BindingMismatch);
		}
		if target.device() != self.barriers.destination_directory.device()
			|| target == self.barriers.stage_directory
			|| target == self.barriers.destination_directory
		{
			return Err(PublicationRecordError::InvalidBarrierScope);
		}
		Ok(())
	}

	fn encode_bounded(&self) -> Writer {
		encode_record(&self.context, |encoder| {
			encoder
				.map(3)?
				.u8(0)?
				.u64(CROSS_DIRECTORY_LINUX_RENAME_NO_REPLACE)?
				.u8(1)?
				.map(4)?
				.u8(0)?;
			write_reference(encoder, self.observed)?;
			encoder.u8(1)?;
			write_reference(encoder, self.barriers.metadata)?;
			encoder.u8(2)?;
			write_identity(encoder, self.barriers.stage_directory)?;
			encoder.u8(3)?;
			write_identity(encoder, self.barriers.destination_directory)?;
			encoder.u8(2)?.u64(DURABILITY_UNCONFIRMED)?;
			Ok(())
		})
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: PublishIntentContext,
	) -> Result<Self, PublicationRecordError> {
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		if decoder.u64()? != CROSS_DIRECTORY_LINUX_RENAME_NO_REPLACE {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 1)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let observed = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let metadata = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		let destination_directory = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		if decoder.u64()? != DURABILITY_UNCONFIRMED {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		Self::new(
			context,
			observed,
			LinuxPublicationBarriers {
				metadata,
				stage_directory,
				destination_directory,
			},
		)
	}
}
