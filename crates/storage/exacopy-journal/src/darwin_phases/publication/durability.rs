use core::num::NonZeroU64;

use minicbor::Decoder;

use super::DarwinPublishObserved;
use super::binding::{ActiveIntent, read_reference, require_before, write_reference};
use crate::DarwinFileIdentity;
use crate::darwin_phases::codec::{decode_record, encode_record, expect_code, frame_payload};
use crate::darwin_phases::{DarwinMetadataRecorded, DarwinPhaseBinding, DarwinPhaseError};
use crate::darwin_prepared::wire::{read_identity, write_identity};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map};

const KIND: FrameKind = FrameKind::DurabilityRecorded;
const CROSS_DIRECTORY_DARWIN_RENAME_EXCL: u64 = 2;
const DARWIN_DIRECTORY_FSYNC: u64 = 1;
const DURABILITY_UNCONFIRMED: u64 = 0;

/// Both held directory identities on which Darwin `fsync` completed after rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublicationBarriers {
	/// The private stage directory, whose original name became absent.
	pub stage_directory: DarwinFileIdentity,
	/// The public parent directory, in which the verified stage was observed.
	pub destination_directory: DarwinFileIdentity,
}

impl DarwinPublicationBarriers {
	fn validate(self) -> Result<(), DarwinPhaseError> {
		if self.stage_directory.volume() != self.destination_directory.volume() {
			return Err(DarwinPhaseError::VolumeMismatch);
		}
		if self.stage_directory.may_alias(self.destination_directory) {
			return Err(DarwinPhaseError::AliasedIdentity);
		}
		Ok(())
	}
}

/// Kind 9 refers to one successful observation, its active intent and the completed barriers.
///
/// The managed APFS profile records completion of the pre-rename stage file `F_FULLFSYNC`
/// and both post-rename directory `fsync` calls. Its achieved durability remains unconfirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinDurabilityRecorded {
	active: ActiveIntent,
	observed: ChainHead,
	metadata: ChainHead,
	barriers: DarwinPublicationBarriers,
}

impl DarwinDurabilityRecorded {
	/// Records successful barriers for the exact active intent and checked publication.
	///
	/// The caller supplies observations from the accepted owned chain and reports actual calls
	/// on the held private and public directories after the rename.
	/// # Errors
	/// Rejects invalid, out-of-order or mismatched evidence, incomplete publication, and
	/// barrier identities differing from their intended directories.
	pub fn new(
		metadata_frame: &Frame,
		intent_frame: &Frame,
		observed_frame: &Frame,
		barriers: DarwinPublicationBarriers,
	) -> Result<Self, DarwinPhaseError> {
		let observed = DarwinPublishObserved::from_frame(observed_frame)?;
		let record = Self::from_fields(
			observed.active(),
			observed_frame.head(),
			metadata_frame.head(),
			barriers,
		)?;
		record.check_evidence(metadata_frame, intent_frame, &observed)?;
		Ok(record)
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.active.binding
	}

	/// Returns the sequence of the active effect.
	#[must_use]
	pub const fn effect_sequence(&self) -> NonZeroU64 {
		self.active.effect
	}

	/// Returns the exact kind-7 frame reference.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.active.reference
	}

	/// Returns the exact kind-8 frame reference.
	#[must_use]
	pub const fn observed(&self) -> ChainHead {
		self.observed
	}

	/// Returns the exact kind-6 evidence of the full stage-file barrier.
	#[must_use]
	pub const fn metadata(&self) -> ChainHead {
		self.metadata
	}

	/// Returns the two held directory identities on which `fsync` succeeded.
	#[must_use]
	pub const fn barriers(&self) -> DarwinPublicationBarriers {
		self.barriers
	}

	/// Encodes the kind-9 managed APFS payload using deterministic CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			self.active.write_header(encoder)?;
			encoder
				.map(3)?
				.u8(0)?
				.u64(CROSS_DIRECTORY_DARWIN_RENAME_EXCL)?
				.u8(1)?
				.map(7)?
				.u8(0)?;
			self.active.write(encoder)?;
			encoder.u8(1)?;
			write_reference(encoder, self.observed)?;
			encoder.u8(2)?;
			write_reference(encoder, self.metadata)?;
			encoder.u8(3)?;
			write_identity(encoder, self.barriers.stage_directory)?;
			encoder.u8(4)?.u64(DARWIN_DIRECTORY_FSYNC)?.u8(5)?;
			write_identity(encoder, self.barriers.destination_directory)?;
			encoder
				.u8(6)?
				.u64(DARWIN_DIRECTORY_FSYNC)?
				.u8(2)?
				.u64(DURABILITY_UNCONFIRMED)?;
			Ok(())
		})
	}

	/// Decodes one complete canonical managed APFS kind-9 payload.
	/// # Errors
	/// Rejects malformed, incompatible or out-of-order barriers.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Decodes a kind-9 frame and checks that its references precede it.
	/// # Errors
	/// Rejects a wrong kind, invalid payload or out-of-order evidence.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		let record = Self::decode(frame_payload(frame, KIND)?)?;
		require_before(record.observed(), frame.head())?;
		Ok(record)
	}

	/// Validates the referenced evidence from the accepted owned chain.
	/// # Errors
	/// Rejects incorrect references, unsuccessful publication and mismatched identities
	/// or bindings in the completed stage-file and directory barriers.
	pub fn validate_evidence(
		&self,
		metadata_frame: &Frame,
		intent_frame: &Frame,
		observed_frame: &Frame,
	) -> Result<(), DarwinPhaseError> {
		if self.observed != observed_frame.head() {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		let observed = DarwinPublishObserved::from_frame(observed_frame)?;
		self.check_evidence(metadata_frame, intent_frame, &observed)
	}

	pub(super) const fn active(&self) -> ActiveIntent {
		self.active
	}

	fn check_evidence(
		&self,
		metadata_frame: &Frame,
		intent_frame: &Frame,
		observed: &DarwinPublishObserved,
	) -> Result<(), DarwinPhaseError> {
		if self.metadata != metadata_frame.head() || self.active != observed.active() {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		let intent = observed.bound_intent(intent_frame)?;
		let target = observed
			.published_target()
			.ok_or(DarwinPhaseError::InconsistentObservation)?;
		let metadata = DarwinMetadataRecorded::from_frame(metadata_frame)?;
		if metadata.record_digest() != intent.metadata_digest()
			|| metadata.binding() != self.binding()
			|| metadata.stage() != target
		{
			return Err(DarwinPhaseError::BindingMismatch);
		}
		let intended = intent.target();
		if self.barriers.stage_directory != intended.stage_directory
			|| self.barriers.destination_directory != intended.parent
		{
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		Ok(())
	}

	fn from_fields(
		active: ActiveIntent,
		observed: ChainHead,
		metadata: ChainHead,
		barriers: DarwinPublicationBarriers,
	) -> Result<Self, DarwinPhaseError> {
		require_before(metadata, active.reference)?;
		require_before(active.reference, observed)?;
		barriers.validate()?;
		Ok(Self {
			active,
			observed,
			metadata,
			barriers,
		})
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let header = ActiveIntent::read_header(decoder)?;
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		expect_code(decoder, CROSS_DIRECTORY_DARWIN_RENAME_EXCL)?;
		expect_key(decoder, 1)?;
		expect_map(decoder, 7)?;
		expect_key(decoder, 0)?;
		let active = ActiveIntent::read(decoder, header)?;
		expect_key(decoder, 1)?;
		let observed = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let metadata = read_reference(decoder)?;
		expect_key(decoder, 3)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 4)?;
		expect_code(decoder, DARWIN_DIRECTORY_FSYNC)?;
		expect_key(decoder, 5)?;
		let destination_directory = read_identity(decoder)?;
		expect_key(decoder, 6)?;
		expect_code(decoder, DARWIN_DIRECTORY_FSYNC)?;
		expect_key(decoder, 2)?;
		expect_code(decoder, DURABILITY_UNCONFIRMED)?;
		Self::from_fields(
			active,
			observed,
			metadata,
			DarwinPublicationBarriers {
				stage_directory,
				destination_directory,
			},
		)
	}
}
