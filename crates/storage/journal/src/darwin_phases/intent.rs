use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use minicbor::Decoder;

use super::codec::{decode_record, encode_record, expect_code, frame_payload};
use super::{
	DarwinMetadataRecorded, DarwinPhaseBinding, DarwinPhaseDigest, DarwinPhaseError,
	DarwinStageSealed, DarwinVerificationRecorded,
};
use crate::darwin_prepared::same_native_object;
use crate::darwin_prepared::wire::{
	read_effect_header, read_identity, write_effect_header, write_identity,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinFileIdentity, JournalContext, PublishIntentContext};

const KIND: FrameKind = FrameKind::PublishIntent;
const RAW_UNIX_COMPONENT: u64 = 1;
const DARWIN_RENAME_EXCL: u64 = 2;

/// The native APFS objects and exact public name bound to exclusive publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublishTarget<'a> {
	/// The verified native file in the private stage directory.
	pub stage: DarwinFileIdentity,
	/// The verified private stage directory.
	pub stage_directory: DarwinFileIdentity,
	/// The held public destination parent.
	pub parent: DarwinFileIdentity,
	/// A validated raw component relative to the public parent.
	pub component: UnixComponent<'a>,
}

impl DarwinPublishTarget<'_> {
	fn validate(&self) -> Result<(), DarwinPhaseError> {
		if self.stage.volume() != self.stage_directory.volume()
			|| self.stage.volume() != self.parent.volume()
		{
			return Err(DarwinPhaseError::VolumeMismatch);
		}
		if same_native_object(self.stage, self.stage_directory)
			|| same_native_object(self.stage, self.parent)
			|| same_native_object(self.stage_directory, self.parent)
		{
			return Err(DarwinPhaseError::AliasedIdentity);
		}
		Ok(())
	}
}

/// Kind 7 binds the exact candidate effect and prerequisite APFS evidence.
///
/// The selected primitive is always Darwin `renameatx_np(RENAME_EXCL)` with no fallback.
/// This payload is evidence. Publication requires the model's authorization after a
/// successful durable append and independent validation of live filesystem conditions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublishIntent<'a> {
	binding: DarwinPhaseBinding,
	effect_sequence: NonZeroU64,
	target: DarwinPublishTarget<'a>,
	seal_digest: DarwinPhaseDigest,
	verification_digest: DarwinPhaseDigest,
	metadata_digest: DarwinPhaseDigest,
}

impl<'a> DarwinPublishIntent<'a> {
	/// Binds a publication candidate to the exact prepared target and completed phases.
	///
	/// The coordinator supplies the effect sequence and validates the preparation frame's
	/// place in the accepted job history.
	///
	/// # Errors
	/// Refuses inconsistent phase records or an incompatible target.
	pub fn new(
		effect_sequence: NonZeroU64,
		prepared_frame: &'a Frame,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
		metadata: &DarwinMetadataRecorded,
	) -> Result<Self, DarwinPhaseError> {
		let prepared = metadata.validated_preparation(prepared_frame, seal, verification)?;
		let preparation = prepared.preparation();
		let target = DarwinPublishTarget {
			stage: preparation.stage.identity,
			stage_directory: preparation.stage.directory,
			parent: prepared.destination_root().identity,
			component: preparation.target_component,
		};
		target.validate()?;
		Ok(Self {
			binding: metadata.binding(),
			effect_sequence,
			target,
			seal_digest: seal.record_digest(),
			verification_digest: verification.record_digest(),
			metadata_digest: metadata.record_digest(),
		})
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the effect sequence bound to this intent.
	#[must_use]
	pub const fn effect_sequence(&self) -> NonZeroU64 {
		self.effect_sequence
	}

	/// Returns the exact candidate stage, directories, and target name.
	#[must_use]
	pub const fn target(&self) -> DarwinPublishTarget<'a> {
		self.target
	}

	/// Binds the exact canonical intent payload.
	#[must_use]
	pub fn record_digest(&self) -> DarwinPhaseDigest {
		DarwinPhaseDigest::of(KIND, &self.encode())
	}

	/// Encodes kind 7 under the managed APFS profile.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			let context = self.binding.context;
			let header = PublishIntentContext {
				job: context.job,
				epoch: context.epoch,
				entry: self.binding.entry,
				effect_sequence: self.effect_sequence.get(),
				plan_digest: context.plan_digest,
			};
			write_effect_header(encoder, &header)?;
			encoder.map(9)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder.u8(1)?;
			write_identity(encoder, self.target.stage)?;
			encoder.u8(2)?;
			write_identity(encoder, self.target.stage_directory)?;
			encoder.u8(3)?;
			write_identity(encoder, self.target.parent)?;
			encoder
				.u8(4)?
				.map(2)?
				.u8(0)?
				.u64(RAW_UNIX_COMPONENT)?
				.u8(1)?
				.bytes(self.target.component.as_bytes())?
				.u8(5)?
				.bytes(self.seal_digest.as_bytes())?
				.u8(6)?
				.bytes(self.verification_digest.as_bytes())?
				.u8(7)?
				.bytes(self.metadata_digest.as_bytes())?
				.u8(8)?
				.u64(DARWIN_RENAME_EXCL)?;
			Ok(())
		})
	}

	/// Decodes one complete intent payload, borrowing its raw public component.
	///
	/// # Errors
	/// Returns an error for malformed, noncanonical, or incompatible intent.
	pub fn decode(payload: &'a [u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the discriminator and decodes one complete intent frame.
	///
	/// # Errors
	/// Returns an error for a wrong discriminator or an invalid payload.
	pub fn from_frame(frame: &'a Frame) -> Result<Self, DarwinPhaseError> {
		Self::decode(frame_payload(frame, KIND)?)
	}

	/// Checks the exact prerequisite evidence, effect sequence, and prepared target.
	///
	/// # Errors
	/// Returns an error if any bound evidence or the expected effect sequence differs.
	pub fn check_prerequisites(
		&self,
		effect_sequence: NonZeroU64,
		prepared_frame: &Frame,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
		metadata: &DarwinMetadataRecorded,
	) -> Result<(), DarwinPhaseError> {
		let expected = DarwinPublishIntent::new(
			effect_sequence,
			prepared_frame,
			seal,
			verification,
			metadata,
		)?;
		if *self != expected {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'a>) -> Result<Self, DarwinPhaseError> {
		let header = read_effect_header(decoder)?;
		let effect_sequence = NonZeroU64::new(header.effect_sequence)
			.ok_or(DarwinPhaseError::InvalidEffectSequence)?;
		let context = JournalContext {
			job: header.job,
			epoch: header.epoch,
			plan_digest: header.plan_digest,
		};
		expect_map(decoder, 9)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, header.entry)?;
		expect_key(decoder, 1)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		let parent = read_identity(decoder)?;
		expect_key(decoder, 4)?;
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		expect_code(decoder, RAW_UNIX_COMPONENT)?;
		expect_key(decoder, 1)?;
		let component =
			UnixComponent::new(decoder.bytes()?).map_err(|_| DarwinPhaseError::InvalidComponent)?;
		let target = DarwinPublishTarget {
			stage,
			stage_directory,
			parent,
			component,
		};
		target.validate()?;
		expect_key(decoder, 5)?;
		let seal_digest = DarwinPhaseDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 6)?;
		let verification_digest = DarwinPhaseDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 7)?;
		let metadata_digest = DarwinPhaseDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 8)?;
		expect_code(decoder, DARWIN_RENAME_EXCL)?;
		Ok(Self {
			binding,
			effect_sequence,
			target,
			seal_digest,
			verification_digest,
			metadata_digest,
		})
	}
}
