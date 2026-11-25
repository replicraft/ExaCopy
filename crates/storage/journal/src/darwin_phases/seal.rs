use minicbor::Decoder;

use super::codec::{
	DARWIN_FULL_FILE_BARRIER, decode_record, encode_record, expect_code, frame_payload,
};
use super::{DarwinPhaseBinding, DarwinPhaseDigest, DarwinPhaseError};
use crate::darwin_prepared::wire::{
	read_entry_header, read_identity, write_header, write_identity,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinEntryPrepared, DarwinFileIdentity, StreamLength};

const KIND: FrameKind = FrameKind::StageSealed;
const SOLE_JOINED_WRITER: u64 = 1;

/// Kind 4 records a sealed stage after its sole writer completes the file barrier and closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinStageSealed {
	binding: DarwinPhaseBinding,
	prepared_frame_digest: [u8; 32],
	stage: DarwinFileIdentity,
	length: StreamLength,
}

impl DarwinStageSealed {
	/// Records confirmed writer closure, quiescence and a successful stage `F_FULLFSYNC`.
	///
	/// The coordinator supplies observations from the current native writer. It owns
	/// validation of the preparation frame's place in the accepted job history.
	///
	/// # Errors
	/// Rejects incompatible preparation and a changed stage identity or extent.
	pub fn new(
		prepared_frame: &Frame,
		stage: DarwinFileIdentity,
		length: StreamLength,
	) -> Result<Self, DarwinPhaseError> {
		let prepared = DarwinEntryPrepared::from_frame(prepared_frame)?;
		let record = Self {
			binding: DarwinPhaseBinding::prepared(&prepared),
			prepared_frame_digest: prepared_frame.head().digest(),
			stage,
			length,
		};
		record.check_preparation(&prepared)?;
		Ok(record)
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the sealed native stage identity.
	#[must_use]
	pub const fn stage(&self) -> DarwinFileIdentity {
		self.stage
	}

	/// Returns the stage's sealed logical byte length.
	#[must_use]
	pub const fn length(&self) -> StreamLength {
		self.length
	}

	/// Binds the exact canonical seal payload.
	#[must_use]
	pub fn record_digest(&self) -> DarwinPhaseDigest {
		DarwinPhaseDigest::of(KIND, &self.encode())
	}

	/// Encodes kind 4 under the managed APFS profile.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			write_header(encoder, self.binding.context, Some(self.binding.entry))?;
			encoder.map(6)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder.u8(1)?.bytes(&self.prepared_frame_digest)?.u8(2)?;
			write_identity(encoder, self.stage)?;
			encoder
				.u8(3)?
				.u64(self.length.get())?
				.u8(4)?
				.u64(SOLE_JOINED_WRITER)?
				.u8(5)?
				.u64(DARWIN_FULL_FILE_BARRIER)?;
			Ok(())
		})
	}

	/// Decodes one complete managed APFS seal payload.
	///
	/// # Errors
	/// Returns an error for malformed, noncanonical, or incompatible evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the discriminator and decodes one complete seal frame.
	///
	/// # Errors
	/// Returns an error for a wrong discriminator or an invalid payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		Self::decode(frame_payload(frame, KIND)?)
	}

	/// Checks the exact preparation frame, stage binding and extent.
	///
	/// # Errors
	/// Returns an error if the frame or one of its observations differs.
	pub fn check_prerequisite(&self, prepared_frame: &Frame) -> Result<(), DarwinPhaseError> {
		self.validated_preparation(prepared_frame).map(|_| ())
	}

	pub(super) fn validated_preparation<'a>(
		&self,
		prepared_frame: &'a Frame,
	) -> Result<DarwinEntryPrepared<'a>, DarwinPhaseError> {
		let prepared = DarwinEntryPrepared::from_frame(prepared_frame)?;
		if self.prepared_frame_digest != prepared_frame.head().digest()
			|| self.binding != DarwinPhaseBinding::prepared(&prepared)
		{
			return Err(DarwinPhaseError::BindingMismatch);
		}
		self.check_preparation(&prepared)?;
		Ok(prepared)
	}

	fn check_preparation(
		&self,
		prepared: &DarwinEntryPrepared<'_>,
	) -> Result<(), DarwinPhaseError> {
		let preparation = prepared.preparation();
		if self.stage != preparation.stage.identity {
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		if self.length.get() != preparation.source.length() {
			return Err(DarwinPhaseError::StreamMismatch);
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let (context, entry) = read_entry_header(decoder)?;
		expect_map(decoder, 6)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, entry)?;
		expect_key(decoder, 1)?;
		let prepared_frame_digest = read_fixed(decoder)?;
		expect_key(decoder, 2)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		let length =
			StreamLength::new(decoder.u64()?).map_err(|_| DarwinPhaseError::StreamMismatch)?;
		expect_key(decoder, 4)?;
		expect_code(decoder, SOLE_JOINED_WRITER)?;
		expect_key(decoder, 5)?;
		expect_code(decoder, DARWIN_FULL_FILE_BARRIER)?;
		Ok(Self {
			binding,
			prepared_frame_digest,
			stage,
			length,
		})
	}
}
