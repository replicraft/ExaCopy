mod cbor;
mod error;
mod identity;

pub use error::IntentError;
pub use identity::{
	JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, PlanDigest, VerificationDigest,
};

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Encoder, encode};

use self::cbor::Decoder;
use crate::frame::{Frame, FrameKind};

const FORMAT_MAJOR: u64 = 1;
const FORMAT_MINOR: u64 = 0;
const REQUIRED_FEATURES: u64 = 0;
const LINUX_PLATFORM: u64 = 1;
const UNIX_BYTES: u64 = 1;
const LINUX_RENAME_NO_REPLACE: u64 = 1;

// Includes two maximum-width CBOR u64 values and all map keys, headers and fixed fields.
const FIXED_FIELDS_MAX_BYTES: usize = 200;
const MAX_PAYLOAD_BYTES: usize = FIXED_FIELDS_MAX_BYTES + MAX_UNIX_COMPONENT_BYTES;

type PayloadCursor = Cursor<[u8; MAX_PAYLOAD_BYTES]>;
type EncodeError = encode::Error<EndOfArray>;

/// The exclusive namespace primitive recorded by a publication intent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PublicationPrimitive {
	/// Local v1 code 1, Linux renameat2(RENAME_NOREPLACE) with no fallback.
	LinuxRenameNoReplace,
}

impl PublicationPrimitive {
	fn code(self) -> u64 {
		match self {
			Self::LinuxRenameNoReplace => LINUX_RENAME_NO_REPLACE,
		}
	}

	fn from_code(code: u64) -> Result<Self, IntentError> {
		match code {
			LINUX_RENAME_NO_REPLACE => Ok(Self::LinuxRenameNoReplace),
			_ => Err(IntentError::UnsupportedPrimitive),
		}
	}
}

/// The common journal fields required by a publication intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishIntentContext {
	/// The job to which the candidate effect belongs.
	pub job: JournalJobId,
	/// The run generation that sealed and verified the stage.
	pub epoch: JournalEpoch,
	/// The entry UUID bound by the plan and journal.
	pub entry: JournalEntryId,
	/// The effect's sequence in its job's effect history.
	pub effect_sequence: u64,
	/// The canonical plan digest.
	pub plan_digest: PlanDigest,
}

/// The sealed stage and exact target bound to a candidate exclusive publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishIntentTarget<'a> {
	/// The native identity observed for the staged file.
	pub stage: LinuxFileIdentity,
	/// The native identity observed for the destination directory.
	pub parent: LinuxFileIdentity,
	/// One validated raw Unix component relative to the parent.
	pub component: UnixComponent<'a>,
	/// The sealed stage's independent file read-back digest.
	pub verification_digest: VerificationDigest,
	/// The namespace primitive for the requested publication.
	pub primitive: PublicationPrimitive,
}

/// The local v1 publication intent payload for journal record kind 7.
///
/// This is an observation to bind against a validated journal chain, current
/// owner, job, epoch, and adapter evidence. Exclusive publication authorization
/// remains with the transaction coordinator and model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishIntent<'a> {
	/// The candidate effect's job and plan context.
	pub context: PublishIntentContext,
	/// The stage and destination observations associated with the candidate effect.
	pub target: PublishIntentTarget<'a>,
}

impl<'a> PublishIntent<'a> {
	/// Encodes the complete local v1 deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let canonical = self.encode_bounded();
		canonical.get_ref()[..canonical.position()].to_vec()
	}

	fn encode_bounded(&self) -> PayloadCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_PAYLOAD_BYTES]));
		self.write_payload(&mut encoder)
			.expect("the validated kind-7 payload fits its fixed-size buffer");
		encoder.into_writer()
	}

	fn write_payload(&self, encoder: &mut Encoder<PayloadCursor>) -> Result<(), EncodeError> {
		encoder
			.map(8)?
			.u64(0)?
			.map(3)?
			.u64(0)?
			.u64(FORMAT_MAJOR)?
			.u64(1)?
			.u64(FORMAT_MINOR)?
			.u64(2)?
			.u64(REQUIRED_FEATURES)?;

		encoder
			.u64(1)?
			.bytes(self.context.job.as_bytes())?
			.u64(2)?
			.u64(self.context.epoch.get())?
			.u64(3)?
			.bytes(self.context.entry.as_bytes())?
			.u64(4)?
			.u64(self.context.effect_sequence)?
			.u64(5)?
			.bytes(self.context.plan_digest.as_bytes())?
			.u64(6)?
			.u64(REQUIRED_FEATURES)?
			.u64(10)?
			.map(5)?
			.u64(0)?;
		encode_identity(encoder, self.target.stage)?;
		encoder.u64(1)?;
		encode_identity(encoder, self.target.parent)?;
		encoder
			.u64(2)?
			.map(2)?
			.u64(0)?
			.u64(UNIX_BYTES)?
			.u64(1)?
			.bytes(self.target.component.as_bytes())?
			.u64(3)?
			.bytes(self.target.verification_digest.as_bytes())?
			.u64(4)?
			.u64(self.target.primitive.code())?;
		Ok(())
	}

	/// Checks the envelope discriminator and decodes its complete payload.
	///
	/// # Errors
	/// Returns a typed error for an incompatible kind or invalid payload.
	pub fn from_frame(frame: &'a Frame) -> Result<Self, IntentError> {
		if frame.kind() != FrameKind::PublishIntent {
			return Err(IntentError::WrongRecordKind);
		}
		Self::decode(frame.payload())
	}

	/// Decodes one complete validated payload for an already identified kind-7 frame.
	///
	/// The filename borrows the input bytes. All maps are shape-checked in canonical
	/// key order. Re-encoding to a bounded buffer enforces shortest representations.
	///
	/// # Errors
	/// Returns a typed error for malformed or unsupported bytes.
	pub fn decode(payload: &'a [u8]) -> Result<Self, IntentError> {
		if payload.len() > MAX_PAYLOAD_BYTES {
			return Err(IntentError::Length);
		}

		let mut decoder = Decoder::new(payload);
		decoder.map(8)?;
		decoder.key(0)?;
		decode_version(&mut decoder)?;
		let context = decode_context(&mut decoder)?;
		decoder.key(10)?;
		let target = decode_target(&mut decoder)?;
		decoder.finish()?;

		let intent = Self { context, target };
		let canonical = intent.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(IntentError::NonCanonical);
		}
		Ok(intent)
	}
}

fn encode_identity(
	encoder: &mut Encoder<PayloadCursor>,
	identity: LinuxFileIdentity,
) -> Result<(), EncodeError> {
	encoder
		.map(4)?
		.u64(0)?
		.u64(LINUX_PLATFORM)?
		.u64(1)?
		.bytes(&identity.device().to_le_bytes())?
		.u64(2)?
		.bytes(&identity.inode().to_le_bytes())?
		.u64(3)?
		.null()?;
	Ok(())
}

fn decode_version(decoder: &mut Decoder<'_>) -> Result<(), IntentError> {
	decoder.map(3)?;
	decoder.key(0)?;
	let major = decoder.uint()?;
	decoder.key(1)?;
	let minor = decoder.uint()?;
	if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
		return Err(IntentError::UnsupportedVersion);
	}
	decoder.key(2)?;
	decode_feature_bits(decoder)
}

fn decode_feature_bits(decoder: &mut Decoder<'_>) -> Result<(), IntentError> {
	if decoder.uint()? != REQUIRED_FEATURES {
		return Err(IntentError::UnsupportedFeatures);
	}
	Ok(())
}

fn decode_context(decoder: &mut Decoder<'_>) -> Result<PublishIntentContext, IntentError> {
	decoder.key(1)?;
	let job = JournalJobId::from_bytes(decoder.fixed_bytes()?)?;
	decoder.key(2)?;
	let epoch = JournalEpoch::new(decoder.uint()?);
	decoder.key(3)?;
	let entry = JournalEntryId::from_bytes(decoder.fixed_bytes()?);
	decoder.key(4)?;
	let effect_sequence = decoder.uint()?;
	decoder.key(5)?;
	let plan_digest = PlanDigest::from_bytes(decoder.fixed_bytes()?);
	decoder.key(6)?;
	decode_feature_bits(decoder)?;
	Ok(PublishIntentContext {
		job,
		epoch,
		entry,
		effect_sequence,
		plan_digest,
	})
}

fn decode_target<'a>(decoder: &mut Decoder<'a>) -> Result<PublishIntentTarget<'a>, IntentError> {
	decoder.map(5)?;
	decoder.key(0)?;
	let stage = decode_identity(decoder)?;
	decoder.key(1)?;
	let parent = decode_identity(decoder)?;
	decoder.key(2)?;
	decoder.map(2)?;
	decoder.key(0)?;
	if decoder.uint()? != UNIX_BYTES {
		return Err(IntentError::UnsupportedComponentEncoding);
	}
	decoder.key(1)?;
	let name = decoder.bytes(MAX_UNIX_COMPONENT_BYTES)?;
	let component = UnixComponent::new(name).map_err(IntentError::InvalidComponent)?;
	decoder.key(3)?;
	let verification_digest = VerificationDigest::from_bytes(decoder.fixed_bytes()?);
	decoder.key(4)?;
	let primitive = PublicationPrimitive::from_code(decoder.uint()?)?;
	Ok(PublishIntentTarget {
		stage,
		parent,
		component,
		verification_digest,
		primitive,
	})
}

fn decode_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, IntentError> {
	decoder.map(4)?;
	decoder.key(0)?;
	if decoder.uint()? != LINUX_PLATFORM {
		return Err(IntentError::UnsupportedPlatform);
	}
	decoder.key(1)?;
	let device = u64::from_le_bytes(decoder.fixed_bytes()?);
	decoder.key(2)?;
	let inode = u64::from_le_bytes(decoder.fixed_bytes()?);
	decoder.key(3)?;
	decoder.null()?;
	Ok(LinuxFileIdentity::new(device, inode))
}
