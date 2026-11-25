use std::fmt;

use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::{ApprovedPublicPlanDigest, OwnerDigest, OwnerTimestamp, PublicPlanEntryId};

use super::{MAX_PAYLOAD_BYTES, PublishIntent};

const VERSION: [u64; 3] = [2, 0, 1];
const FIELDS: u64 = 7;
const ARM64_EXT4_FIXTURE: u64 = 1;

// Allows the version, association, two frame references, qualification tuple,
// full-width timestamp and byte-string headers beyond the maximum v1 payload.
const WRAPPER_OVERHEAD_LIMIT: usize = 320;

/// Maximum encoded size of the bounded Linux public-apply intent payload.
pub const MAX_PUBLIC_APPLY_INTENT_BYTES: usize = MAX_PAYLOAD_BYTES + WRAPPER_OVERHEAD_LIMIT;

type Buffer = Cursor<[u8; MAX_PUBLIC_APPLY_INTENT_BYTES]>;
type EncodeError = encode::Error<EndOfArray>;

/// The signed owner and approved public entry associated with one private effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicApplyAssociation {
	/// Digest of the exact signed owner envelope.
	pub owner_digest: OwnerDigest,
	/// Approved public Plan body digest.
	pub public_plan: ApprovedPublicPlanDigest,
	/// Approved public entry identifier within the Plan's exact page.
	pub public_entry: PublicPlanEntryId,
}

/// Digest identifying the independently selected process-crash qualification record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyQualificationDigest([u8; 32]);

impl ApplyQualificationDigest {
	/// Wraps a local qualification record's digest for evidence comparison.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the recorded digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Scope of the native eligibility observation recorded with a public intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyProcessCrashEnvironment {
	/// Exact Linux boot UUID.
	pub boot_id: [u8; 16],
	/// Identity of the held mount namespace.
	pub mount_namespace: u64,
	/// Unique native mount identity within the current boot.
	pub unique_mount: u64,
	/// Observed Linux device number.
	pub device: u64,
}

/// Qualified process-crash fixture profile named by an intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyCrashProfile {
	/// The selected ARM64 Ubuntu/ext4 fixture environment.
	Arm64UbuntuExt4FixtureV1,
}

/// Recorded qualification claims, subject to independent admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyQualification {
	/// Identity of the independently enrolled qualification evidence.
	pub record: ApplyQualificationDigest,
	/// Selected fixed profile in that evidence.
	pub profile: ApplyCrashProfile,
	/// Exact environment at the intent boundary.
	pub environment: ApplyProcessCrashEnvironment,
}

/// Preceding frames and trusted clock observation required by the public intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyIntentEvidence {
	/// Verified independent stream evidence immediately before metadata.
	pub verification: ChainHead,
	/// Completed metadata frame immediately before this intent.
	pub metadata: ChainHead,
	/// Exact independently selected qualification claims.
	pub qualification: ApplyQualification,
	/// Fresh trusted wall-clock observation before synchronizing the intent.
	pub intent_time: OwnerTimestamp,
}

/// Mandatory kind-7 v2 payload for a public Plan effect.
///
/// The inner v1 data shape retains the private Plan binding. This wrapper is
/// a journal assertion. A consumer must independently authenticate the owner,
/// validate the referenced frames and actual capabilities, and gate any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicApplyIntent<'name> {
	private: PublishIntent<'name>,
	association: PublicApplyAssociation,
	evidence: ApplyIntentEvidence,
}

impl<'name> PublicApplyIntent<'name> {
	/// Constructs one syntactically and structurally bound public effect record.
	///
	/// # Errors
	/// Refuses invalid private effect fields, frame links and environment identity.
	pub fn new(
		private: PublishIntent<'name>,
		association: PublicApplyAssociation,
		evidence: ApplyIntentEvidence,
	) -> Result<Self, PublicApplyIntentError> {
		if private.context.epoch.get() == 0
			|| private.context.entry.as_bytes() == &[0; 16]
			|| private.context.effect_sequence != 1
			|| private.target.stage == private.target.parent
			|| private.target.stage.device() != private.target.parent.device()
			|| private.target.parent.device() != evidence.qualification.environment.device
		{
			return Err(PublicApplyIntentError::Binding);
		}
		let environment = evidence.qualification.environment;
		if environment.boot_id == [0; 16]
			|| environment.mount_namespace == 0
			|| environment.unique_mount == 0
		{
			return Err(PublicApplyIntentError::Binding);
		}
		if evidence.verification == ChainHead::start()
			|| evidence.verification.sequence().checked_add(1) != Some(evidence.metadata.sequence())
			|| evidence.metadata.sequence().checked_add(1).is_none()
		{
			return Err(PublicApplyIntentError::FrameBinding);
		}
		Ok(Self {
			private,
			association,
			evidence,
		})
	}

	/// Returns the private effect fields inside the mandatory wrapper.
	#[must_use]
	pub const fn private(&self) -> &PublishIntent<'name> {
		&self.private
	}

	/// Returns the public Plan, entry and signed owner association.
	#[must_use]
	pub const fn association(&self) -> PublicApplyAssociation {
		self.association
	}

	/// Returns the referenced frames, qualification and clock claims.
	#[must_use]
	pub const fn evidence(&self) -> ApplyIntentEvidence {
		self.evidence
	}

	/// Encodes the bounded canonical public-apply payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encoded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	/// Checks the frame discriminator and binds the preceding metadata frame.
	///
	/// # Errors
	/// Refuses unsupported, malformed or mismatched evidence, including a v1 intent.
	pub fn from_frame(frame: &'name Frame) -> Result<Self, PublicApplyIntentError> {
		if frame.kind() != FrameKind::PublishIntent {
			return Err(PublicApplyIntentError::WrongRecordKind);
		}
		let intent = Self::decode(frame.payload())?;
		let metadata = intent.evidence.metadata;
		if metadata.sequence().checked_add(1) != Some(frame.head().sequence())
			|| metadata.digest() != frame.previous_digest()
		{
			return Err(PublicApplyIntentError::FrameBinding);
		}
		Ok(intent)
	}

	/// Decodes one bounded canonical public-apply payload.
	///
	/// # Errors
	/// Refuses unsupported versions, malformed fields, or noncanonical encoding.
	pub fn decode(input: &'name [u8]) -> Result<Self, PublicApplyIntentError> {
		if input.len() > MAX_PUBLIC_APPLY_INTENT_BYTES {
			return Err(PublicApplyIntentError::Length);
		}
		let mut decoder = Decoder::new(input);
		expect_map(&mut decoder, FIELDS)?;
		expect_key(&mut decoder, 0)?;
		expect_map(&mut decoder, 3)?;
		for (key, value) in [0, 1, 2].into_iter().zip(VERSION) {
			expect_key(&mut decoder, key)?;
			if decoder.u64()? != value {
				return Err(PublicApplyIntentError::UnsupportedVersion);
			}
		}
		expect_key(&mut decoder, 1)?;
		let private = PublishIntent::decode(decoder.bytes()?)
			.map_err(PublicApplyIntentError::PrivateIntent)?;
		expect_key(&mut decoder, 2)?;
		let association = read_association(&mut decoder)?;
		expect_key(&mut decoder, 3)?;
		let verification = read_head(&mut decoder)?;
		expect_key(&mut decoder, 4)?;
		let metadata = read_head(&mut decoder)?;
		expect_key(&mut decoder, 5)?;
		let qualification = read_qualification(&mut decoder)?;
		expect_key(&mut decoder, 6)?;
		expect_array(&mut decoder, 2)?;
		let seconds = decoder.i64()?;
		let nanos = decoder.u32()?;
		let intent_time =
			OwnerTimestamp::new(seconds, nanos).map_err(|_| PublicApplyIntentError::Binding)?;
		let intent = Self::new(
			private,
			association,
			ApplyIntentEvidence {
				verification,
				metadata,
				qualification,
				intent_time,
			},
		)?;
		let canonical = intent.encoded();
		if canonical.get_ref()[..canonical.position()] != *input {
			return Err(PublicApplyIntentError::NonCanonical);
		}
		Ok(intent)
	}

	fn encoded(&self) -> Buffer {
		let mut encoder = Encoder::new(Buffer::new([0; MAX_PUBLIC_APPLY_INTENT_BYTES]));
		self.write(&mut encoder)
			.expect("validated intent fits the fixed public payload bound");
		encoder.into_writer()
	}

	fn write(&self, encoder: &mut Encoder<Buffer>) -> Result<(), EncodeError> {
		let evidence = self.evidence;
		let qualification = evidence.qualification;
		let environment = qualification.environment;
		let profile = match qualification.profile {
			ApplyCrashProfile::Arm64UbuntuExt4FixtureV1 => ARM64_EXT4_FIXTURE,
		};
		encoder.map(FIELDS)?.u8(0)?.map(3)?;
		for (key, value) in [0, 1, 2].into_iter().zip(VERSION) {
			encoder.u8(key)?.u64(value)?;
		}
		let private = self.private.encode_bounded();
		encoder
			.u8(1)?
			.bytes(&private.get_ref()[..private.position()])?
			.u8(2)?
			.array(3)?
			.bytes(self.association.owner_digest.as_bytes())?
			.bytes(self.association.public_plan.as_bytes())?
			.bytes(self.association.public_entry.as_bytes())?
			.u8(3)?;
		write_head(encoder, evidence.verification)?;
		encoder.u8(4)?;
		write_head(encoder, evidence.metadata)?;
		encoder
			.u8(5)?
			.array(3)?
			.bytes(qualification.record.as_bytes())?
			.u64(profile)?
			.array(4)?
			.bytes(&environment.boot_id)?
			.u64(environment.mount_namespace)?
			.u64(environment.unique_mount)?
			.u64(environment.device)?
			.u8(6)?
			.array(2)?
			.i64(evidence.intent_time.seconds())?
			.u32(evidence.intent_time.nanoseconds())?;
		Ok(())
	}
}

fn read_association(
	decoder: &mut Decoder<'_>,
) -> Result<PublicApplyAssociation, PublicApplyIntentError> {
	expect_array(decoder, 3)?;
	Ok(PublicApplyAssociation {
		owner_digest: OwnerDigest::from_bytes(fixed(decoder)?),
		public_plan: ApprovedPublicPlanDigest::from_bytes(fixed(decoder)?),
		public_entry: PublicPlanEntryId::from_bytes(fixed(decoder)?)
			.map_err(|_| PublicApplyIntentError::Binding)?,
	})
}

fn read_qualification(
	decoder: &mut Decoder<'_>,
) -> Result<ApplyQualification, PublicApplyIntentError> {
	expect_array(decoder, 3)?;
	let record = ApplyQualificationDigest::from_bytes(fixed(decoder)?);
	let profile = match decoder.u64()? {
		ARM64_EXT4_FIXTURE => ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
		_ => return Err(PublicApplyIntentError::UnsupportedQualification),
	};
	expect_array(decoder, 4)?;
	Ok(ApplyQualification {
		record,
		profile,
		environment: ApplyProcessCrashEnvironment {
			boot_id: fixed(decoder)?,
			mount_namespace: decoder.u64()?,
			unique_mount: decoder.u64()?,
			device: decoder.u64()?,
		},
	})
}

fn read_head(decoder: &mut Decoder<'_>) -> Result<ChainHead, PublicApplyIntentError> {
	expect_array(decoder, 2)?;
	ChainHead::after(decoder.u64()?, fixed(decoder)?).ok_or(PublicApplyIntentError::FrameBinding)
}

fn write_head(encoder: &mut Encoder<Buffer>, head: ChainHead) -> Result<(), EncodeError> {
	encoder
		.array(2)?
		.u64(head.sequence())?
		.bytes(&head.digest())?;
	Ok(())
}

fn fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], PublicApplyIntentError> {
	decoder
		.bytes()?
		.try_into()
		.map_err(|_| PublicApplyIntentError::Length)
}

fn expect_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), PublicApplyIntentError> {
	(decoder.u8()? == key)
		.then_some(())
		.ok_or(PublicApplyIntentError::InvalidCbor)
}

fn expect_array(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), PublicApplyIntentError> {
	(decoder.array()? == Some(fields))
		.then_some(())
		.ok_or(PublicApplyIntentError::InvalidCbor)
}

fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), PublicApplyIntentError> {
	(decoder.map()? == Some(fields))
		.then_some(())
		.ok_or(PublicApplyIntentError::InvalidCbor)
}

/// Why a mandatory public intent payload could not be interpreted.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicApplyIntentError {
	/// Wrong enclosing journal frame kind.
	WrongRecordKind,
	/// Payload or fixed field length is outside the selected bound.
	Length,
	/// Malformed CBOR or field order.
	InvalidCbor,
	/// Noncanonical or trailing bytes.
	NonCanonical,
	/// Unsupported mandatory public intent version or feature set.
	UnsupportedVersion,
	/// The qualification profile is unsupported.
	UnsupportedQualification,
	/// A private or qualification identity is incompatible.
	Binding,
	/// The preceding frame references do not establish the required order and identity.
	FrameBinding,
	/// The mandatory canonical inner private intent was refused.
	PrivateIntent(super::IntentError),
}

impl From<minicbor::decode::Error> for PublicApplyIntentError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl fmt::Display for PublicApplyIntentError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind => "wrong public intent frame kind",
			Self::Length => "public intent payload or field length is unsupported",
			Self::InvalidCbor => "invalid public intent CBOR shape",
			Self::NonCanonical => "public intent payload is not canonical",
			Self::UnsupportedVersion => {
				"public intent version or required features are unsupported"
			}
			Self::UnsupportedQualification => "public intent qualification profile is unsupported",
			Self::Binding => "public intent has incompatible identities or time",
			Self::FrameBinding => "public intent frame references disagree",
			Self::PrivateIntent(error) => {
				return write!(formatter, "inner private intent refused ({error})");
			}
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for PublicApplyIntentError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::PrivateIntent(error) => Some(error),
			_ => None,
		}
	}
}
