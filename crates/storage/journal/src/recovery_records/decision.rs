use minicbor::Decoder;

use super::codec::{
	decode_frame, decode_record, encode_record, read_reference, require_before, require_reference,
	write_reference,
};
use super::{RecoveryRecordError, RecoveryStarted};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed, read_identity, write_identity};
use crate::{
	JournalContext, JournalEntryId, LinuxFileIdentity, MetadataRecorded, OwnerDigest, StreamDigest,
	StreamEvidence, StreamLength, VerificationRecorded,
};

// The sole local decision resumes barriers and receipt for the original publication.
const COMPLETE_PUBLISHED_RECEIPT: u64 = 1;
// The original private stage name was absent during inspection.
const PRIVATE_STAGE_ABSENT: u64 = 0;

/// Exact observations for the local cross-directory no-clobber recovery decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedRecoveryEvidence {
	/// Identity found at the public target after the original private stage name was absent.
	pub target: LinuxFileIdentity,
	/// Directory held during the final target observation.
	pub destination_directory: LinuxFileIdentity,
	/// Private directory held during the original stage name absence observation.
	pub stage_directory: LinuxFileIdentity,
	/// Exact original kind-5 frame whose measurements were rechecked.
	pub verification: ChainHead,
	/// Actual recovery read-back of the public target with complete length and BLAKE3 digest.
	pub stream: StreamEvidence,
	/// Exact original kind-6 frame whose required metadata was rechecked on the public target.
	pub metadata: ChainHead,
}

/// The preceding frames from the independently scanned and checked journal chain.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryDecisionFrames<'a> {
	/// The kind-19 start immediately before the decision.
	pub started: &'a Frame,
	/// The original verified kind-7 publication intent.
	pub intent: &'a Frame,
	/// The original kind-5 verification record cited by the decision.
	pub verification: &'a Frame,
	/// The original kind-6 metadata record cited by the decision.
	pub metadata: &'a Frame,
}

/// Independently established directory bindings for this recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDirectories {
	/// The held, trusted private directory containing the original stage name.
	pub stage: LinuxFileIdentity,
	/// The held, trusted directory containing the public target name.
	pub destination: LinuxFileIdentity,
}

/// A local kind-20 record to finish barriers and a receipt for an already-published file.
///
/// The record identifies observations made in a recovery generation. Authorization
/// and live namespace checks remain with the recovery coordinator. The original
/// publication effect keeps its own recorded identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDecision {
	context: JournalContext,
	entry: JournalEntryId,
	started: ChainHead,
	evidence: PublishedRecoveryEvidence,
}

impl RecoveryDecision {
	/// Constructs a decision from the identity, stream and metadata revalidation evidence.
	///
	/// # Errors
	/// Rejects invalid identities and reserved or unordered evidence references.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		started: ChainHead,
		evidence: PublishedRecoveryEvidence,
	) -> Result<Self, RecoveryRecordError> {
		require_reference(started)?;
		require_reference(evidence.verification)?;
		require_reference(evidence.metadata)?;
		require_before(evidence.verification, evidence.metadata)?;
		require_before(evidence.metadata, started)?;
		if evidence.target != evidence.stream.identity
			|| evidence.target == evidence.stage_directory
			|| evidence.target == evidence.destination_directory
			|| evidence.stage_directory == evidence.destination_directory
			|| evidence.stage_directory.device() != evidence.destination_directory.device()
			|| evidence.target.device() != evidence.destination_directory.device()
		{
			return Err(RecoveryRecordError::InvalidIdentityScope);
		}
		Ok(Self {
			context,
			entry,
			started,
			evidence,
		})
	}

	/// Returns the job, plan, and recovery generation that made the observation.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the entry whose original publication was observed.
	#[must_use]
	pub const fn entry(&self) -> JournalEntryId {
		self.entry
	}

	/// Returns the exact kind-19 record immediately before this decision.
	#[must_use]
	pub const fn started(&self) -> ChainHead {
		self.started
	}

	/// Returns the measured stream, observed identities, and original evidence references.
	#[must_use]
	pub const fn evidence(&self) -> PublishedRecoveryEvidence {
		self.evidence
	}

	/// Encodes the complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(4)?
				.u8(0)?
				.u64(COMPLETE_PUBLISHED_RECEIPT)?
				.u8(1)?
				.map(4)?
				.u8(0)?;
			write_identity(encoder, self.evidence.target)?;
			encoder.u8(1)?;
			write_identity(encoder, self.evidence.destination_directory)?;
			encoder.u8(2)?;
			write_identity(encoder, self.evidence.stage_directory)?;
			encoder
				.u8(3)?
				.u64(PRIVATE_STAGE_ABSENT)?
				.u8(2)?
				.map(5)?
				.u8(0)?;
			write_reference(encoder, self.started)?;
			encoder.u8(1)?;
			write_reference(encoder, self.evidence.verification)?;
			encoder.u8(2)?;
			write_reference(encoder, self.evidence.metadata)?;
			encoder
				.u8(3)?
				.u64(self.evidence.stream.length.get())?
				.u8(4)?
				.bytes(self.evidence.stream.digest.as_bytes())?
				.u8(3)?
				.null()?; // This decision creates no new namespace effect identity.
			Ok(())
		})
	}

	/// Decodes a complete canonical payload for an identified kind-20 record.
	///
	/// # Errors
	/// Rejects malformed, unsupported or inconsistent evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, RecoveryRecordError> {
		decode_record(payload, Self::read_body, Self::encode)
	}

	/// Checks the envelope kind and its exact kind-19 predecessor reference.
	///
	/// # Errors
	/// Rejects a wrong kind, invalid payload or mismatched preceding frame reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, RecoveryRecordError> {
		decode_frame(
			frame,
			FrameKind::RecoveryDecision,
			Self::decode,
			Self::started,
		)
	}

	/// Checks the recorded decision against original copy evidence and independent bindings.
	///
	/// The caller supplies frames from the verified chain, a trusted owner digest and held
	/// directory identities. The caller verifies frame synchronization and current live state.
	///
	/// # Errors
	/// Rejects mismatched or out-of-order references, generations, identities, stream
	/// measurements, or associated metadata records.
	pub fn validate_evidence(
		&self,
		frames: RecoveryDecisionFrames<'_>,
		expected_owner: OwnerDigest,
		directories: RecoveryDirectories,
	) -> Result<(), RecoveryRecordError> {
		if self.started != frames.started.head()
			|| self.evidence.verification != frames.verification.head()
			|| self.evidence.metadata != frames.metadata.head()
			|| self.evidence.stage_directory != directories.stage
			|| self.evidence.destination_directory != directories.destination
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		require_before(frames.metadata.head(), frames.intent.head())?;
		require_before(frames.intent.head(), frames.started.head())?;
		let started = RecoveryStarted::from_frame(frames.started)?;
		let intent = started.validate_intent(frames.intent, expected_owner)?;
		let verification = VerificationRecorded::from_frame(frames.verification)
			.map_err(RecoveryRecordError::Verification)?;
		let metadata = MetadataRecorded::from_frame(frames.metadata)
			.map_err(RecoveryRecordError::Verification)?;
		let original = JournalContext {
			job: intent.context.job,
			epoch: intent.context.epoch,
			plan_digest: intent.context.plan_digest,
		};
		if started.context() != self.context
			|| started.entry() != self.entry
			|| verification.context != original
			|| metadata.context != original
			|| verification.entry != self.entry
			|| metadata.entry != self.entry
			|| metadata.stage != self.evidence.target
			|| intent.target.stage != self.evidence.target
			|| intent.target.parent != self.evidence.destination_directory
			|| intent.target.verification_digest != verification.record_digest()
			|| verification.stage() != self.evidence.stream
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		Ok(())
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, RecoveryRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		if decoder.u64()? != COMPLETE_PUBLISHED_RECEIPT {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 1)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let target = read_identity(decoder)?;
		expect_key(decoder, 1)?;
		let destination_directory = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		if decoder.u64()? != PRIVATE_STAGE_ABSENT {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 2)?;
		expect_map(decoder, 5)?;
		expect_key(decoder, 0)?;
		let started = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let verification = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let metadata = read_reference(decoder)?;
		expect_key(decoder, 3)?;
		let length =
			StreamLength::new(decoder.u64()?).map_err(RecoveryRecordError::Verification)?;
		expect_key(decoder, 4)?;
		let digest = StreamDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 3)?;
		decoder.null()?;
		Self::new(
			context,
			entry,
			started,
			PublishedRecoveryEvidence {
				target,
				destination_directory,
				stage_directory,
				verification,
				stream: StreamEvidence {
					identity: target,
					length,
					digest,
				},
				metadata,
			},
		)
	}
}
