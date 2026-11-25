use minicbor::Decoder;

use super::super::binding::{read_reference, require_before, write_reference};
use super::super::{DarwinNamespaceObservation, DarwinPublicationNames};
use super::{DarwinRecoveryHistory, DarwinRecoveryStarted, require_successor};
use crate::darwin_phases::codec::{decode_record, encode_record, expect_code, frame_payload};
use crate::darwin_prepared::wire::{
	read_entry_header, read_identity, write_header, write_identity,
};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map};
use crate::{
	DarwinFileIdentity, DarwinMetadataRecorded, DarwinPhaseBinding, DarwinPhaseError,
	DarwinRequiredMetadata, DarwinStreamEvidence, DarwinVerificationRecorded,
};

const KIND: FrameKind = FrameKind::RecoveryDecision;
const COMPLETE_PUBLISHED_RECEIPT: u64 = 1;
const PRIVATE_STAGE_ABSENT: u64 = 0;
const BLAKE3_256_READBACK: u64 = 1;
const STRICT_BASIC_APFS_METADATA: u64 = 1;

/// Fresh managed APFS observations made while holding the reconciled names and target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublishedRecoveryEvidence {
	/// Observations of the original stage name and public target, under their respective parents.
	pub names: DarwinPublicationNames,
	/// Held private stage directory in which the original stage name was absent.
	pub stage_directory: DarwinFileIdentity,
	/// Held public directory containing the observed target.
	pub destination_directory: DarwinFileIdentity,
	/// BLAKE3-256 of the exact public target stream read to EOF in this recovery generation.
	pub stream: DarwinStreamEvidence,
	/// Strict metadata observed on the held public target after read-back.
	pub metadata: DarwinRequiredMetadata,
}

/// Historical and recovery frames from the independently authenticated journal chain.
#[derive(Clone, Copy, Debug)]
pub struct DarwinRecoveryDecisionFrames<'a> {
	/// Exact kind 19 immediately following the original attempt.
	pub started: &'a Frame,
	/// The original accepted history cited by kind 19.
	pub history: DarwinRecoveryHistory<'a>,
}

/// Managed APFS kind 20 records fresh evidence for completing an already-published copy.
///
/// The sole decision is to complete barriers and a receipt for the original effect.
/// This record confers no filesystem authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinRecoveryDecision {
	binding: DarwinPhaseBinding,
	started: ChainHead,
	verification: ChainHead,
	metadata: ChainHead,
	evidence: DarwinPublishedRecoveryEvidence,
}

impl DarwinRecoveryDecision {
	/// Binds current observations to the originals in the accepted journal.
	///
	/// The coordinator holds the authorized private job and destination, verifies that
	/// both names stayed stable through read-back, and checks the target's mode, UID,
	/// GID, atime and mtime after read-back. The strict profile requires absence of
	/// visible xattrs, resource forks, nonempty effective ACLs and BSD flags.
	///
	/// # Errors
	/// Rejects inconsistent names, identities, frame bindings, streams or required metadata.
	pub fn new(
		frames: DarwinRecoveryDecisionFrames<'_>,
		evidence: DarwinPublishedRecoveryEvidence,
	) -> Result<Self, DarwinPhaseError> {
		let started = DarwinRecoveryStarted::from_frame(frames.started)?;
		let history = frames.history;
		let intent = started.validate_history(history)?;
		let verification = DarwinVerificationRecorded::from_frame(history.verification)?;
		let metadata = DarwinMetadataRecorded::from_frame(history.metadata)?;
		check_observation(evidence)?;
		let target = intent.target();
		if evidence.stream.identity != target.stage
			|| evidence.stage_directory != target.stage_directory
			|| evidence.destination_directory != target.parent
		{
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		if evidence.stream != verification.stage() {
			return Err(DarwinPhaseError::StreamMismatch);
		}
		if evidence.metadata != metadata.metadata() {
			return Err(DarwinPhaseError::MetadataMismatch);
		}
		Ok(Self {
			binding: started.binding(),
			started: frames.started.head(),
			verification: history.verification.head(),
			metadata: history.metadata.head(),
			evidence,
		})
	}

	/// Returns the binding in the recovery epoch.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the exact kind-19 frame reference.
	#[must_use]
	pub const fn started(&self) -> ChainHead {
		self.started
	}

	/// Returns the exact original kind-5 frame reference.
	#[must_use]
	pub const fn verification(&self) -> ChainHead {
		self.verification
	}

	/// Returns the exact original kind-6 frame reference.
	#[must_use]
	pub const fn metadata(&self) -> ChainHead {
		self.metadata
	}

	/// Returns recorded read-back and name observations from this recovery epoch.
	#[must_use]
	pub const fn evidence(&self) -> DarwinPublishedRecoveryEvidence {
		self.evidence
	}

	/// Encodes kind 20 as deterministic managed APFS v2 CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			write_header(encoder, self.binding.context, Some(self.binding.entry))?;
			encoder.map(7)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder.u8(1)?.u64(COMPLETE_PUBLISHED_RECEIPT)?.u8(2)?;
			write_reference(encoder, self.started)?;
			encoder.u8(3)?;
			write_reference(encoder, self.verification)?;
			encoder.u8(4)?;
			write_reference(encoder, self.metadata)?;
			encoder
				.u8(5)?
				.map(7)?
				.u8(0)?
				.u64(PRIVATE_STAGE_ABSENT)?
				.u8(1)?;
			write_identity(encoder, self.evidence.stage_directory)?;
			encoder.u8(2)?;
			write_identity(encoder, self.evidence.destination_directory)?;
			encoder.u8(3)?.u64(BLAKE3_256_READBACK)?.u8(4)?;
			self.evidence.stream.write(encoder)?;
			encoder.u8(5)?.u64(STRICT_BASIC_APFS_METADATA)?.u8(6)?;
			self.evidence.metadata.write(encoder)?;
			encoder.u8(6)?.null()?;
			Ok(())
		})
	}

	/// Decodes one complete canonical managed APFS kind-20 payload.
	///
	/// # Errors
	/// Rejects malformed, unsupported, or contradictory recorded evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the kind-20 envelope and verifies its exact kind-19 predecessor.
	///
	/// # Errors
	/// Rejects incompatible payloads, wrong kinds, or a mismatched predecessor.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		let record = Self::decode(frame_payload(frame, KIND)?)?;
		require_successor(record.started, frame)?;
		Ok(record)
	}

	/// Checks the historical decision against the accepted chain.
	///
	/// Filesystem reconciliation still requires fresh live observations.
	///
	/// # Errors
	/// Rejects differences from the accepted original and recovery records.
	pub fn validate_evidence(
		&self,
		frames: DarwinRecoveryDecisionFrames<'_>,
	) -> Result<(), DarwinPhaseError> {
		if *self != Self::new(frames, self.evidence)? {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let (context, entry) = read_entry_header(decoder)?;
		expect_map(decoder, 7)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, entry)?;
		expect_key(decoder, 1)?;
		expect_code(decoder, COMPLETE_PUBLISHED_RECEIPT)?;
		expect_key(decoder, 2)?;
		let started = read_reference(decoder)?;
		expect_key(decoder, 3)?;
		let verification = read_reference(decoder)?;
		expect_key(decoder, 4)?;
		let metadata = read_reference(decoder)?;
		require_before(verification, metadata)?;
		require_before(metadata, started)?;
		expect_key(decoder, 5)?;
		let evidence = read_evidence(decoder)?;
		expect_key(decoder, 6)?;
		decoder.null()?;
		Ok(Self {
			binding,
			started,
			verification,
			metadata,
			evidence,
		})
	}
}

fn read_evidence(
	decoder: &mut Decoder<'_>,
) -> Result<DarwinPublishedRecoveryEvidence, DarwinPhaseError> {
	expect_map(decoder, 7)?;
	expect_key(decoder, 0)?;
	expect_code(decoder, PRIVATE_STAGE_ABSENT)?;
	expect_key(decoder, 1)?;
	let stage_directory = read_identity(decoder)?;
	expect_key(decoder, 2)?;
	let destination_directory = read_identity(decoder)?;
	expect_key(decoder, 3)?;
	expect_code(decoder, BLAKE3_256_READBACK)?;
	expect_key(decoder, 4)?;
	let stream = DarwinStreamEvidence::read(decoder)?;
	expect_key(decoder, 5)?;
	expect_code(decoder, STRICT_BASIC_APFS_METADATA)?;
	expect_key(decoder, 6)?;
	let metadata = DarwinRequiredMetadata::read(decoder)?;
	let evidence = DarwinPublishedRecoveryEvidence {
		names: DarwinPublicationNames {
			target: DarwinNamespaceObservation::Present(stream.identity),
			stage: DarwinNamespaceObservation::Absent,
		},
		stage_directory,
		destination_directory,
		stream,
		metadata,
	};
	check_observation(evidence)?;
	Ok(evidence)
}

fn check_observation(evidence: DarwinPublishedRecoveryEvidence) -> Result<(), DarwinPhaseError> {
	let target = evidence.stream.identity;
	if evidence.names.stage != DarwinNamespaceObservation::Absent
		|| evidence.names.target != DarwinNamespaceObservation::Present(target)
	{
		return Err(DarwinPhaseError::InconsistentObservation);
	}
	if target.volume() != evidence.stage_directory.volume()
		|| target.volume() != evidence.destination_directory.volume()
	{
		return Err(DarwinPhaseError::VolumeMismatch);
	}
	if target.may_alias(evidence.stage_directory)
		|| target.may_alias(evidence.destination_directory)
		|| evidence
			.stage_directory
			.may_alias(evidence.destination_directory)
	{
		return Err(DarwinPhaseError::AliasedIdentity);
	}
	Ok(())
}
