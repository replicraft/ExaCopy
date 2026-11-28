use std::fmt;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReadError, FrameReader};
use exacopy_journal::{
	ApplyQualification, BasicMetadata, DurabilityRecorded, LinuxFileIdentity,
	LinuxPublicationBarriers, MetadataRecorded, OwnerTimestamp, PublicApplyAssociation,
	PublicApplyIntent, PublicApplyIntentError, PublicationOutcome, PublicationRecordError,
	PublishObserved, ReceiptCommitted, VerificationRecordError, VerificationRecorded,
};

use super::{PublicApplyReceipt, PublicApplyReceiptError};
use crate::linux::receipt::ReceiptEvidence;

#[cfg(test)]
mod tests;

// Five bounded 256-byte phase bodies, one bounded v2 intent, and six frame envelopes
// fit within this limit. Read one extra byte to distinguish exact EOF from the cap.
const MAX_COMMIT_SUFFIX_BYTES: u64 = 4096;

/// Facts selected independently of the candidate journal suffix and receipt.
///
/// The caller authenticates the owner, associates the approved Plan, and verifies
/// the actual prefix through the seal and the provenance of these expectations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicApplyCommitSelection<'name> {
	/// Accepted boundary of the exact preceding StageSealed frame.
	pub seal: ChainHead,
	/// Selected signed owner and exact approved public Plan and entry.
	pub association: PublicApplyAssociation,
	/// Exact recorded profile and environment from independently selected evidence.
	pub qualification: ApplyQualification,
	/// Exact expected receipt context, roots, raw name and measured file facts.
	pub copy: ReceiptEvidence<'name>,
	/// Read-back required metadata selected by the caller.
	pub metadata: BasicMetadata,
	/// Private stage directory identity within the selected job.
	pub stage_directory: LinuxFileIdentity,
	/// Creation time from the selected authenticated owner.
	pub owner_created: OwnerTimestamp,
	/// Original exclusive expiry bound to the selected public Plan, if specified.
	pub expires_at: Option<OwnerTimestamp>,
}

/// Why a v2 public-apply commit did not match a bounded journal suffix.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicApplyCommitError {
	/// The separately accepted seal is not a noninitial chain boundary.
	MissingSeal,
	/// The framed suffix is malformed, damaged, torn, or unavailable.
	Envelope(FrameReadError),
	/// The stream ended before this required phase.
	Missing(FrameKind),
	/// The required phase was skipped or substituted.
	Order(FrameKind),
	/// Supplied receipt bytes fail the mandatory canonical decoder.
	Receipt(PublicApplyReceiptError),
	/// An independently checked stage verification or metadata payload was refused.
	Verification(VerificationRecordError),
	/// The required v2 intent or its frame association was refused.
	Intent(PublicApplyIntentError),
	/// A canonical publication, barrier, or receipt commitment was refused.
	Publication(PublicationRecordError),
	/// A phase or receipt disagrees with the selected scope or another accepted phase.
	Binding,
	/// The commit is followed by bytes or exceeds the bounded suffix.
	TrailingOrOversize,
	/// A reliable terminal byte probe could not be made.
	TerminalProbe(io::Error),
}

impl fmt::Display for PublicApplyCommitError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MissingSeal => {
				formatter.write_str("public apply commit requires an accepted seal")
			}
			Self::Envelope(error) => {
				write!(formatter, "public apply journal envelope refused ({error})")
			}
			Self::Missing(kind) => write!(formatter, "public apply journal lacks {kind:?}"),
			Self::Order(kind) => write!(
				formatter,
				"public apply journal expected consecutive {kind:?}"
			),
			Self::Receipt(error) => write!(formatter, "public apply receipt refused ({error})"),
			Self::Verification(error) => {
				write!(formatter, "public apply seal evidence refused ({error})")
			}
			Self::Intent(error) => write!(formatter, "public apply intent refused ({error})"),
			Self::Publication(error) => write!(
				formatter,
				"public apply publication records refused ({error})"
			),
			Self::Binding => formatter
				.write_str("public apply commit evidence disagrees with the selected facts"),
			Self::TrailingOrOversize => {
				formatter.write_str("public apply commit suffix exceeds its boundary")
			}
			Self::TerminalProbe(error) => {
				write!(formatter, "public apply journal EOF check failed ({error})")
			}
		}
	}
}

impl std::error::Error for PublicApplyCommitError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Envelope(error) => Some(error),
			Self::Receipt(error) => Some(error),
			Self::Verification(error) => Some(error),
			Self::Intent(error) => Some(error),
			Self::Publication(error) => Some(error),
			Self::TerminalProbe(error) => Some(error),
			_ => None,
		}
	}
}

impl PublicApplyReceipt<'_> {
	/// Validates exactly one committed v2 apply suffix and this canonical receipt.
	///
	/// Supply the stream immediately after the independently accepted kind-4 seal.
	/// It must contain consecutive kinds 5, 6, 7, 8, 9 and 18, followed by EOF.
	/// The method checks framed records against each other and the selected facts.
	/// The supplied reader must return from each individual read call. Interrupted
	/// reads share one retry budget across the entire suffix and final EOF probe.
	/// Owner authentication, live qualification, native receipt identity and proof
	/// that those bytes reach actual artifact EOF, and physical journal custody remain
	/// the caller's responsibility.
	/// # Errors
	/// Refuses an unselected or incomplete suffix, a legacy intent, tampered records,
	/// a nonpublished outcome, or a receipt inconsistent with the exact commit.
	pub fn validate_commit(
		input: impl Read,
		receipt_bytes: &[u8],
		selected: PublicApplyCommitSelection<'_>,
	) -> Result<(), PublicApplyCommitError> {
		Self::validate_commit_boundary(input, receipt_bytes, selected).map(|_| ())
	}

	pub(in crate::linux) fn validate_commit_boundary(
		input: impl Read,
		receipt_bytes: &[u8],
		selected: PublicApplyCommitSelection<'_>,
	) -> Result<ChainHead, PublicApplyCommitError> {
		use PublicApplyCommitError as Error;

		if selected.seal == ChainHead::start() {
			return Err(Error::MissingSeal);
		}
		let receipt = PublicApplyReceipt::decode(receipt_bytes).map_err(Error::Receipt)?;
		if receipt.association() != selected.association
			|| receipt.private().evidence() != selected.copy
			|| selected.copy.source == selected.copy.destination.identity
		{
			return Err(Error::Binding);
		}
		let mut input = InterruptBudget {
			input: input.take(MAX_COMMIT_SUFFIX_BYTES + 1),
			retries_left: MAX_INTERRUPTED_RETRIES,
		};
		let mut reader = FrameReader::new(&mut input, selected.seal);
		let verification = required(&mut reader, FrameKind::VerificationRecorded)?;
		let metadata = required(&mut reader, FrameKind::MetadataRecorded)?;
		let intent = required(&mut reader, FrameKind::PublishIntent)?;
		let proposal = PublicApplyIntent::from_frame(&intent).map_err(Error::Intent)?;
		check_seal_records(&verification, &metadata, &proposal, selected)?;
		if !receipt.matches_intent(intent.head(), &proposal) {
			return Err(Error::Binding);
		}

		let observed_frame = required(&mut reader, FrameKind::PublishObserved)?;
		let observed = PublishObserved::from_frame(&observed_frame).map_err(Error::Publication)?;
		let context = proposal.private().context;
		let target = selected.copy.stream.identity;
		if observed.context() != context
			|| observed.intent() != intent.head()
			|| observed.outcome() != (PublicationOutcome::Published { target })
		{
			return Err(Error::Binding);
		}
		let durability_frame = required(&mut reader, FrameKind::DurabilityRecorded)?;
		let durability =
			DurabilityRecorded::from_frame(&durability_frame).map_err(Error::Publication)?;
		if durability.context() != context
			|| durability.observed() != observed_frame.head()
			|| durability.barriers()
				!= (LinuxPublicationBarriers {
					metadata: metadata.head(),
					stage_directory: selected.stage_directory,
					destination_directory: selected.copy.destination.identity,
				})
			|| selected.stage_directory == target
			|| selected.stage_directory == selected.copy.source
			|| receipt.private().durability_frame() != durability_frame.head()
		{
			return Err(Error::Binding);
		}

		let committed = required(&mut reader, FrameKind::ReceiptCommitted)?;
		let record = ReceiptCommitted::from_frame(&committed).map_err(Error::Publication)?;
		record
			.validate_evidence(&durability_frame, receipt.digest())
			.map_err(Error::Publication)?;
		if reader.offset() > MAX_COMMIT_SUFFIX_BYTES {
			return Err(Error::TrailingOrOversize);
		}
		check_eof(&mut input)?;
		Ok(committed.head())
	}
}

fn check_seal_records(
	verification: &Frame,
	metadata: &Frame,
	intent: &PublicApplyIntent<'_>,
	selected: PublicApplyCommitSelection<'_>,
) -> Result<(), PublicApplyCommitError> {
	use PublicApplyCommitError as Error;

	let proof = VerificationRecorded::from_frame(verification).map_err(Error::Verification)?;
	let record = MetadataRecorded::from_frame(metadata).map_err(Error::Verification)?;
	let operation = intent.private();
	let claims = intent.evidence();
	let expected = selected.copy;
	let time = |time: OwnerTimestamp| (time.seconds(), time.nanoseconds());
	let intent_time = time(claims.intent_time);
	if claims.verification != verification.head()
		|| claims.metadata != metadata.head()
		|| claims.qualification != selected.qualification
		|| intent_time < time(selected.owner_created)
		|| selected
			.expires_at
			.is_some_and(|expiry| intent_time >= time(expiry))
		|| proof.context != expected.context
		|| proof.entry != expected.entry
		|| expected.source.device() != selected.qualification.environment.device
		|| proof.source().identity != expected.source
		|| proof.stage() != expected.stream
		|| proof.record_digest() != operation.target.verification_digest
		|| record.context != expected.context
		|| record.entry != expected.entry
		|| record.stage != expected.stream.identity
		|| record.metadata != selected.metadata
	{
		return Err(Error::Binding);
	}
	Ok(())
}

fn required(
	reader: &mut FrameReader<impl Read>,
	kind: FrameKind,
) -> Result<Frame, PublicApplyCommitError> {
	let preceding = reader.head();
	let frame = reader
		.next_frame()
		.map_err(PublicApplyCommitError::Envelope)?
		.ok_or(PublicApplyCommitError::Missing(kind))?;
	if frame.kind() != kind || preceding.sequence().checked_add(1) != Some(frame.head().sequence())
	{
		return Err(PublicApplyCommitError::Order(kind));
	}
	Ok(frame)
}

fn check_eof(input: &mut impl Read) -> Result<(), PublicApplyCommitError> {
	loop {
		match input.read(&mut [0]) {
			Ok(0) => return Ok(()),
			Ok(_) => return Err(PublicApplyCommitError::TrailingOrOversize),
			Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
			Err(error) => return Err(PublicApplyCommitError::TerminalProbe(error)),
		}
	}
}

struct InterruptBudget<R> {
	input: R,
	retries_left: u8,
}

impl<R: Read> Read for InterruptBudget<R> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		match self.input.read(output) {
			Err(error) if error.kind() == io::ErrorKind::Interrupted => {
				// FrameReader and the terminal probe both retry Interrupted. Turn
				// exhaustion into a nonretryable error while preserving its cause.
				let Some(left) = self.retries_left.checked_sub(1) else {
					return Err(io::Error::other(error));
				};
				self.retries_left = left;
				Err(error)
			}
			result => result,
		}
	}
}
