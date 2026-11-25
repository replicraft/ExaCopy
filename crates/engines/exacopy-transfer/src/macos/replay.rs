//! Read-only replay of the initial single-file preserve-mode journal on managed APFS.

use std::io::Read;
use std::num::NonZeroU32;

use ed25519_dalek::VerifyingKey;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReadError, FrameReader};
use exacopy_journal::{
	DarwinFileIdentity, DarwinOwnerRecord, DarwinReceiptCommitted, OwnerProfileId,
};

use super::plan::DarwinCopyPlan;
use super::receipt::{DarwinCopyReceipt, DarwinReceiptFrames};

mod error;
mod recovery;
mod validate;

#[cfg(test)]
pub(super) mod tests;

pub use error::DarwinReplayError;

const INITIAL_ORDER: [FrameKind; 9] = [
	FrameKind::JobPrepared,
	FrameKind::EntryPrepared,
	FrameKind::StageSealed,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::PublishIntent,
	FrameKind::PublishObserved,
	FrameKind::DurabilityRecorded,
	FrameKind::ReceiptCommitted,
];

/// Independently selected signing authority and the observed, authorized private job root.
#[derive(Clone, Copy, Debug)]
pub struct DarwinReplayAuthority<'key> {
	/// Profile selected from trusted recovery configuration.
	pub profile: OwnerProfileId,
	/// Verification key selected from the same trusted configuration.
	pub key: &'key VerifyingKey,
	/// Native identity of the independently reopened private job directory.
	pub state_root: DarwinFileIdentity,
	/// Non-root owner observed for that directory.
	pub state_root_uid: NonZeroU32,
}

/// The last accepted chain head and byte position in the first segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinJournalBoundary {
	/// Chain head after the last accepted frame, or the initial anchor.
	pub head: ChainHead,
	/// Segment-relative position immediately after the accepted bytes.
	pub offset: u64,
}

/// The way the first segment ended after the accepted prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinJournalTail {
	/// EOF at a frame boundary.
	Clean,
	/// EOF in a structurally plausible partial frame.
	Torn {
		/// Bytes consumed beyond the accepted boundary.
		bytes_read: usize,
	},
}

/// Historical classification of the original publication attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinReplayStatus {
	/// Preparation stopped before intent, or the adapter reported no rename attempt.
	Incomplete,
	/// The attempt recorded an incumbent at the destination.
	Conflict,
	/// An intent may have taken effect and needs fresh observation.
	Uncertain,
	/// An exclusive rename succeeded but further verification, barriers or commitment remained.
	PublishedIncomplete,
	/// The recorded history reached receipt commitment.
	Complete,
}

/// Accepted historical evidence for one managed APFS job and its first recovery generation.
#[derive(Debug)]
pub struct DarwinJournalReplay {
	frames: Vec<Frame>,
	boundary: DarwinJournalBoundary,
	tail: DarwinJournalTail,
	status: DarwinReplayStatus,
}

impl DarwinJournalReplay {
	/// Returns the validated frame boundary to preserve for reconciliation.
	#[must_use]
	pub const fn boundary(&self) -> DarwinJournalBoundary {
		self.boundary
	}

	/// Returns the integrity of the end of the supplied segment.
	#[must_use]
	pub const fn tail(&self) -> DarwinJournalTail {
		self.tail
	}

	/// Classifies the original publication independently of live names and artifacts.
	///
	/// Recovery records remain available through [`Self::frame`]. They describe prior
	/// reconciliation observations and leave the original attempt's status intact.
	#[must_use]
	pub const fn status(&self) -> DarwinReplayStatus {
		self.status
	}

	/// Returns the exact accepted frame of the selected kind, when present.
	#[must_use]
	pub fn frame(&self, kind: FrameKind) -> Option<&Frame> {
		self.frames.iter().find(|frame| frame.kind() == kind)
	}

	/// Checks a canonical receipt artifact against the accepted chain and the original plan.
	///
	/// # Errors
	/// Requires a committed receipt. Rejects incompatible bytes, observations or references.
	pub fn validate_receipt<'bytes>(
		&self,
		plan: &DarwinCopyPlan<'_>,
		bytes: &'bytes [u8],
	) -> Result<DarwinCopyReceipt<'bytes>, DarwinReplayError> {
		let [
			_,
			_,
			_,
			verification,
			metadata,
			intent,
			observed,
			durability,
			committed,
		] = self.frames.as_slice()
		else {
			return Err(DarwinReplayError::MissingReceiptCommitment);
		};
		if committed.kind() != FrameKind::ReceiptCommitted {
			return Err(DarwinReplayError::MissingReceiptCommitment);
		}
		let receipt = DarwinCopyReceipt::decode(bytes)?;
		DarwinReceiptCommitted::from_frame(committed)?
			.validate_evidence(durability, receipt.digest())?;
		receipt.validate_evidence(
			plan,
			DarwinReceiptFrames {
				verification,
				metadata,
				intent,
				observed,
				durability,
			},
		)?;
		Ok(receipt)
	}
}

/// Checks a single-file journal against a canonical plan and independently trusted owner.
///
/// The caller supplies a reader scoped to the held private job and observations of the
/// independently authorized directory. Each complete record must come from the same consecutive
/// frame chain and match its prerequisites. Any torn frame contributes only the tail length.
/// The supported recovery suffix consists of one recovery start after an eligible original
/// publication attempt and an optional decision immediately following it.
/// Replay issues no filesystem operations or authority. A recovery coordinator must independently
/// validate live objects, containment and receipt bytes before interpreting current state.
///
/// # Errors
/// Rejects invalid authority, incompatible plans or records, I/O errors, damaged frames,
/// sequence gaps, and any complete record outside the supported history.
pub fn replay_journal(
	reader: impl Read,
	plan: &DarwinCopyPlan<'_>,
	owner_bytes: &[u8],
	authority: DarwinReplayAuthority<'_>,
) -> Result<DarwinJournalReplay, DarwinReplayError> {
	let owner = DarwinOwnerRecord::decode(owner_bytes, authority.profile, authority.key)?;
	let expected_job = validate::expected_job(plan, &owner, authority)?;
	let (frames, boundary, tail) = read_prefix(reader)?;
	let recovery_start = frames
		.iter()
		.position(|frame| frame.kind() == FrameKind::RecoveryStarted)
		.unwrap_or(frames.len());
	let (original, recovery) = frames.split_at(recovery_start);
	let status = validate::history(original, expected_job, plan, &owner)?;
	recovery::validate(&owner, original, recovery)?;
	Ok(DarwinJournalReplay {
		frames,
		boundary,
		tail,
		status,
	})
}

fn read_prefix(
	reader: impl Read,
) -> Result<(Vec<Frame>, DarwinJournalBoundary, DarwinJournalTail), DarwinReplayError> {
	// At most eight original frames and two recovery frames, or a nine-frame initial history.
	let mut reader = FrameReader::new(reader, ChainHead::start());
	let mut frames = Vec::with_capacity(INITIAL_ORDER.len() + 1);
	let tail = loop {
		let frame = match reader.next_frame() {
			Ok(Some(frame)) => frame,
			Ok(None) => break DarwinJournalTail::Clean,
			Err(FrameReadError::TornTail { bytes_read, .. }) => {
				break DarwinJournalTail::Torn { bytes_read };
			}
			Err(error) => return Err(DarwinReplayError::Frame(error)),
		};
		let preceding = frames.last().map(Frame::kind);
		let expected = match preceding {
			Some(FrameKind::RecoveryStarted) => Some(FrameKind::RecoveryDecision),
			Some(FrameKind::RecoveryDecision) => None,
			_ => INITIAL_ORDER.get(frames.len()).copied(),
		};
		let starts_recovery = frame.kind() == FrameKind::RecoveryStarted
			&& matches!(
				preceding,
				Some(
					FrameKind::PublishIntent
						| FrameKind::PublishObserved
						| FrameKind::DurabilityRecorded
				)
			);
		if Some(frame.kind()) != expected && !starts_recovery {
			return Err(DarwinReplayError::UnexpectedRecord {
				expected,
				found: frame.kind(),
			});
		}
		let sequence = frame.head().sequence();
		if usize::try_from(sequence).ok() != Some(frames.len() + 1) {
			return Err(DarwinReplayError::NonconsecutiveSequence { sequence });
		}
		frames.push(frame);
	};
	let boundary = DarwinJournalBoundary {
		head: reader.head(),
		offset: reader.offset(),
	};
	Ok((frames, boundary, tail))
}
