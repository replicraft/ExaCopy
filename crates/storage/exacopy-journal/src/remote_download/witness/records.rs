//! Canonical selector-2 phase declarations and exact enclosing-frame checks.
//!
//! These declarations describe historical data. An authoritative scanner must
//! resolve their phase anchors and compare the recorded facts to the selected
//! history. Native custody, current consent and authority are separate.

use minicbor::Decoder;

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::remote_download::finalization::{RemoteLocalMetadata, RemotePublishTarget};
use crate::remote_download::replay::RemoteReplayBoundary;
use crate::{LinuxFileIdentity, NamespaceObservation, StreamDigest, StreamLength};

use super::{Error, RemoteWitnessBinding, check_successor, successor_end, wire};

mod body;

const MAX_PHASE_PAYLOAD: usize = 922;

/// Canonical witnessed-publication observation. Only one outcome can be recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteWitnessedOutcome {
	/// A submitted exclusive rename was observed with the intended target and witness.
	Submitted(LinuxFileIdentity),
	/// The native exclusive operation refused an incumbent.
	Conflict,
	/// The result was uncertain. Retain each namespace observation as recorded.
	Uncertain {
		/// Public target observation.
		target: NamespaceObservation,
		/// Private stage observation.
		stage: NamespaceObservation,
		/// Protected job witness observation.
		witness: NamespaceObservation,
	},
	/// Recovery independently verified the public inode and exact retained witness.
	Recovered {
		/// Observed public inode.
		target: LinuxFileIdentity,
		/// Actual earlier signed intent for the protected witness.
		witness: ChainHead,
	},
}

/// Historical witness presence retained across a pre-publication retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteRetainedWitness {
	/// No witness intent existed and the witness was observed absent.
	NoIntent,
	/// An intent existed but the witness was observed absent.
	AbsentAfterIntent(ChainHead),
	/// The exact declared witness was observed and retained.
	Preserved {
		/// Exact intent for the protected witness.
		intent: ChainHead,
		/// Protected job directory.
		job_directory: LinuxFileIdentity,
		/// Exact raw witness basename including its fixed prefix.
		name: [u8; 40],
	},
}

/// Recorded reason for preserving this attempt and selecting a fresh pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteWitnessRetirementReason {
	/// A fresh pass was explicitly selected.
	FreshSelection,
	/// Bounded retained reuse was refused before intent.
	RetainedReuseRefused,
}

/// Phase-specific assertions in the selector-2 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteWitnessCloseoutBody<'name> {
	/// The joined stage and protected witness were sealed as the only two links.
	Seal {
		/// Recorded private stage directory.
		directory: LinuxFileIdentity,
		/// Exact logical length of the observed stage.
		extent: StreamLength,
		/// Exact earlier signed witness intent.
		witness: ChainHead,
		/// Recorded protected job directory.
		job_directory: LinuxFileIdentity,
		/// Exact raw protected witness name.
		name: [u8; 40],
	},
	/// Independent whole-stream read-back matched the captured source bytes.
	Verify {
		/// Exact logical length of the observed stage.
		extent: StreamLength,
		/// Whole BLAKE3 digest of the selected source.
		source: StreamDigest,
		/// Whole BLAKE3 digest from independent stage read-back.
		stage: StreamDigest,
	},
	/// The fixed data-only policy was observed with exact local metadata.
	Metadata(RemoteLocalMetadata),
	/// One exclusive no-replace rename was intended.
	Intent {
		/// Exact earlier witnessed seal.
		seal: ChainHead,
		/// Exact earlier independently measured verification frame.
		verification: ChainHead,
		/// Exact earlier signed witness intent.
		witness: ChainHead,
		/// Recorded private stage directory.
		directory: LinuxFileIdentity,
		/// Exact recorded target root, parent and basename.
		target: RemotePublishTarget<'name>,
		/// Exact selected historical witness qualification digest.
		qualification: [u8; 32],
		/// Exact selected archived base-grant digest.
		grant: [u8; 32],
	},
	/// The exact one-shot rename submission or independent recovery was observed.
	Observed(RemoteWitnessedOutcome),
	/// The file and all three required directory barriers succeeded.
	Durability {
		/// Exact earlier selected policy and local metadata frame.
		metadata: ChainHead,
		/// Recorded private stage directory.
		directory: LinuxFileIdentity,
		/// Recorded public target parent.
		target_parent: LinuxFileIdentity,
		/// Recorded protected job directory.
		job_directory: LinuxFileIdentity,
		/// Exact selected historical witness qualification digest.
		qualification: [u8; 32],
	},
	/// The selected final receipt completed exclusive promotion and barriers.
	CommittedReceipt {
		/// Domain-separated digest over exact canonical receipt bytes.
		digest: [u8; 32],
		/// Recorded exact sealed receipt inode.
		inode: LinuxFileIdentity,
	},
	/// Pre-intent retirement preserved the stage and any exact protected witness.
	Retire {
		/// Recorded private stage directory.
		directory: LinuxFileIdentity,
		/// Exact recorded target root, parent and basename.
		target: RemotePublishTarget<'name>,
		/// Exact selected historical witness qualification digest.
		qualification: [u8; 32],
		/// Exact selected archived base-grant digest.
		grant: [u8; 32],
		/// The recorded selection reason.
		reason: RemoteWitnessRetirementReason,
		/// Recorded witness preservation facts.
		retained: RemoteRetainedWitness,
	},
}

impl RemoteWitnessCloseoutBody<'_> {
	/// Returns the exact enclosing frame type.
	#[must_use]
	pub const fn kind(self) -> FrameKind {
		match self {
			Self::Seal { .. } => FrameKind::StageSealed,
			Self::Verify { .. } => FrameKind::VerificationRecorded,
			Self::Metadata(_) => FrameKind::MetadataRecorded,
			Self::Intent { .. } => FrameKind::PublishIntent,
			Self::Observed(_) => FrameKind::PublishObserved,
			Self::Durability { .. } => FrameKind::DurabilityRecorded,
			Self::CommittedReceipt { .. } => FrameKind::ReceiptCommitted,
			Self::Retire { .. } => FrameKind::RemoteCaptureRetired,
		}
	}
}

/// Canonical, bounded selector-2 record matching an independently resolved binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteWitnessCloseoutRecord<'frame> {
	binding: RemoteWitnessBinding,
	previous: RemoteReplayBoundary,
	body: RemoteWitnessCloseoutBody<'frame>,
}

impl<'frame> RemoteWitnessCloseoutRecord<'frame> {
	pub(super) const fn new(
		binding: RemoteWitnessBinding,
		previous: RemoteReplayBoundary,
		body: RemoteWitnessCloseoutBody<'frame>,
	) -> Self {
		Self {
			binding,
			previous,
			body,
		}
	}

	/// Returns the selected profile's exact payload ceiling for this kind.
	#[must_use]
	pub const fn payload_cap(kind: FrameKind) -> Option<usize> {
		Some(match kind {
			FrameKind::StageSealed => 543,
			FrameKind::VerificationRecorded => 475,
			FrameKind::MetadataRecorded => 454,
			FrameKind::PublishIntent => MAX_PHASE_PAYLOAD,
			FrameKind::PublishObserved => 476,
			FrameKind::DurabilityRecorded => 551,
			FrameKind::ReceiptCommitted => 455,
			FrameKind::RemoteCaptureRetired => 905,
			_ => return None,
		})
	}

	/// Matches an actual frame to the exact selected historical context.
	///
	/// # Errors
	/// Refuses noncanonical records, unknown shapes, caps and incorrect frame links.
	pub fn from_frame(
		frame: &'frame Frame,
		end: RemoteReplayBoundary,
		binding: RemoteWitnessBinding,
		previous: RemoteReplayBoundary,
	) -> Result<Self, Error> {
		let kind = frame.kind();
		let cap = Self::payload_cap(kind).ok_or(Error::UnsupportedVersion)?;
		if frame.payload().len() > cap {
			return Err(Error::Length);
		}
		check_successor(frame, kind, previous, end)?;
		let mut decoder = wire::selected_body(frame.payload(), binding, previous.head, kind)?;
		let body = body::read(kind, &mut decoder)?;
		let record = Self::new(binding, previous, body);
		if decoder.position() != decoder.input().len() || record.encode()? != frame.payload() {
			return Err(Error::NonCanonical);
		}
		Ok(record)
	}

	/// Returns the bounded recorded phase below the exact common binding.
	#[must_use]
	pub const fn body(self) -> RemoteWitnessCloseoutBody<'frame> {
		self.body
	}

	/// Returns the complete canonical bytes for this recorded phase.
	///
	/// # Errors
	/// Refuses a representation exceeding its selected phase limit.
	pub fn encode(self) -> Result<Vec<u8>, Error> {
		let kind = self.body.kind();
		let mut output = wire::encoder::<MAX_PHASE_PAYLOAD>();
		wire::common(&mut output, self.binding, self.previous.head, kind)?;
		body::write(&mut output, self.body)?;
		let payload = wire::finish(output);
		if payload.len() > Self::payload_cap(kind).ok_or(Error::UnsupportedVersion)? {
			return Err(Error::Length);
		}
		successor_end(self.previous, payload.len())?;
		Ok(payload)
	}
}

fn native(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, Error> {
	let identity = crate::remote_download::wire::read_identity(decoder)?;
	if identity.inode() == 0 {
		return Err(Error::Binding);
	}
	Ok(identity)
}
