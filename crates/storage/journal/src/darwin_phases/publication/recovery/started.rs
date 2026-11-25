use std::num::NonZeroU64;

use minicbor::Decoder;

use super::super::binding::{read_reference, require_before, write_reference};
use super::super::{DarwinDurabilityRecorded, DarwinPublicationOutcome, DarwinPublishObserved};
use super::require_successor;
use crate::darwin_phases::codec::{decode_record, encode_record, frame_payload};
use crate::darwin_prepared::wire::{read_entry_header, write_header};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map};
use crate::{
	DarwinEntryPrepared, DarwinJobPrepared, DarwinMetadataRecorded, DarwinOwnerRecord,
	DarwinPhaseBinding, DarwinPhaseError, DarwinPublishIntent, DarwinStageSealed,
	DarwinVerificationRecorded, JournalEpoch,
};

const KIND: FrameKind = FrameKind::RecoveryStarted;

/// Authenticated and replay-accepted original evidence for the initial recovery generation.
#[derive(Clone, Copy, Debug)]
pub struct DarwinRecoveryHistory<'a> {
	/// Owner decoded with the independently trusted profile and verification key.
	pub owner: &'a DarwinOwnerRecord,
	/// Kind 1 from the accepted chain, checked against the canonical plan and held job root.
	pub job: &'a Frame,
	/// Kind 2 from that chain, checked against the source and destination in the plan.
	pub entry: &'a Frame,
	/// Original kind 4 recording the quiescent, synchronized stage.
	pub seal: &'a Frame,
	/// Original kind 5 recording source and independent stage measurements.
	pub verification: &'a Frame,
	/// Original kind 6 recording the checked required metadata.
	pub metadata: &'a Frame,
	/// Original kind 7 with verified prerequisites.
	pub intent: &'a Frame,
	/// Exact kind 8 required when the original attempt ends at kind 9.
	pub observed_before_durability: Option<&'a Frame>,
	/// Last accepted frame from the original publication attempt.
	pub preceding: &'a Frame,
}

/// Managed APFS kind 19 starts reconciliation of the original publication in a fresh epoch.
///
/// This payload associates an epoch and exact accepted prefix. It conveys no permission
/// to rename, write a public file, or retire a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinRecoveryStarted {
	binding: DarwinPhaseBinding,
	prior_epoch: JournalEpoch,
	intent: ChainHead,
	preceding: ChainHead,
}

impl DarwinRecoveryStarted {
	/// Binds the first post-intent recovery generation to an accepted original history.
	///
	/// The caller checks that these frames are the current accepted chain, checks the canonical
	/// plan, independently authenticates the owner, and validates held roots and their
	/// authorization. Supply the exact terminal frame, which can be kind 7, a potentially
	/// successful initial kind 8, or initial kind 9 with its original successful kind 8.
	///
	/// # Errors
	/// Rejects unrelated or unsupported history, a mismatched owner, and epoch exhaustion.
	pub fn new(history: DarwinRecoveryHistory<'_>) -> Result<Self, DarwinPhaseError> {
		let intent = history.validate_intent()?;
		Self::from_accepted_intent(history, intent)
	}

	fn from_accepted_intent(
		history: DarwinRecoveryHistory<'_>,
		intent: DarwinPublishIntent<'_>,
	) -> Result<Self, DarwinPhaseError> {
		check_preceding(history)?;
		let mut binding = intent.binding();
		let prior_epoch = binding.context.epoch;
		binding.context.epoch = JournalEpoch::new(
			prior_epoch
				.get()
				.checked_add(1)
				.ok_or(DarwinPhaseError::InvalidRecoveryEpoch)?,
		);
		Ok(Self {
			binding,
			prior_epoch,
			intent: history.intent.head(),
			preceding: history.preceding.head(),
		})
	}

	/// Returns the original job, plan, entry, owner and stage with the fresh recovery epoch.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the original publication epoch.
	#[must_use]
	pub const fn prior_epoch(&self) -> JournalEpoch {
		self.prior_epoch
	}

	/// Returns the exact original kind-7 frame reference.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.intent
	}

	/// Returns the exact last accepted original frame.
	#[must_use]
	pub const fn preceding(&self) -> ChainHead {
		self.preceding
	}

	/// Encodes kind 19 as deterministic managed APFS v2 CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			write_header(encoder, self.binding.context, Some(self.binding.entry))?;
			encoder.map(4)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder.u8(1)?.u64(self.prior_epoch.get())?.u8(2)?;
			write_reference(encoder, self.intent)?;
			encoder.u8(3)?;
			write_reference(encoder, self.preceding)
		})
	}

	/// Decodes a complete canonical managed APFS kind-19 payload.
	///
	/// # Errors
	/// Rejects incompatible, malformed, or inconsistent evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the kind-19 envelope and the exact immediate predecessor.
	///
	/// # Errors
	/// Rejects incompatible payloads, wrong kinds, or a mismatched predecessor.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		let record = Self::decode(frame_payload(frame, KIND)?)?;
		require_successor(record.preceding, frame)?;
		Ok(record)
	}

	/// Checks decoded recovery evidence against the independently accepted original history.
	///
	/// # Errors
	/// Rejects differences from the accepted observations, original intent, or owner.
	pub fn validate_evidence(
		&self,
		history: DarwinRecoveryHistory<'_>,
	) -> Result<(), DarwinPhaseError> {
		self.validate_history(history).map(|_| ())
	}

	pub(super) fn validate_history<'a>(
		&self,
		history: DarwinRecoveryHistory<'a>,
	) -> Result<DarwinPublishIntent<'a>, DarwinPhaseError> {
		let intent = history.validate_intent()?;
		if *self != Self::from_accepted_intent(history, intent)? {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		Ok(intent)
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let (context, entry) = read_entry_header(decoder)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, entry)?;
		expect_key(decoder, 1)?;
		let prior_epoch = JournalEpoch::new(decoder.u64()?);
		if prior_epoch.get().checked_add(1) != Some(context.epoch.get()) {
			return Err(DarwinPhaseError::InvalidRecoveryEpoch);
		}
		expect_key(decoder, 2)?;
		let intent = read_reference(decoder)?;
		expect_key(decoder, 3)?;
		let preceding = read_reference(decoder)?;
		if intent != preceding {
			require_before(intent, preceding)?;
			if preceding.sequence() - intent.sequence() > 2 {
				return Err(DarwinPhaseError::InvalidFrameOrder);
			}
		}
		Ok(Self {
			binding,
			prior_epoch,
			intent,
			preceding,
		})
	}
}

impl<'a> DarwinRecoveryHistory<'a> {
	fn validate_intent(self) -> Result<DarwinPublishIntent<'a>, DarwinPhaseError> {
		let mut prior = ChainHead::start();
		for frame in [
			self.job,
			self.entry,
			self.seal,
			self.verification,
			self.metadata,
			self.intent,
		] {
			require_successor(prior, frame)?;
			prior = frame.head();
		}
		let job = DarwinJobPrepared::from_frame(self.job)?;
		job.validate_owner(self.owner)?;
		let entry = DarwinEntryPrepared::from_frame(self.entry)?;
		entry.validate_job(&job)?;
		let seal = DarwinStageSealed::from_frame(self.seal)?;
		let verification = DarwinVerificationRecorded::from_frame(self.verification)?;
		let metadata = DarwinMetadataRecorded::from_frame(self.metadata)?;
		let intent = DarwinPublishIntent::from_frame(self.intent)?;
		intent.check_prerequisites(NonZeroU64::MIN, self.entry, &seal, &verification, &metadata)?;
		Ok(intent)
	}
}

fn check_preceding(history: DarwinRecoveryHistory<'_>) -> Result<(), DarwinPhaseError> {
	let preceding = history.preceding;
	match (preceding.kind(), history.observed_before_durability) {
		(FrameKind::PublishIntent, None) if preceding.head() == history.intent.head() => Ok(()),
		(FrameKind::PublishObserved, None) => {
			require_successor(history.intent.head(), preceding)?;
			let observed = DarwinPublishObserved::from_frame(preceding)?;
			observed.validate_intent(history.intent)?;
			match observed.outcome() {
				DarwinPublicationOutcome::UncertainRename
				| DarwinPublicationOutcome::RenameConfirmedIncomplete
				| DarwinPublicationOutcome::Published => Ok(()),
				_ => Err(DarwinPhaseError::InconsistentObservation),
			}
		}
		(FrameKind::DurabilityRecorded, Some(observed_frame)) => {
			require_successor(history.intent.head(), observed_frame)?;
			require_successor(observed_frame.head(), preceding)?;
			let observed = DarwinPublishObserved::from_frame(observed_frame)?;
			if observed.outcome() != DarwinPublicationOutcome::Published {
				return Err(DarwinPhaseError::InconsistentObservation);
			}
			let durability = DarwinDurabilityRecorded::from_frame(preceding)?;
			durability.validate_evidence(history.metadata, history.intent, observed_frame)
		}
		_ => Err(DarwinPhaseError::InvalidFrameOrder),
	}
}
