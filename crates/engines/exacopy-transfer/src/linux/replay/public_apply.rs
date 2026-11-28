use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	ApplyQualification, DurabilityRecorded, OwnerTimestamp, PublicApplyAssociation,
	PublicApplyIntent, PublicApplyOwnerRecord, PublicationOutcome, PublishObserved,
	ReceiptCommitted, VerificationRecorded,
};

use super::suffix::PublicationFrames;
use super::{
	JournalBoundary, JournalReplay, JournalReplayError, JournalTail, LocalCopyPlan,
	MAX_LOCAL_JOURNAL_BYTES, ReplayOwner, Scan, check_public_stage_plan, check_public_stream,
	publication_context, require_binding, scan_bound_journal,
};

pub(in crate::linux) const MAX_PUBLIC_APPLY_SUFFIX_BYTES: usize = 4096;

pub(in crate::linux) struct PublicApplyReplay {
	pub(in crate::linux) journal: JournalReplay,
	pub(in crate::linux) seal: Option<JournalBoundary>,
}

pub(in crate::linux) fn replay_public_apply(
	reader: impl Read,
	plan: &LocalCopyPlan<'_>,
	owner: &PublicApplyOwnerRecord,
	qualification: ApplyQualification,
) -> Result<PublicApplyReplay, JournalReplayError> {
	check_public_stage_plan(plan, owner)?;
	let end = Cell::new(MAX_LOCAL_JOURNAL_BYTES + 1);
	let cap_reached = Cell::new(false);
	let bounded = PublicHistoryReader {
		reader,
		end: &end,
		cap_reached: &cap_reached,
		position: 0,
		interruptions: MAX_INTERRUPTED_RETRIES,
	};
	let scan = scan_bound_journal(
		bounded,
		plan,
		ReplayOwner::PublicApply(owner, qualification, &end),
	)
	.map_err(|error| {
		if cap_reached.get() {
			JournalReplayError::PublicSuffixTooLarge
		} else {
			error
		}
	})?;
	check_public_stream(&scan.summary, owner.manifest().binding)?;
	if let Some(seal) = scan.seal_boundary {
		let extra = match scan.summary.tail {
			JournalTail::Clean => 0,
			JournalTail::Torn { bytes_read } => {
				u64::try_from(bytes_read).map_err(|_| JournalReplayError::SegmentTooLarge)?
			}
		};
		let consumed = scan.summary.boundary.offset + extra;
		if consumed - seal.offset > MAX_PUBLIC_APPLY_SUFFIX_BYTES as u64 {
			return Err(JournalReplayError::PublicSuffixTooLarge);
		}
	}
	Ok(PublicApplyReplay {
		journal: scan.summary,
		seal: scan.seal_boundary,
	})
}

impl<R: Read> Scan<R> {
	pub(super) fn replay_public_suffix(
		&mut self,
		frames: PublicationFrames,
		plan: &LocalCopyPlan<'_>,
		owner: &PublicApplyOwnerRecord,
		qualification: ApplyQualification,
		verification: VerificationRecorded,
	) -> Result<(), JournalReplayError> {
		let PublicationFrames {
			verification: proof,
			metadata,
			intent,
		} = frames;
		let parsed =
			PublicApplyIntent::from_frame(&intent).map_err(JournalReplayError::PublicIntent)?;
		let accepted = parsed.private();
		let evidence = parsed.evidence();
		let claims = owner.manifest();
		let destination = plan.destination();
		let context = publication_context(plan.context(), plan.attempt().entry);
		require_binding(
			FrameKind::PublishIntent,
			parsed.association()
				== (PublicApplyAssociation {
					owner_digest: owner.digest(),
					public_plan: claims.binding.public_plan,
					public_entry: claims.binding.public_entry,
				})
				&& accepted.context == context
				&& accepted.target.stage == verification.stage().identity
				&& accepted.target.parent == destination.root.identity
				&& accepted.target.component == destination.component
				&& accepted.target.verification_digest == verification.record_digest()
				&& evidence.verification == proof.head()
				&& evidence.metadata == metadata.head()
				&& evidence.qualification == qualification
				&& qualification.environment.device == plan.source().root_identity.device()
				&& time(evidence.intent_time) >= time(claims.owner.created)
				&& claims
					.binding
					.expires_at
					.is_some_and(|expiry| time(evidence.intent_time) < time(expiry)),
		)?;
		self.summary.intent = Some(context);
		self.summary.intent_head = Some(intent.head());
		self.summary.last_effect_sequence = context.effect_sequence;

		let Some(frame) = self.next(Some(FrameKind::PublishObserved))? else {
			return Ok(());
		};
		let observed = PublishObserved::from_frame(&frame)?;
		require_binding(
			FrameKind::PublishObserved,
			observed.context() == context
				&& observed.intent() == intent.head()
				&& observed.outcome()
					== (PublicationOutcome::Published {
						target: accepted.target.stage,
					}),
		)?;
		self.summary.observation = Some(observed);
		self.summary.observation_head = Some(frame.head());

		let Some(durability_frame) = self.next(Some(FrameKind::DurabilityRecorded))? else {
			return Ok(());
		};
		let durability = DurabilityRecorded::from_frame(&durability_frame)?;
		let barriers = durability.barriers();
		let source = plan.source();
		require_binding(
			FrameKind::DurabilityRecorded,
			durability.context() == context
				&& durability.observed() == frame.head()
				&& barriers.metadata == metadata.head()
				&& barriers.destination_directory == destination.root.identity
				&& ![
					claims.owner.state_root,
					source.file_identity,
					source.root_identity,
					accepted.target.stage,
				]
				.contains(&barriers.stage_directory),
		)?;
		self.summary.durability = Some(durability);
		self.summary.durability_head = Some(durability_frame.head());

		let Some(frame) = self.next(Some(FrameKind::ReceiptCommitted))? else {
			return Ok(());
		};
		let receipt = ReceiptCommitted::from_frame(&frame)?;
		require_binding(
			FrameKind::ReceiptCommitted,
			receipt.context() == context && receipt.durability() == durability_frame.head(),
		)?;
		self.summary.receipt = Some(receipt);
		let _ = self.next(None)?;
		if self.summary.tail != JournalTail::Clean {
			return Err(JournalReplayError::TrailingAfterReceipt);
		}
		Ok(())
	}
}

fn time(value: OwnerTimestamp) -> (i64, u32) {
	(value.seconds(), value.nanoseconds())
}

struct PublicHistoryReader<'limit, R> {
	reader: R,
	end: &'limit Cell<u64>,
	cap_reached: &'limit Cell<bool>,
	position: u64,
	interruptions: u8,
}

impl<R: Read> Read for PublicHistoryReader<'_, R> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let remaining =
			usize::try_from(self.end.get().saturating_sub(self.position)).unwrap_or(usize::MAX);
		if remaining == 0 {
			self.cap_reached.set(true);
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"checked apply history exceeds its byte ceiling",
			));
		}
		let length = remaining.min(output.len());
		let count = match self.reader.read(&mut output[..length]) {
			Err(error) if error.kind() == io::ErrorKind::Interrupted => {
				if self.interruptions == 0 {
					return Err(io::Error::other(error));
				}
				self.interruptions -= 1;
				return Err(error);
			}
			result => result?,
		};
		if count > length {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"invalid journal read count",
			));
		}
		self.position += u64::try_from(count).map_err(io::Error::other)?;
		Ok(count)
	}
}
