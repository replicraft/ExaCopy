//! Read-only replay of the fixed single-file publication journal.

use std::io::Read;

use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReadError, FrameReader};
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, EntryPrepared, JobPrepared, JournalContext, JournalEntryId,
	JournalEpoch, LinuxFileIdentity, LiveSourceView, MetadataRecorded, ObservedTimestamp,
	OwnerRecord, OwnerStateDirectory, OwnerTimestamp, PublishIntent, PublishIntentContext,
	PublishObserved, ReceiptCommitted, StageSealed, VerificationRecorded,
};

use super::LocalCopyPlan;

mod error;
mod suffix;

pub use error::JournalReplayError;

#[cfg(test)]
mod tests;

/// Sequence assigned to the first publication effect in a local v1 copy.
const PUBLICATION_EFFECT_SEQUENCE: u64 = 1;

/// Maximum byte length of the local profile's single journal segment.
pub const MAX_LOCAL_JOURNAL_BYTES: u64 = DurableJournal::MAX_FIRST_SEGMENT_BYTES;

/// The byte and chain boundary after the last accepted record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalBoundary {
	/// The last accepted chain head, or the initial anchor for an empty prefix.
	pub head: ChainHead,
	/// Byte position in the first segment, immediately after the accepted prefix.
	pub offset: u64,
}

/// How the reader reached the end of the accepted journal prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalTail {
	/// EOF at a frame boundary, including EOF before job preparation.
	Clean,
	/// EOF in a structurally plausible but incomplete frame.
	Torn {
		/// Bytes consumed beyond the accepted boundary.
		bytes_read: usize,
	},
}

/// Recorded claims from a compatible local v1 journal prefix.
///
/// A summary conveys historical observations for read-only reconciliation. Current
/// authority, containment, live names and artifacts, and verification remain independent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReplay {
	/// The last accepted record's boundary.
	pub boundary: JournalBoundary,
	/// Whether the input ends in a partial frame.
	pub tail: JournalTail,
	/// Source observation from entry preparation.
	pub source: Option<LiveSourceView>,
	/// Source link count observed at preparation.
	pub source_link_count: Option<u64>,
	/// Stage identity from entry preparation.
	pub stage: Option<LinuxFileIdentity>,
	/// Stage seal observation, including the recorded logical stream length.
	pub sealed: Option<StageSealed>,
	/// Stream measurements from the recorded verification.
	pub verification: Option<VerificationRecorded>,
	/// Exact verification frame of the active publication effect.
	pub verification_head: Option<ChainHead>,
	/// Metadata and file barrier from the recorded run.
	pub metadata: Option<MetadataRecorded>,
	/// Exact metadata frame of the active publication effect.
	pub metadata_head: Option<ChainHead>,
	/// Context of the most recent complete publication intent.
	pub intent: Option<PublishIntentContext>,
	/// Exact reference to the active publication intent.
	pub intent_head: Option<ChainHead>,
	/// Latest recorded observation of the active publication.
	pub observation: Option<PublishObserved>,
	/// Exact reference to the latest recorded observation.
	pub observation_head: Option<ChainHead>,
	/// Recorded namespace barriers, including the claimed stage directory identity.
	pub durability: Option<DurabilityRecorded>,
	/// Exact barrier frame of the active publication.
	pub durability_head: Option<ChainHead>,
	/// Most recent recovery generation, or the plan generation before the first recovery start.
	pub latest_epoch: JournalEpoch,
	/// Highest effect sequence reserved by an original intent or recovery decision.
	pub last_effect_sequence: u64,
	/// The private stage directory claimed by the recovery decisions in this journal.
	pub recovery_stage_directory: Option<LinuxFileIdentity>,
	/// A recovery decision confirmed that the active intent already published the stage.
	pub published_recovery: bool,
	/// Recorded exact receipt reference. Validate the artifact separately.
	pub receipt: Option<ReceiptCommitted>,
}

/// Reads one local v1 journal from its initial anchor against an independently bound plan.
///
/// The caller supplies an owner authenticated using the applicable profile's trusted key
/// and a plan validated against that owner and the authorized recovery location. Replay
/// rechecks their recorded bindings and accepts only a consecutive, kind-correct prefix up to
/// [`MAX_LOCAL_JOURNAL_BYTES`]. Recovery can reconcile the active publication or record a
/// freshly checked retained stage with a new no-clobber effect.
/// A plausible torn frame contributes no claims to the summary. The reader performs no
/// filesystem effects and issues no authority for reconciliation actions.
///
/// # Errors
/// Refuses incompatible owner and plan bindings, read errors, damaged complete frames,
/// unknown formats, reordered or extra records, and inconsistent record evidence.
pub fn replay_journal(
	reader: impl Read,
	plan: &LocalCopyPlan<'_>,
	owner: &OwnerRecord,
) -> Result<JournalReplay, JournalReplayError> {
	let context = plan.context();
	let manifest = owner.manifest();
	let destination = plan.destination().root.identity;
	if manifest.job != context.job
		|| manifest.plan_digest != context.plan_digest
		|| manifest.destination_device != destination.device()
		|| manifest.state_root == destination
		|| manifest.state_root == plan.source().root_identity
		|| manifest.state_root == plan.source().file_identity
		|| !manifest.directories.contains(&OwnerStateDirectory::Journal)
		|| !manifest.directories.contains(&OwnerStateDirectory::Stage)
	{
		return Err(JournalReplayError::OwnerBinding);
	}

	let mut scan = Scan {
		reader: FrameReader::new(reader.take(MAX_LOCAL_JOURNAL_BYTES + 1), ChainHead::start()),
		summary: JournalReplay {
			boundary: JournalBoundary {
				head: ChainHead::start(),
				offset: 0,
			},
			tail: JournalTail::Clean,
			source: None,
			source_link_count: None,
			stage: None,
			sealed: None,
			verification: None,
			verification_head: None,
			metadata: None,
			metadata_head: None,
			intent: None,
			intent_head: None,
			observation: None,
			observation_head: None,
			durability: None,
			durability_head: None,
			latest_epoch: context.epoch,
			last_effect_sequence: 0,
			recovery_stage_directory: None,
			published_recovery: false,
			receipt: None,
		},
	};
	scan.replay(plan, owner, context)?;
	Ok(scan.summary)
}

struct Scan<R> {
	reader: FrameReader<R>,
	summary: JournalReplay,
}

impl<R: Read> Scan<R> {
	fn read_next(&mut self) -> Result<Option<Frame>, JournalReplayError> {
		let frame = match self.reader.next_frame() {
			Ok(Some(frame)) => frame,
			Ok(None) => return Ok(None),
			Err(FrameReadError::TornTail { offset, bytes_read }) => {
				let bytes_read_u64 =
					u64::try_from(bytes_read).map_err(|_| JournalReplayError::SegmentTooLarge)?;
				if offset
					.checked_add(bytes_read_u64)
					.is_none_or(|end| end > MAX_LOCAL_JOURNAL_BYTES)
				{
					return Err(JournalReplayError::SegmentTooLarge);
				}
				self.summary.tail = JournalTail::Torn { bytes_read };
				return Ok(None);
			}
			Err(error) => return Err(JournalReplayError::Frame(error)),
		};
		if self.reader.offset() > MAX_LOCAL_JOURNAL_BYTES {
			return Err(JournalReplayError::SegmentTooLarge);
		}
		let sequence = frame.head().sequence();
		if self.summary.boundary.head.sequence().checked_add(1) != Some(sequence) {
			return Err(JournalReplayError::NonconsecutiveSequence { sequence });
		}
		self.summary.boundary = JournalBoundary {
			head: frame.head(),
			offset: self.reader.offset(),
		};
		Ok(Some(frame))
	}

	fn next(&mut self, expected: Option<FrameKind>) -> Result<Option<Frame>, JournalReplayError> {
		let Some(frame) = self.read_next()? else {
			return Ok(None);
		};
		if Some(frame.kind()) != expected {
			return Err(JournalReplayError::UnexpectedRecord {
				expected,
				found: frame.kind(),
			});
		}
		Ok(Some(frame))
	}

	fn replay(
		&mut self,
		plan: &LocalCopyPlan<'_>,
		owner: &OwnerRecord,
		context: JournalContext,
	) -> Result<(), JournalReplayError> {
		let Some(frame) = self.next(Some(FrameKind::JobPrepared))? else {
			return Ok(());
		};
		let job = JobPrepared::from_frame(&frame)?;
		let destination = plan.destination();
		require_binding(
			FrameKind::JobPrepared,
			job.context == context
				&& job.owner_digest == owner.digest()
				&& job.destination_root == destination.root,
		)?;
		let Some(frame) = self.next(Some(FrameKind::EntryPrepared))? else {
			return Ok(());
		};
		let entry = EntryPrepared::from_frame(&frame)?;
		let prepared = entry.preparation();
		let source = plan.source();
		let state_root = owner.manifest().state_root;
		let stage = prepared.stage;
		let entry_id = plan.attempt().entry;
		require_binding(
			FrameKind::EntryPrepared,
			entry.context == context
				&& entry.entry == entry_id
				&& prepared.source.identity() == source.file_identity
				&& prepared.source.length() == source.length
				&& prepared.source.times().modified_at == source.modified_at
				&& prepared.source.times().changed_at == source.changed_at
				&& prepared.target.root == destination.root.id
				&& prepared.target.component == destination.component
				&& stage.device() == destination.root.identity.device()
				&& stage != destination.root.identity
				&& stage != state_root
				&& stage != source.root_identity,
		)?;
		self.summary.source = Some(prepared.source);
		self.summary.source_link_count = Some(prepared.source_metadata.link_count());
		self.summary.stage = Some(stage);

		let Some(frame) = self.next(Some(FrameKind::StageSealed))? else {
			return Ok(());
		};
		let sealed = StageSealed::from_frame(&frame)?;
		require_binding(
			FrameKind::StageSealed,
			sealed.context == context
				&& sealed.entry == entry_id
				&& sealed.stage == stage
				&& sealed.length.get() == source.length,
		)?;
		self.summary.sealed = Some(sealed);

		let Some(verification_frame) = self.next(Some(FrameKind::VerificationRecorded))? else {
			return Ok(());
		};
		let verification = VerificationRecorded::from_frame(&verification_frame)?;
		require_binding(
			FrameKind::VerificationRecorded,
			verification.context == context
				&& verification.entry == entry_id
				&& verification.source().identity == prepared.source.identity()
				&& verification.stage().identity == stage
				&& verification.source().length.get() == source.length
				&& verification.stage().length == sealed.length,
		)?;
		self.summary.verification = Some(verification);
		self.summary.verification_head = Some(verification_frame.head());

		let Some(metadata_frame) = self.next(Some(FrameKind::MetadataRecorded))? else {
			return Ok(());
		};
		let metadata = MetadataRecorded::from_frame(&metadata_frame)?;
		let source_times = prepared.source.times();
		require_binding(
			FrameKind::MetadataRecorded,
			metadata.context == context
				&& metadata.entry == entry_id
				&& metadata.stage == stage
				&& metadata.metadata.mode() == prepared.source_metadata.mode()
				&& metadata.metadata.uid == prepared.source_metadata.owner()
				&& metadata.metadata.gid == prepared.source_metadata.group()
				&& same_time(metadata.metadata.accessed_at, source_times.accessed_at)
				&& same_time(metadata.metadata.modified_at, source_times.modified_at),
		)?;
		self.summary.metadata = Some(metadata);
		self.summary.metadata_head = Some(metadata_frame.head());

		let Some(intent_frame) = self.next(Some(FrameKind::PublishIntent))? else {
			return Ok(());
		};
		let intent = PublishIntent::from_frame(&intent_frame)?;
		require_binding(
			FrameKind::PublishIntent,
			intent.context == publication_context(context, entry_id)
				&& intent.target.stage == stage
				&& intent.target.parent == destination.root.identity
				&& intent.target.component == destination.component
				&& intent.target.verification_digest == verification.record_digest(),
		)?;
		self.summary.intent = Some(intent.context);
		self.summary.intent_head = Some(intent_frame.head());
		self.summary.last_effect_sequence = intent.context.effect_sequence;

		self.replay_suffix(
			suffix::PublicationFrames {
				verification: verification_frame,
				metadata: metadata_frame,
				intent: intent_frame,
			},
			plan,
			owner,
		)
	}
}

fn publication_context(context: JournalContext, entry: JournalEntryId) -> PublishIntentContext {
	PublishIntentContext {
		job: context.job,
		epoch: context.epoch,
		entry,
		effect_sequence: PUBLICATION_EFFECT_SEQUENCE,
		plan_digest: context.plan_digest,
	}
}

fn same_time(actual: OwnerTimestamp, source: ObservedTimestamp) -> bool {
	actual.seconds() == source.seconds() && actual.nanoseconds() == source.nanoseconds()
}

fn require_binding(kind: FrameKind, matches: bool) -> Result<(), JournalReplayError> {
	if matches {
		Ok(())
	} else {
		Err(JournalReplayError::RecordBinding { kind })
	}
}
