use crate::RegularFileEvidence;

use super::{Context, CurrentGrant, Digest, Directory, ObjectId, Selection, Slot};

/// Exact independently observed boundary of the single serialized journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalHead {
	/// Increasing frame sequence.
	pub sequence: u64,
	/// Exact frame-chain digest.
	pub digest: Digest,
}

impl JournalHead {
	// Capture intent, capture observation and publication intent are mandatory.
	const REQUIRED_SUCCESSORS: u64 = 3;

	pub(super) fn bounds_attempt(self) -> bool {
		self.sequence != 0
			&& self.digest != [0; 32]
			&& self
				.sequence
				.checked_add(Self::REQUIRED_SUCCESSORS)
				.is_some()
	}
}

/// Disposition independently established from the complete relevant journal history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryDisposition {
	/// The accepted chain is before any relevant capture or publication intent.
	FreshPreIntent,
	/// The history includes an earlier protected operation intent or effect.
	PriorIntent,
	/// Incomplete, inconsistent or ambiguous evidence precludes fresh admission.
	Indeterminate,
}

/// Admission evidence from replay and the current writer, under the same held lease.
///
/// The caller must establish the disposition using the complete authoritative history
/// for the selected scope, including earlier attempts capable of affecting these
/// slots. A change of epoch alone cannot clear an earlier intent. The pure model
/// compares these independently reported facts; they carry no native authority.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmissionHistory<'name> {
	/// Current, independently revalidated held context for both observations.
	pub context: Context<'name>,
	/// Exact terminal head of the fully checked replay.
	pub replayed: JournalHead,
	/// Exact durable head independently observed by the current writer owner.
	pub current: JournalHead,
	/// What the complete replay established about earlier intents and effects.
	pub disposition: HistoryDisposition,
}

impl AdmissionHistory<'_> {
	pub(super) fn fresh_head(self, expected: Context<'_>) -> Option<JournalHead> {
		(self.context == expected
			&& self.disposition == HistoryDisposition::FreshPreIntent
			&& self.replayed == self.current)
			.then_some(self.current)
	}
}

/// A synced record independently reread and bound to its exact predecessor.
///
/// The journal owner must validate the underlying frame chain and durability.
/// This value supplies facts to the model without carrying a writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Durable<R> {
	/// Previous accepted head read from the same chain.
	pub previous: JournalHead,
	/// New record head after the successful journal barrier.
	pub current: JournalHead,
	/// Canonically decoded independently reread record contents.
	pub record: R,
}

impl<R> Durable<R> {
	pub(super) fn follows(&self, previous: JournalHead) -> bool {
		self.previous == previous
			&& previous.sequence.checked_add(1) == Some(self.current.sequence)
			&& self.current.digest != [0; 32]
			&& self.current.digest != previous.digest
	}
}

/// Report of the bound replacement's staged verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageReady<'name> {
	/// Exact physical and authorization context for the stage.
	pub context: Context<'name>,
	/// Native identity of the matching held stage.
	pub object: ObjectId,
	/// Complete matching read-back stream and required metadata.
	pub measured: RegularFileEvidence,
	/// All writers are joined and future data-write permits have been revoked.
	pub quiesced: bool,
	/// The required data barrier succeeded.
	pub data_flushed: bool,
	/// The measurements follow an independent complete read-back.
	pub independently_verified: bool,
	/// Required metadata was checked and durably applied.
	pub metadata_ready: bool,
	/// The same stage remains sealed.
	pub sealed: bool,
}

impl StageReady<'_> {
	pub(super) fn matches(self, selection: Selection<'_>) -> bool {
		self.context == selection.context
			&& self.object == selection.replacement
			&& self.measured == selection.replacement_evidence
			&& self.quiesced
			&& self.data_flushed
			&& self.independently_verified
			&& self.metadata_ready
			&& self.sealed
	}
}

/// Kind support established without following or traversing the captured entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
	/// An admitted ordinary regular file under the selected profile.
	Regular,
	/// An opaque entry outside the supported file profile.
	Opaque,
}

/// Identity of one exact entry observed without following a referent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry<'name> {
	/// The exact held directory and raw name.
	pub slot: Slot<'name>,
	/// Native identity of the observed entry itself.
	pub object: ObjectId,
	/// Kind disposition without payload access.
	pub kind: EntryKind,
}

/// Confirmed namespace barriers following a known relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBarriers {
	/// Original public parent whose required barrier succeeded.
	pub public: Directory,
	/// Private recovery parent whose required barrier succeeded.
	pub recovery: Directory,
}

/// Independent observation of the captured entry after both namespace barriers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureObservation<'name> {
	/// Exact current held context.
	pub context: Context<'name>,
	/// Required completed namespace barriers.
	pub barriers: CaptureBarriers,
	/// Actual retained entry at the private slot after both barriers.
	pub retained: Entry<'name>,
}

/// Verified evidence from a separately authorized independent image workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageObservation<'name> {
	/// Exact captured object that the stable image workflow reread.
	pub captured: Entry<'name>,
	/// Separate read grant checked while using the held retained object.
	pub read: CurrentGrant<'name>,
	/// Separate creation grant checked while retaining the image.
	pub create: CurrentGrant<'name>,
	/// Independently observed identity of the created private image.
	pub image: ObjectId,
	/// The stable source measurement, including required metadata.
	pub original: RegularFileEvidence,
	/// Independently verified complete data and metadata of the image.
	pub measured: RegularFileEvidence,
	/// Stable view of the exact original throughout image verification.
	pub stable_view: bool,
	/// Image identity, file barrier and required private namespace barrier are confirmed.
	pub durably_retained: bool,
}

/// Ready stage and freshly rechecked retained version before exclusive placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyForPublication<'name> {
	/// Current independently revalidated stage readiness.
	pub stage: StageReady<'name>,
	/// Exact private retained object freshly observed.
	pub retained: Entry<'name>,
	/// Required private image independently rechecked by its qualified owner.
	pub retained_image: Option<ObjectId>,
}
