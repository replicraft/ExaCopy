use super::{CaptureObservation, Entry, JournalHead, ObjectId, Selection};

/// Durable intent to relocate exactly one public slot occupant to the reserved recovery name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureIntent<'name> {
	/// Exact approved capture parameters and distinct publication policy.
	pub selection: Selection<'name>,
}

/// Independently established result to persist after one known capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRecord<'name> {
	/// Binds the captured evidence to this acknowledged capture intent.
	pub capture_head: JournalHead,
	/// Actual retained entry and completed namespace barriers.
	pub observed: CaptureObservation<'name>,
}

/// Durable publication intent, separate from the authority to relocate a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishIntent<'name> {
	/// Exact approved stage, target and authorization parameters.
	pub selection: Selection<'name>,
	/// Independently observed, durably recorded capture of the approved incumbent.
	pub captured: Entry<'name>,
	/// Independently verified recovery image identity when required.
	pub image: Option<ObjectId>,
}

/// One abstract capture decision. The adapter must still hold all native rights.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct CaptureSlot<'name> {
	pub(super) intent: CaptureIntent<'name>,
	pub(super) head: JournalHead,
}

impl<'name> CaptureSlot<'name> {
	/// Exact decision context, public and recovery slots and selected grants.
	#[must_use]
	pub const fn intent(&self) -> CaptureIntent<'name> {
		self.intent
	}

	/// Independently acknowledged durable intent head.
	#[must_use]
	pub const fn head(&self) -> JournalHead {
		self.head
	}
}

/// One abstract exclusive placement decision. The adapter must use no-clobber.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct PublishStage<'name> {
	pub(super) intent: PublishIntent<'name>,
	pub(super) head: JournalHead,
}

impl<'name> PublishStage<'name> {
	/// Exact verified stage, retention and target bound to the decision.
	#[must_use]
	pub const fn intent(&self) -> PublishIntent<'name> {
		self.intent
	}

	/// Independently acknowledged durable publication intent head.
	#[must_use]
	pub const fn head(&self) -> JournalHead {
		self.head
	}
}

/// Qualified report from the single opaque slot relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureOutcome<'name> {
	/// The actual entry observed after a completed relocation.
	Captured(Entry<'name>),
	/// The primitive definitively did not move an entry, for example a private slot collision.
	NoEffect,
	/// A failure or missing evidence leaves the effect unresolved.
	Uncertain,
}

/// Qualified report from exclusive placement of the replacement stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationOutcome<'name> {
	/// The verified stage was found at its final name after placement.
	Placed {
		/// The independently observed final target.
		target: Entry<'name>,
		/// The original private stage slot was independently observed absent.
		stage_absent: bool,
		/// The exact original remains in the reserved recovery slot.
		retained: Entry<'name>,
	},
	/// A racing public occupant prevented placement.
	Conflict {
		/// The independently observed preserved public entry.
		target: Entry<'name>,
		/// The retained verified stage.
		stage: Entry<'name>,
		/// The exact original remains at the recovery slot.
		retained: Entry<'name>,
	},
	/// A failure or incomplete observation leaves the effect unresolved.
	Uncertain,
}
