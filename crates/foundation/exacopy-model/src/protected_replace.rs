//! Pure decisions for one separately approved protected replacement.
//!
//! The caller owns the native gates. It must enforce unique live admission for
//! each attempt, preserve the selected layout and hold the live grant through each effect.
//! Opaque digests label independently checked facts. The model has no native
//! capture, restoration, publication or deletion rights.

mod effect;
mod evidence;
mod selection;

pub use effect::{
	CaptureIntent, CaptureOutcome, CaptureRecord, CaptureSlot, PublicationOutcome, PublishIntent,
	PublishStage,
};
pub use evidence::{
	AdmissionHistory, CaptureBarriers, CaptureObservation, Durable, Entry, EntryKind,
	HistoryDisposition, ImageObservation, JournalHead, ReadyForPublication, StageReady,
};
pub use selection::{
	Context, CurrentGrant, Digest, Directory, FilesystemId, Grant, ImagePolicy, ObjectId,
	Selection, Slot,
};

/// Current decision phase. Terminal states authorize no further effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
	/// The approved incumbent and verified replacement stage have been observed.
	Prepared,
	/// A single opaque capture has been authorized.
	CaptureIssued,
	/// An actual retained entry has been observed, without confirmed capture durability.
	CaptureObserved,
	/// The exact expected incumbent is durably retained.
	CaptureRecorded,
	/// Any required independent recovery image has been verified and retained.
	ImageReady,
	/// Exclusive placement has been authorized once.
	PublicationIssued,
	/// The verified replacement is observed at the target. Publication durability is unconfirmed.
	PlacedUnconfirmed,
	/// A qualified no-effect report or known conflict ended the attempt.
	Conflict,
	/// A different or unsupported captured entry is retained. Separate reconciliation is required.
	StalePlan,
	/// An ambiguous or incompatible operation requires reconciliation.
	ReconciliationRequired,
	/// The attempt was stopped before capture authorization.
	Cancelled,
}

/// Why this decision was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
	/// The admitted profile, native identities, or byte limits are invalid.
	Selection,
	/// The incumbent no longer matches the plan before capture authorization.
	Incumbent,
	/// The expected stage is not fully verified, metadata-ready and sealed in this scope.
	Stage,
	/// The active effect authority, lease, or expiry no longer matches.
	Authority,
	/// The replay does not establish fresh pre-intent history at the current held head.
	History,
	/// The journal head, record, barriers or observations cannot establish the needed fact.
	Evidence,
	/// The image evidence is incomplete or not separately authorized.
	Image,
	/// The current phase does not accept the requested transition.
	Order,
}

/// Fixed-size decision state for a single attempt with no restart or restoration constructor.
#[derive(Debug)]
pub struct Session<'name> {
	selection: Selection<'name>,
	head: JournalHead,
	phase: Phase,
	last_captured: Option<Entry<'name>>,
	image: Option<ObjectId>,
}

impl<'name> Session<'name> {
	/// Start a fresh attempt from a matching pre-intent replay and live observations.
	///
	/// # Errors
	/// Refuses aliased or unqualified scope, incorrect incumbent, incomplete verification,
	/// prior intents, uncertain history, and heads that cannot represent the required successors.
	pub fn start(
		selection: Selection<'name>,
		prelookup: Entry<'name>,
		stage: StageReady<'name>,
		history: AdmissionHistory<'name>,
	) -> Result<Self, Refusal> {
		if !selection.is_admissible() {
			return Err(Refusal::Selection);
		}
		if prelookup.slot != selection.context.target
			|| prelookup.object != selection.incumbent
			|| prelookup.kind != EntryKind::Regular
		{
			return Err(Refusal::Incumbent);
		}
		if !stage.matches(selection) {
			return Err(Refusal::Stage);
		}
		let head = history
			.fresh_head(selection.context)
			.ok_or(Refusal::History)?;
		if !head.bounds_attempt() {
			return Err(Refusal::Evidence);
		}
		Ok(Self {
			selection,
			head,
			phase: Phase::Prepared,
			last_captured: None,
			image: None,
		})
	}

	/// Returns the current phase.
	#[must_use]
	pub const fn phase(&self) -> Phase {
		self.phase
	}

	/// Returns the last matching-location capture observation for inspection.
	///
	/// This is historical evidence. Independently reopen and inspect the recovery slot
	/// before relying on it. There is no restoration permit.
	#[must_use]
	pub const fn last_captured(&self) -> Option<Entry<'name>> {
		self.last_captured
	}

	/// Returns the bounded intent to persist for one opaque relocation.
	#[must_use]
	pub fn capture_intent(&self) -> Option<CaptureIntent<'name>> {
		(self.phase == Phase::Prepared).then_some(CaptureIntent {
			selection: self.selection,
		})
	}

	/// Accepts a durable capture intent and authorizes at most one opaque relocation.
	///
	/// # Errors
	/// Refuses the wrong phase, unverified stage, invalid authority or wrong durable intent.
	/// Unusable evidence in the active phase stops this attempt for reconciliation.
	pub fn authorize_capture(
		&mut self,
		stage: StageReady<'name>,
		current: CurrentGrant<'name>,
		durable: Durable<CaptureIntent<'name>>,
	) -> Result<CaptureSlot<'name>, Refusal> {
		let intent = self.capture_intent().ok_or(Refusal::Order)?;
		self.authorize(stage, current, self.selection.capture, &durable, &intent)?;
		self.phase = Phase::CaptureIssued;
		Ok(CaptureSlot {
			intent,
			head: self.head,
		})
	}

	/// Consumes the capture decision and records only the actual reported private entry.
	///
	/// # Errors
	/// Refuses a stale decision, wrong phase or inconsistent capture location.
	pub fn observe_capture(
		&mut self,
		permit: CaptureSlot<'name>,
		outcome: CaptureOutcome<'name>,
	) -> Result<(), Refusal> {
		if self.phase != Phase::CaptureIssued {
			return Err(Refusal::Order);
		}
		if permit.intent.selection != self.selection || permit.head != self.head {
			return self.stop(Refusal::Evidence);
		}
		self.phase = match outcome {
			CaptureOutcome::NoEffect => Phase::Conflict,
			CaptureOutcome::Uncertain => Phase::ReconciliationRequired,
			CaptureOutcome::Captured(entry)
				if entry.slot == self.selection.context.recovery && entry.object.0 != [0; 32] =>
			{
				self.last_captured = Some(entry);
				Phase::CaptureObserved
			}
			CaptureOutcome::Captured(_) => return self.stop(Refusal::Evidence),
		};
		Ok(())
	}

	/// Accepts actual durable capture evidence after both namespace barriers.
	///
	/// A mismatched captured identity is retained and yields a terminal stale-plan outcome.
	///
	/// # Errors
	/// Refuses unknown or mismatched evidence, including a rebind of the private slot.
	pub fn acknowledge_capture(
		&mut self,
		durable: Durable<CaptureRecord<'name>>,
	) -> Result<(), Refusal> {
		if self.phase != Phase::CaptureObserved {
			return Err(Refusal::Order);
		}
		let observed = durable.record.observed;
		let context = self.selection.context;
		if !durable.follows(self.head)
			|| durable.record.capture_head != self.head
			|| observed.context != context
			|| observed.barriers.public != context.target.parent
			|| observed.barriers.recovery != context.recovery.parent
			|| Some(observed.retained) != self.last_captured
			|| observed.retained.object.0 == [0; 32]
		{
			return self.stop(Refusal::Evidence);
		}
		self.head = durable.current;
		let retained = observed.retained;
		self.phase =
			if retained.object == self.selection.incumbent && retained.kind == EntryKind::Regular {
				Phase::CaptureRecorded
			} else {
				Phase::StalePlan
			};
		Ok(())
	}

	/// Accepts a separately authorized stable-view and independent recovery image observation.
	///
	/// # Errors
	/// Refuses incomplete, aliased, excessive or unauthorized image evidence.
	pub fn acknowledge_image(&mut self, observed: ImageObservation<'name>) -> Result<(), Refusal> {
		if self.phase != Phase::CaptureRecorded {
			return Err(Refusal::Order);
		}
		let ImagePolicy::IndependentImage {
			read,
			create,
			max_bytes,
		} = self.selection.image
		else {
			return Err(Refusal::Order);
		};
		let context = self.selection.context;
		if Some(observed.captured) != self.last_captured
			|| !observed.read.admits(context, read)
			|| !observed.create.admits(context, create)
			|| observed.original != observed.measured
			|| observed.measured.byte_len > max_bytes
			|| !observed.stable_view
			|| !observed.durably_retained
			|| observed.image.0 == [0; 32]
			|| context.binds(observed.image)
			|| [
				self.selection.source,
				self.selection.replacement,
				self.selection.incumbent,
			]
			.contains(&observed.image)
		{
			return self.stop(Refusal::Image);
		}
		self.image = Some(observed.image);
		self.phase = Phase::ImageReady;
		Ok(())
	}

	/// Returns the exact intent only after retaining the approved incumbent and any required image.
	#[must_use]
	pub fn publish_intent(&self) -> Option<PublishIntent<'name>> {
		match (self.phase, self.selection.image) {
			(Phase::CaptureRecorded, ImagePolicy::RetainObject)
			| (Phase::ImageReady, ImagePolicy::IndependentImage { .. }) => Some(PublishIntent {
				selection: self.selection,
				captured: self.last_captured?,
				image: self.image,
			}),
			_ => None,
		}
	}

	/// Accepts a distinct durable intent before authorizing one exclusive publication.
	///
	/// # Errors
	/// Refuses the wrong phase, stale stage, changed retention, invalid authority or wrong intent.
	pub fn authorize_publication(
		&mut self,
		ready: ReadyForPublication<'name>,
		current: CurrentGrant<'name>,
		durable: Durable<PublishIntent<'name>>,
	) -> Result<PublishStage<'name>, Refusal> {
		let intent = self.publish_intent().ok_or(Refusal::Order)?;
		if ready.retained != intent.captured || ready.retained_image != intent.image {
			return self.stop(Refusal::Evidence);
		}
		self.authorize(
			ready.stage,
			current,
			self.selection.publication,
			&durable,
			&intent,
		)?;
		self.phase = Phase::PublicationIssued;
		Ok(PublishStage {
			intent,
			head: self.head,
		})
	}

	/// Consumes the publication decision and classifies its independently observed result.
	///
	/// # Errors
	/// Refuses a stale decision, wrong phase or inconsistent namespace observation.
	pub fn observe_publication(
		&mut self,
		permit: PublishStage<'name>,
		outcome: PublicationOutcome<'name>,
	) -> Result<(), Refusal> {
		if self.phase != Phase::PublicationIssued {
			return Err(Refusal::Order);
		}
		if permit.intent.selection != self.selection || permit.head != self.head {
			return self.stop(Refusal::Evidence);
		}
		self.phase = match outcome {
			PublicationOutcome::Uncertain => Phase::ReconciliationRequired,
			PublicationOutcome::Placed {
				target,
				stage_absent: true,
				retained,
			} if Some(retained) == self.last_captured
				&& self.replacement_at(target, self.selection.context.target) =>
			{
				Phase::PlacedUnconfirmed
			}
			PublicationOutcome::Conflict {
				target,
				stage,
				retained,
			} if Some(retained) == self.last_captured
				&& self.replacement_at(stage, self.selection.context.stage)
				&& target.slot == self.selection.context.target
				&& target.object.0 != [0; 32]
				&& target.object != self.selection.replacement =>
			{
				Phase::Conflict
			}
			_ => return self.stop(Refusal::Evidence),
		};
		Ok(())
	}

	/// Stops the current attempt without authorizing recapture, publication or restoration.
	pub fn interrupt(&mut self) {
		self.phase = match self.phase {
			Phase::Prepared => Phase::Cancelled,
			Phase::CaptureIssued
			| Phase::CaptureObserved
			| Phase::CaptureRecorded
			| Phase::ImageReady
			| Phase::PublicationIssued => Phase::ReconciliationRequired,
			terminal => terminal,
		};
	}

	fn authorize<R: Eq>(
		&mut self,
		stage: StageReady<'name>,
		current: CurrentGrant<'name>,
		grant: Grant,
		durable: &Durable<R>,
		intent: &R,
	) -> Result<(), Refusal> {
		if !stage.matches(self.selection) {
			return self.stop(Refusal::Stage);
		}
		if !current.admits(self.selection.context, grant) {
			return self.stop(Refusal::Authority);
		}
		if !durable.follows(self.head) || &durable.record != intent {
			return self.stop(Refusal::Evidence);
		}
		self.head = durable.current;
		Ok(())
	}

	fn replacement_at(&self, entry: Entry<'name>, slot: Slot<'name>) -> bool {
		entry.slot == slot
			&& entry.object == self.selection.replacement
			&& entry.kind == EntryKind::Regular
	}

	fn stop<T>(&mut self, refusal: Refusal) -> Result<T, Refusal> {
		self.phase = Phase::ReconciliationRequired;
		Err(refusal)
	}
}
