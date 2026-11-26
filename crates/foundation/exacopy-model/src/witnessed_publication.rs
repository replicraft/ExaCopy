//! Pure decisions for selector-2 publication with a protected inode witness.
//!
//! The caller authenticates bindings and holds the serialized lease and exact
//! native capabilities throughout each observation and submission. None of
//! these logical tokens supplies a filesystem or journal capability.

use core::num::NonZeroU64;

use crate::retained_prefix::Head;

mod state;

pub use state::{Publication, RenameSubmission, WitnessSubmission};

/// Native identity observed through a held descriptor on the admitted mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
	/// Same-boot unique mount ID.
	pub mount: NonZeroU64,
	/// Device identifier.
	pub device: u64,
	/// Inode number, comparable only while the relevant descriptors are held.
	pub inode: NonZeroU64,
}

/// Observed selected regular file under its exact admitted name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldFile {
	/// Native identity of the regular inode.
	pub identity: FileIdentity,
	/// Exact link count observed while holding it.
	pub links: u64,
}

/// Observation relative to the exact independently checked namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameObservation {
	/// Exclusive name was positively absent.
	Absent,
	/// The exact current name and held regular descriptor agree.
	Held(HeldFile),
	/// Missing or unsupported knowledge, including a nonregular entry.
	Uncertain,
}

/// Stable recorded selector-2 scope, independent of the process-specific lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeBinding {
	/// Exact committed owner, job, entry, lineage, and signed scope.
	pub subject: [u8; 32],
	/// Exact admitted boot, mount, protected directories and raw names.
	pub namespace: [u8; 32],
	/// Exact physical stage originally held under that scope.
	pub stage: FileIdentity,
	/// Base grant independently selected for the continued history.
	pub base_grant: [u8; 32],
	/// Witness-operation qualification selected for the same history.
	pub qualification: [u8; 32],
	/// Retention approval committed by kind 41.
	pub approval: Approval,
}

/// Separately authenticated retention consent for the exact scope and grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Approval {
	/// Commitment to the canonical authenticated approval projection.
	pub digest: [u8; 32],
	/// Exclusive POSIX deadline of the admitted consent.
	pub deadline: NonZeroU64,
}

/// Current logical evidence tied to the held lease and accepted journal head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveBinding {
	/// Exact currently held scope and names.
	pub scope: ScopeBinding,
	/// Identity of the exact serialized lease under the current process.
	pub lease: [u8; 32],
	/// Exact freshly authenticated positive base-grant observation.
	pub base_grant: Option<[u8; 32]>,
	/// Independently selected current approval, supplied by runtime authority.
	pub approval: Option<Approval>,
	/// Trusted current POSIX seconds, or uncertainty.
	pub now: Option<u64>,
	/// Exact current accepted and checked journal boundary.
	pub head: Head,
}

/// Simultaneous holds and exact positive observations under one lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceObservation {
	/// Exact held lease shared by every name observation.
	pub lease: [u8; 32],
	/// Exact boot, mount, protected directories and raw-name binding.
	pub namespace: [u8; 32],
	/// Continuously protected witness namespace under the selected profile.
	pub protected: bool,
	/// Exact private stage name.
	pub stage: NameObservation,
	/// Exact protected witness name.
	pub witness: NameObservation,
	/// Exact public target name.
	pub target: NameObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Aliases {
	StageOnly,
	WitnessedStage,
	WitnessedTarget,
}

impl NamespaceObservation {
	fn aliases(self, live: LiveBinding, aliases: Aliases) -> bool {
		use NameObservation::{Absent, Held};
		let one_link = Held(HeldFile {
			identity: live.scope.stage,
			links: 1,
		});
		let two_links = Held(HeldFile {
			identity: live.scope.stage,
			links: 2,
		});
		self.matches_binding(live)
			&& match aliases {
				Aliases::StageOnly => self.stage == one_link && self.witness == Absent,
				Aliases::WitnessedStage => self.stage == two_links && self.witness == two_links,
				Aliases::WitnessedTarget => {
					self.stage == Absent && self.witness == two_links && self.target == two_links
				}
			}
	}

	fn matches_binding(self, live: LiveBinding) -> bool {
		self.protected && self.lease == live.lease && self.namespace == live.scope.namespace
	}
}

impl LiveBinding {
	fn admitted(self, scope: ScopeBinding) -> bool {
		self.scope == scope
			&& self.lease != [0; 32]
			&& self.head.sequence > 0
			&& self.head.end > 0
			&& self.head.digest != [0; 32]
			&& scope.subject != [0; 32]
			&& scope.namespace != [0; 32]
			&& scope.base_grant != [0; 32]
			&& scope.qualification != [0; 32]
			&& scope.approval.digest != [0; 32]
			&& self.base_grant == Some(scope.base_grant)
			&& self.approval == Some(scope.approval)
			&& self
				.now
				.is_some_and(|time| time < scope.approval.deadline.get())
	}
}

/// Independently selected history where live witness handling might begin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureBoundary {
	/// The current originating capture closed both endpoints and synchronized the stage.
	/// Its exact live journal head was independently checked as a clean capture boundary.
	ClosedAndSynced,
	/// An earlier witness intent already reached the journal.
	HistoricalWitnessIntent,
	/// An earlier publication intent already reached the journal.
	HistoricalPublicationIntent,
	/// Capture is incomplete or its exact historical state is unconfirmed.
	IncompleteOrUncertain,
}

/// Actual result of the single submitted witness link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWitnessOutcome {
	/// Definite creation of the protected witness.
	Linked,
	/// Definite refusal with no new link.
	Refused,
	/// The native result is unconfirmed.
	Uncertain,
}

/// Read-only facts from the exact submitted witness link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessObservation {
	/// The exact two links were observed immediately following submission.
	Linked,
	/// Reconciliation is necessary. Retain the actual known native fact.
	Reconcile(NativeWitnessOutcome),
}

/// Barrier evidence for the linked inode and protected witness directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessBarriers {
	/// Both full barriers were independently confirmed on the exact held objects.
	BothConfirmed,
	/// At least one required barrier was unconfirmed.
	Incomplete,
}

/// Actual known result of a submitted, consumed no-replace operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRenameOutcome {
	/// The submitter received definite success.
	Success,
	/// The submitter received a definite native no-replace conflict.
	Conflict,
	/// The submitter cannot establish the outcome.
	Uncertain,
}

/// Read-only classification of a live submission and its held rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionObservation {
	/// Complete positive namespace observation at this point in time.
	Published,
	/// Definite no-replace refusal with independently confirmed incumbent.
	Conflict,
	/// Reconciliation is necessary. Retain the actual known native fact.
	Reconcile(NativeRenameOutcome),
}

/// Scope and actual accepted boundary of one historical publication intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalIntent {
	/// Exact archived scope, selected qualification and retention consent.
	pub scope: ScopeBinding,
	/// Exact independently accepted intent frame and boundary.
	pub head: Head,
}

/// Classification of one independently observed recovery point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryObservation<'intent> {
	/// Exact witnessed inode and live public name were confirmed now.
	Recovered(Recovered<'intent>),
	/// The checked observations do not justify positive recovery.
	Reconcile,
}

/// Evidence about one exact checked recovery observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovered<'intent> {
	intent: &'intent HistoricalIntent,
	lease: [u8; 32],
}

impl<'intent> Recovered<'intent> {
	/// Exact historical intent supplying all recorded binding information.
	#[must_use]
	pub const fn intent(self) -> &'intent HistoricalIntent {
		self.intent
	}

	/// Current lease under which this observation was made.
	#[must_use]
	pub const fn lease(self) -> [u8; 32] {
		self.lease
	}
}

/// Independent local readback of the exact currently held witnessed target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryReadback {
	/// Complete matching bytes, exact EOF and required metadata were confirmed under the same holds.
	Complete,
	/// At least one required local readback observation was unconfirmed.
	Incomplete,
}

/// Checks a historical intent against current read-only held observations.
///
/// The complete immutable local bytes, EOF and metadata must already have
/// been independently checked under the same holds. The enum reports the
/// caller's observation and carries no native capability. A positive result
/// authorizes no effect and says nothing about later public-name presence.
#[must_use]
pub fn observe_recovery(
	intent: &HistoricalIntent,
	live: LiveBinding,
	names: NamespaceObservation,
	readback: RecoveryReadback,
) -> RecoveryObservation<'_> {
	if live.admitted(intent.scope)
		&& live.head == intent.head
		&& names.aliases(live, Aliases::WitnessedTarget)
		&& readback == RecoveryReadback::Complete
	{
		RecoveryObservation::Recovered(Recovered {
			intent,
			lease: live.lease,
		})
	} else {
		RecoveryObservation::Reconcile
	}
}

/// A logical publication model step could not be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Refusal {
	/// The operation does not follow the active phase.
	Order,
	/// Scope, head, lease, grant or current consent differs.
	Binding,
	/// The exact namespace or required native reports do not agree.
	Evidence,
}
