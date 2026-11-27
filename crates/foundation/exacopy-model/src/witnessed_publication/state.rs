use super::{
	Aliases, CaptureBoundary, LiveBinding, NameObservation, NamespaceObservation,
	NativeRenameOutcome, NativeWitnessOutcome, Refusal, ScopeBinding, SubmissionObservation,
	WitnessBarriers, WitnessObservation,
};
use crate::retained_prefix::Head;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
	CaptureClosed,
	WitnessIntent,
	WitnessSubmitted,
	WitnessLinked,
	WitnessSealed,
	RenameIntent,
	RenameSubmitted,
	Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Origin {
	scope: ScopeBinding,
	lease: [u8; 32],
}

/// One live witnessed publication decision from closed capture.
#[derive(Debug, Eq, PartialEq)]
pub struct Publication {
	origin: Origin,
	head: Head,
	phase: Phase,
}

/// One consumed logical witness-link request for the originating live process.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct WitnessSubmission {
	origin: Origin,
	head: Head,
}

/// One consumed logical rename request for the originating live process.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct RenameSubmission {
	origin: Origin,
	head: Head,
}

impl RenameSubmission {
	/// Returns the authorized head and model scope for the native submission gate.
	#[must_use]
	pub const fn binding(&self) -> (Head, ScopeBinding) {
		(self.head, self.origin.scope)
	}
}

impl Publication {
	/// Begins after the originating live capture closed its source and writer and synchronized the stage.
	///
	/// The caller must establish that `boundary` describes the exact clean
	/// current head in `live` and maintain one live state per lease and lineage.
	/// A head supplies arithmetic and binding evidence. The model cannot derive
	/// the semantic history or fresh live capture from it.
	///
	/// # Errors
	/// Refuses an unapproved binding, unclosed capture or mismatched stage name.
	pub fn begin(
		live: LiveBinding,
		names: NamespaceObservation,
		boundary: CaptureBoundary,
	) -> Result<Self, Refusal> {
		if !live.admitted(live.scope) {
			return Err(Refusal::Binding);
		}
		if boundary != CaptureBoundary::ClosedAndSynced || !names.aliases(live, Aliases::StageOnly)
		{
			return Err(Refusal::Evidence);
		}
		Ok(Self {
			origin: Origin {
				scope: live.scope,
				lease: live.lease,
			},
			head: live.head,
			phase: Phase::CaptureClosed,
		})
	}

	/// Confirms a durable and independently reread kind 41.
	///
	/// # Errors
	/// Refuses a different live binding, current approval or invalid successor.
	pub fn witness_intent(&mut self, live: LiveBinding) -> Result<(), Refusal> {
		self.require_current(live, Phase::CaptureClosed)?;
		if !live.head.is_successor_of(self.head) {
			return Err(Refusal::Binding);
		}
		self.head = live.head;
		self.phase = Phase::WitnessIntent;
		Ok(())
	}

	/// Consumes the single live link request after confirmed witness intent.
	///
	/// # Errors
	/// Refuses repeat submission, stale authority or unexpected namespace.
	pub fn submit_witness(
		&mut self,
		live: LiveBinding,
		names: NamespaceObservation,
	) -> Result<WitnessSubmission, Refusal> {
		self.require_live(live, Phase::WitnessIntent)?;
		if !names.aliases(live, Aliases::StageOnly) {
			return Err(Refusal::Evidence);
		}
		self.phase = Phase::WitnessSubmitted;
		Ok(WitnessSubmission {
			origin: self.origin,
			head: self.head,
		})
	}

	/// Reports one native witness-link result even after approval expires.
	///
	/// # Errors
	/// Refuses an unrelated submission or wrong active phase.
	pub fn observe_witness(
		&mut self,
		submission: WitnessSubmission,
		live: LiveBinding,
		names: NamespaceObservation,
		outcome: NativeWitnessOutcome,
	) -> Result<WitnessObservation, Refusal> {
		if self.phase != Phase::WitnessSubmitted {
			return Err(Refusal::Order);
		}
		if (submission.origin, submission.head) != (self.origin, self.head) {
			return Err(Refusal::Binding);
		}
		if self.same(live)
			&& outcome == NativeWitnessOutcome::Linked
			&& names.aliases(live, Aliases::WitnessedStage)
		{
			self.phase = Phase::WitnessLinked;
			Ok(WitnessObservation::Linked)
		} else {
			self.phase = Phase::Terminal;
			Ok(WitnessObservation::Reconcile(outcome))
		}
	}

	/// Confirms a linked, independently checked and synchronized witness seal.
	///
	/// The caller supplies the exact held inode and witness-directory barrier
	/// observations. The accepted seal head remains separate evidence.
	///
	/// # Errors
	/// Refuses changed authority, bad aliases or a stale seal.
	pub fn seal_witness(
		&mut self,
		live: LiveBinding,
		names: NamespaceObservation,
		witness_barriers: WitnessBarriers,
	) -> Result<(), Refusal> {
		self.require_current(live, Phase::WitnessLinked)?;
		if !live.head.is_successor_of(self.head) {
			return Err(Refusal::Binding);
		}
		if witness_barriers != WitnessBarriers::BothConfirmed
			|| !names.aliases(live, Aliases::WitnessedStage)
		{
			return Err(Refusal::Evidence);
		}
		self.head = live.head;
		self.phase = Phase::WitnessSealed;
		Ok(())
	}

	/// Confirms the checked closeout's verification, metadata and durable intent.
	///
	/// The three heads must come from the exact current independently observed
	/// and validated closeout. They supply no native operation capability.
	///
	/// # Errors
	/// Refuses invalid order, scope, authority, aliases or actual target absence.
	pub fn rename_intent(
		&mut self,
		live: LiveBinding,
		names: NamespaceObservation,
		verification: Head,
		metadata: Head,
	) -> Result<(), Refusal> {
		self.require_current(live, Phase::WitnessSealed)?;
		if !verification.is_successor_of(self.head)
			|| !metadata.is_successor_of(verification)
			|| !live.head.is_successor_of(metadata)
		{
			return Err(Refusal::Binding);
		}
		if !names.aliases(live, Aliases::WitnessedStage) || names.target != NameObservation::Absent
		{
			return Err(Refusal::Evidence);
		}
		self.head = live.head;
		self.phase = Phase::RenameIntent;
		Ok(())
	}

	/// Consumes the single live no-replace request before native submission.
	///
	/// # Errors
	/// Refuses a stale or already consumed intent, bad aliases or lost approval.
	pub fn submit_rename(
		&mut self,
		live: LiveBinding,
		names: NamespaceObservation,
	) -> Result<RenameSubmission, Refusal> {
		self.require_live(live, Phase::RenameIntent)?;
		if !names.aliases(live, Aliases::WitnessedStage) || names.target != NameObservation::Absent
		{
			return Err(Refusal::Evidence);
		}
		self.phase = Phase::RenameSubmitted;
		Ok(RenameSubmission {
			origin: self.origin,
			head: self.head,
		})
	}

	/// Reports one exact native result even if live authorization has expired.
	///
	/// The result is observation-point evidence and supplies no follow-up effect.
	///
	/// # Errors
	/// Refuses an unrelated submission or wrong active phase.
	pub fn observe_submission(
		&mut self,
		submission: RenameSubmission,
		live: LiveBinding,
		names: NamespaceObservation,
		outcome: NativeRenameOutcome,
	) -> Result<SubmissionObservation, Refusal> {
		use SubmissionObservation::{Conflict, Published, Reconcile};

		if self.phase != Phase::RenameSubmitted {
			return Err(Refusal::Order);
		}
		if (submission.origin, submission.head) != (self.origin, self.head) {
			return Err(Refusal::Binding);
		}
		self.phase = Phase::Terminal;
		if !self.same(live) {
			return Ok(Reconcile(outcome));
		}
		Ok(match outcome {
			NativeRenameOutcome::Success if names.aliases(live, Aliases::WitnessedTarget) => {
				Published
			}
			NativeRenameOutcome::Conflict
				if names.aliases(live, Aliases::WitnessedStage)
					&& matches!(names.target, NameObservation::Held(file)
						if file.identity != live.scope.stage
						&& file.identity.mount == live.scope.stage.mount
						&& file.identity.device == live.scope.stage.device
						&& file.links != 0) =>
			{
				Conflict
			}
			_ => Reconcile(outcome),
		})
	}

	fn require_live(&self, live: LiveBinding, phase: Phase) -> Result<(), Refusal> {
		self.require_current(live, phase)?;
		if live.head != self.head {
			return Err(Refusal::Binding);
		}
		Ok(())
	}

	fn require_current(&self, live: LiveBinding, phase: Phase) -> Result<(), Refusal> {
		if self.phase != phase {
			return Err(Refusal::Order);
		}
		if live.lease != self.origin.lease || !live.admitted(self.origin.scope) {
			return Err(Refusal::Binding);
		}
		Ok(())
	}

	fn same(&self, live: LiveBinding) -> bool {
		live.scope == self.origin.scope && live.lease == self.origin.lease && live.head == self.head
	}
}
