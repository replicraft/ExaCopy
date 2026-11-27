use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{FileIdentity as ModelIdentity, RenameSubmission};

use super::{
	NativePrepublication, ReservedJournalRead, SealedProtectedWitness, StageError,
	WitnessReservationObservationError,
};
use crate::linux::{
	FileIdentity, PublishError, RetainedPrefixSelection, SourceObservation,
	WitnessReservationAuthority,
};

mod durability;
mod receipt;
mod record;

pub use durability::{
	WitnessDurabilityAppend, WitnessDurabilityEffect, WitnessDurabilityError,
	WitnessDurabilityRequest,
};
pub use receipt::{
	WitnessReceiptAppend, WitnessReceiptEffect, WitnessReceiptError, WitnessReceiptIdentity,
	WitnessReceiptNames, WitnessReceiptPlacement, WitnessReceiptPlan, WitnessReceiptRequest,
};
pub use record::WitnessObservationAppend;

/// Exact original native selection presented before the one exclusive rename.
#[derive(Clone, Copy, Debug)]
pub struct WitnessPublicationRequest<'name> {
	/// Independently accepted durable kind-7 boundary.
	pub intent: Head,
	/// Exact original private stage and public target names.
	pub stage: RetainedPrefixSelection<'name>,
	/// Original stage identity with the unique native mount number.
	pub model_stage: ModelIdentity,
	/// Exact held protected job.
	pub job: FileIdentity,
	/// Exact held destination directory.
	pub destination: FileIdentity,
	/// Exact original grant, retention and qualification commitments.
	pub authority: WitnessReservationAuthority,
}

/// Refusal before the native rename was submitted.
#[derive(Debug)]
pub enum WitnessPublicationError<E> {
	/// The exact accepted kind 7 or native custody could not be confirmed.
	Preflight(WitnessReservationObservationError),
	/// Independent application replay did not confirm the witnessed intent.
	IntentReplay(E),
	/// The current application authority or model denied submission.
	Admission(E),
	/// The supplied logical submission disagrees with the native request.
	ModelBinding,
}

/// Point-in-time status of one bound native name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WitnessPublicationName {
	/// The name could not be established as absent or as the held regular inode.
	#[default]
	Unobserved,
	/// The exact name was observed absent.
	Absent,
	/// An exact regular inode was held long enough to observe its native stamp.
	Regular(SourceObservation),
}

impl WitnessPublicationName {
	fn agrees(self, other: Self) -> bool {
		match (self, other) {
			(Self::Regular(first), Self::Regular(later)) => first.recheck(later).is_ok(),
			(Self::Absent, Self::Absent) => true,
			_ => false,
		}
	}
}

/// Read-only observations of the exact namespace around a submitted rename.
#[derive(Clone, Copy, Debug, Default)]
pub struct WitnessPublicationNames {
	/// Original private stage basename.
	pub private_stage: WitnessPublicationName,
	/// Protected job witness basename.
	pub protected_witness: WitnessPublicationName,
	/// Selected public destination basename.
	pub public_target: WitnessPublicationName,
}

impl WitnessPublicationNames {
	pub(in crate::linux::recovery::writer) fn agrees(self, other: Self) -> bool {
		self.private_stage.agrees(other.private_stage)
			&& self.protected_witness.agrees(other.protected_witness)
			&& self.public_target.agrees(other.public_target)
	}
}

/// Native result after one submitted no-replace call, before durability.
#[derive(Debug)]
pub enum WitnessPublicationObservation {
	/// Confirmed two-link public and witness names; the old private name was absent.
	Published(SourceObservation),
	/// Kernel conflict with independently observed intact aliases and distinct incumbent.
	Conflict(SourceObservation),
	/// Keep all known facts and reconcile under an independently checked policy.
	Reconcile {
		/// Actual return of the single native no-replace call.
		submission: Result<(), PublishError>,
		/// Point-in-time namespace facts where observations succeeded.
		names: Box<WitnessPublicationNames>,
		/// Why the expected positive or conflict observation could not be confirmed.
		observation_failure: Option<StageError>,
	},
}

/// The one consumed live submission and its read-only observation, still held under the original lease.
#[must_use]
pub struct WitnessPublication<'view, 'lease> {
	held: SealedProtectedWitness<'view, 'lease>,
	submission: Option<RenameSubmission>,
	observation: WitnessPublicationObservation,
	observation_head: Option<Head>,
	durability: durability::Progress,
	receipt: receipt::Progress,
}

impl WitnessPublication<'_, '_> {
	/// Returns the observation while the original custody remains held.
	#[must_use]
	pub const fn observation(&self) -> &WitnessPublicationObservation {
		&self.observation
	}

	/// Exact durable and independently confirmed outcome boundary, when recorded.
	#[must_use]
	pub const fn observation_head(&self) -> Option<Head> {
		self.observation_head
	}

	/// Releases original custody and returns the native fact, and its token if unspent.
	pub fn into_observation(self) -> (Option<RenameSubmission>, WitnessPublicationObservation) {
		(self.submission, self.observation)
	}
}

impl<'view, 'lease> SealedProtectedWitness<'view, 'lease> {
	/// Submits one no-replace rename under the current authority and exact durable kind 7.
	///
	/// The caller verifies the complete held journal and its expected selected intent.
	/// The gate may only authorize the matching live model submission and return its
	/// guard. The application binds the model lease, subject, namespace and exact
	/// approval deadline to this live operation. It performs no I/O, await,
	/// credential change or lease reentry. The guard
	/// is dropped when the syscall returns. Subsequent observations require no new
	/// authority and convey neither durability nor permission for another effect.
	///
	/// # Errors
	/// Consumes the holder on a preflight, replay or admission refusal. A result after
	/// any submitted syscall contains the exact observed outcome or reconciliation.
	pub fn publish_witnessed<G, E>(
		self,
		expected: Head,
		verify_intent: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
		enter: impl FnOnce(WitnessPublicationRequest<'_>) -> Result<(RenameSubmission, G), E>,
	) -> Result<WitnessPublication<'view, 'lease>, WitnessPublicationError<E>> {
		use WitnessPublicationError as Error;
		if self.phase != NativePrepublication::IntentSynced {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		}
		verify_intent(
			self.read_prepublication(expected)
				.map_err(Error::Preflight)?,
		)
		.map_err(Error::IntentReplay)?;
		self.recheck_prepublication(expected)
			.map_err(Error::Preflight)?;
		let rename = self
			.stage
			.prepare_rename()
			.map_err(|error| Error::Preflight(error.into()))?;
		let original = &self.active.reservation;
		let job = original.held.lease.job();
		let stage = original.held.stage.selection();
		let ids = original.held.eligibility.facts().ids();
		if ids.mount_id != job.root.mount {
			return Err(Error::ModelBinding);
		}
		let model_stage = ModelIdentity {
			mount: NonZeroU64::new(ids.unique_mount).ok_or(Error::ModelBinding)?,
			device: stage.file.device,
			inode: NonZeroU64::new(stage.file.inode).ok_or(Error::ModelBinding)?,
		};
		let request = WitnessPublicationRequest {
			intent: expected,
			stage,
			model_stage,
			job: job.identity(),
			destination: job.destination_identity(),
			authority: original.authority,
		};
		let (submission, guard) = enter(request).map_err(Error::Admission)?;
		let (intent, scope) = submission.binding();
		if intent != request.intent
			|| scope.stage != request.model_stage
			|| scope.base_grant != request.authority.base_grant
			|| scope.qualification != request.authority.qualification
			|| scope.approval.digest != request.authority.retention_approval
		{
			return Err(Error::ModelBinding);
		}
		let observation = rename.submit(guard);
		Ok(WitnessPublication {
			held: self,
			submission: Some(submission),
			observation,
			observation_head: None,
			durability: durability::Progress::Unspent,
			receipt: receipt::Progress::default(),
		})
	}
}

#[cfg(test)]
#[path = "../../../../../../../tests/unit/witness_publication.rs"]
mod tests;
