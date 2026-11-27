//! Binds the one model publication to the original live witnessed Linux holder.

use std::num::NonZeroU64;

use exacopy_journal::remote_download::witness::RemoteWitnessIntent;
use exacopy_journal::remote_download::witness::replay::RemoteWitnessedReplayPhase;
use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{
	Approval, CaptureBoundary, FileIdentity, HeldFile, LiveBinding, NameObservation,
	NamespaceObservation, NativeWitnessOutcome, Publication, Refusal, RenameSubmission,
	ScopeBinding, WitnessBarriers, WitnessObservation, WitnessSubmission,
};
use exacopy_platform::linux::{WitnessPublication, WitnessPublicationError, kernel_random};
use exacopy_transfer::remote_witnessed_finalization::{
	WitnessedLiveCut, WitnessedPublicationIntent,
};

use super::prepublication::{WitnessedAdapterError, confirm_successor};
use super::{LinkedWitnessedStage, WitnessAdmissionError, WitnessPass, model_head};
use crate::assembly::linux::remote_witness_authority::WitnessMutationGuard;

#[derive(Debug)]
pub(super) struct WitnessModel {
	scope: ScopeBinding,
	lease: [u8; 32],
}

pub(super) struct LinkedPublication {
	model: WitnessModel,
	state: Publication,
	verification: Option<Head>,
	metadata: Option<Head>,
}

impl WitnessModel {
	pub(super) fn new(
		pass: WitnessPass<'_, '_>,
		intent: RemoteWitnessIntent,
	) -> Result<Self, WitnessAdmissionError> {
		let mut lease = [0; 32];
		kernel_random(&mut lease).map_err(|_| WitnessAdmissionError::Binding)?;
		let binding = intent.binding();
		let context = binding.context();
		let ids = pass.current.facts().ids();
		let names = pass.names;
		let stage = FileIdentity {
			mount: NonZeroU64::new(ids.unique_mount).ok_or(WitnessAdmissionError::Binding)?,
			device: names.retained.file.device,
			inode: NonZeroU64::new(names.retained.file.inode)
				.ok_or(WitnessAdmissionError::Binding)?,
		};
		let consent = intent.consent();
		let subject = blake3::Hasher::new_derive_key("ExaCopy live witnessed model subject v1")
			.update(context.owner.as_bytes())
			.update(context.job.as_bytes())
			.update(context.entry.as_bytes())
			.update(binding.scope().as_bytes())
			.update(&binding.prepared().digest())
			.update(&binding.continuation().digest())
			.update(&intent.boundary().head.digest())
			.finalize();
		let mut namespace =
			blake3::Hasher::new_derive_key("ExaCopy live witnessed model namespace v1");
		namespace.update(&ids.boot_id);
		for number in [
			ids.mount_namespace,
			ids.mount_id,
			ids.unique_mount,
			ids.root.device,
			ids.root.inode,
			names.job.device(),
			names.job.inode(),
			names.retained.directory.device,
			names.retained.directory.inode,
			stage.device,
			stage.inode.get(),
		] {
			namespace.update(&number.to_le_bytes());
		}
		for name in [
			names.retained.stage.as_bytes(),
			names.retained.target.as_bytes(),
			&intent.witness_name(),
		] {
			let width = u16::try_from(name.len()).map_err(|_| WitnessAdmissionError::Binding)?;
			namespace.update(&width.to_le_bytes()).update(name);
		}
		Ok(Self {
			scope: ScopeBinding {
				subject: *subject.as_bytes(),
				namespace: *namespace.finalize().as_bytes(),
				stage,
				base_grant: consent.base_grant_digest,
				qualification: *pass.current.verified().digest().as_bytes(),
				approval: Approval {
					digest: consent.approval_digest,
					deadline: consent.deadline,
				},
			},
			lease,
		})
	}

	fn observation(&self, head: Head) -> LiveBinding {
		LiveBinding {
			scope: self.scope,
			lease: self.lease,
			base_grant: None,
			approval: None,
			now: None,
			head,
		}
	}

	fn admitted(&self, head: Head, guard: &WitnessMutationGuard<'_>) -> LiveBinding {
		self.admitted_at(head, guard.observed_wall_seconds())
	}

	fn admitted_at(&self, head: Head, now: Option<u64>) -> LiveBinding {
		LiveBinding {
			base_grant: Some(self.scope.base_grant),
			approval: Some(self.scope.approval),
			now,
			..self.observation(head)
		}
	}

	fn names(&self, witnessed: bool) -> NamespaceObservation {
		let held = NameObservation::Held(HeldFile {
			identity: self.scope.stage,
			links: if witnessed { 2 } else { 1 },
		});
		NamespaceObservation {
			lease: self.lease,
			namespace: self.scope.namespace,
			protected: true,
			stage: held,
			witness: if witnessed {
				held
			} else {
				NameObservation::Absent
			},
			target: NameObservation::Absent,
		}
	}

	pub(super) fn begin(
		&self,
		head: Head,
		guard: &WitnessMutationGuard<'_>,
	) -> Result<Publication, Refusal> {
		Publication::begin(
			self.admitted(head, guard),
			self.names(false),
			CaptureBoundary::ClosedAndSynced,
		)
	}

	pub(super) fn authorize_link(
		&self,
		state: &mut Publication,
		head: Head,
		guard: &WitnessMutationGuard<'_>,
	) -> Result<WitnessSubmission, Refusal> {
		let live = self.admitted(head, guard);
		state.witness_intent(live)?;
		state.submit_witness(live, self.names(false))
	}

	pub(super) fn linked(
		self,
		mut state: Publication,
		submission: WitnessSubmission,
		head: Head,
	) -> Result<LinkedPublication, WitnessAdmissionError> {
		let result = state
			.observe_witness(
				submission,
				self.observation(head),
				self.names(true),
				NativeWitnessOutcome::Linked,
			)
			.map_err(WitnessAdmissionError::Model)?;
		if result != WitnessObservation::Linked {
			return Err(WitnessAdmissionError::Binding);
		}
		Ok(LinkedPublication {
			model: self,
			state,
			verification: None,
			metadata: None,
		})
	}
}

impl LinkedPublication {
	pub(super) fn seal(&mut self, head: Head, admitted_at: Option<u64>) -> Result<(), Refusal> {
		self.state.seal_witness(
			self.model.admitted_at(head, admitted_at),
			self.model.names(true),
			WitnessBarriers::BothConfirmed,
		)
	}

	pub(super) fn verified(&mut self, head: Head) {
		self.verification = Some(head);
	}

	pub(super) fn metadata(&mut self, head: Head) {
		self.metadata = Some(head);
	}

	fn authorize_rename(&mut self, live: LiveBinding) -> Result<RenameSubmission, Refusal> {
		let verification = self.verification.ok_or(Refusal::Evidence)?;
		let metadata = self.metadata.ok_or(Refusal::Evidence)?;
		let names = self.model.names(true);
		self.state
			.rename_intent(live, names, verification, metadata)?;
		self.state.submit_rename(live, names)
	}
}

pub(in crate::assembly::linux::remote_continued) struct SubmittedPublication<'view, 'lease> {
	// Keep the single matching model state under the original native custody for
	// later consumption of the actual submission observation.
	logical: LinkedPublication,
	native: WitnessPublication<'view, 'lease>,
}

impl SubmittedPublication<'_, '_> {
	pub(in crate::assembly::linux::remote_continued) fn observation(
		&self,
	) -> &exacopy_platform::linux::WitnessPublicationObservation {
		self.native.observation()
	}
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum WitnessedSubmitError {
	Origin(WitnessedAdapterError),
	Native(WitnessPublicationError<WitnessAdmissionError>),
}

pub(super) fn submit<'view, 'lease>(
	prepared: WitnessedPublicationIntent<LinkedWitnessedStage<'view, 'lease, '_, '_>>,
) -> Result<SubmittedPublication<'view, 'lease>, WitnessedSubmitError> {
	let (linked, previous) = prepared.into_parts();
	let pass = linked.pass;
	let witness = linked.intent;
	linked
		.check_origin(WitnessedLiveCut {
			current: pass.current,
			witness,
			budget: pass.budget,
			previous,
		})
		.map_err(WitnessedSubmitError::Origin)?;
	let head = model_head(previous);
	let mut logical = linked.logical;
	let native = linked
		.chain
		.publish_witnessed(
			head,
			|input| {
				confirm_successor(
					input,
					pass.trust,
					pass.selection,
					witness,
					previous,
					RemoteWitnessedReplayPhase::PublishIntentRequiresObservation,
				)
			},
			|native| {
				let model = &logical.model;
				let root = pass.current.facts().ids().root;
				if native.intent != head
					|| native.model_stage != model.scope.stage
					|| native.stage != pass.names.retained
					|| native.destination.device() != root.device
					|| native.destination.inode() != root.inode
					|| native.job.device() != pass.names.job.device()
					|| native.job.inode() != pass.names.job.inode()
					|| native.authority.base_grant != model.scope.base_grant
					|| native.authority.qualification != model.scope.qualification
					|| native.authority.retention_approval != model.scope.approval.digest
					|| witness.consent().deadline != model.scope.approval.deadline
				{
					return Err(WitnessAdmissionError::Binding);
				}
				let mut guard = pass
					.approval
					.enter(pass.grant, pass.names)
					.map_err(WitnessAdmissionError::Consent)?;
				if !guard.recheck_locked() {
					return Err(WitnessAdmissionError::Consent(
						crate::assembly::linux::remote_witness_authority::ConsentRefusal::Clock,
					));
				}
				let live = model.admitted(head, &guard);
				let submission = logical
					.authorize_rename(live)
					.map_err(WitnessAdmissionError::Model)?;
				Ok((submission, guard))
			},
		)
		.map_err(WitnessedSubmitError::Native)?;
	Ok(SubmittedPublication { logical, native })
}

#[cfg(test)]
mod tests;
