use std::ptr;

use ed25519_dalek::VerifyingKey;
use exacopy_journal::{
	ApprovedPublicPlanDigest, LinuxFileIdentity, OwnerProfileId, OwnerTimestamp, OwnerToken,
	PlanDigest, PublicApplyBinding,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::FileIdentity;
use exacopy_transfer::linux::PublicApplyStageRequest;

use super::{CopyRoots, LocalApplyGrantError, LocalApplyHostSelection, LocalApplyRootSelection};

pub(super) struct AttemptScope {
	pub(super) binding: PublicApplyBinding,
	pub(super) copy: CopyBinding,
	pub(super) private_plan: PlanDigest,
	pub(super) max_buffer: u64,
	pub(super) source_file: LinuxFileIdentity,
	owner_profile: OwnerProfileId,
	owner_key: VerifyingKey,
	owner_token: OwnerToken,
	pub(super) created: OwnerTimestamp,
}

impl AttemptScope {
	pub(super) fn capture(
		host: &LocalApplyHostSelection<'_>,
		approved: ApprovedPublicPlanDigest,
		roots: CopyRoots<'_>,
		request: &PublicApplyStageRequest<'_, '_, '_>,
	) -> Result<Self, LocalApplyGrantError> {
		use LocalApplyGrantError::Scope;

		let binding = request.binding;
		let private = request.private_plan;
		let source = private.source();
		let target = private.destination();
		let attempt = private.attempt();
		let entry = request.approved.entry();
		let fields = request.approved.body().fields();
		let created = request.profile.created;
		let expiry = fields.expires_at.ok_or(Scope)?;
		let expiry =
			OwnerTimestamp::new(expiry.seconds(), expiry.nanoseconds()).map_err(|_| Scope)?;
		if approved != host.approved_plan
			|| request.approved.body().digest() != *approved.as_bytes()
			|| binding.public_plan != approved
			|| entry.entry_id.as_bytes() != host.public_entry.as_bytes()
			|| entry.source.root_id.as_bytes() != host.source.alias.as_bytes()
			|| entry.destination.root_id.as_bytes() != host.destination.alias.as_bytes()
			|| entry.source.basename != host.source.name.as_bytes()
			|| entry.destination.basename != host.destination.name.as_bytes()
			|| binding.stream_length.get() != entry.stream_length
			|| binding.stream_digest.as_bytes() != &entry.stream_digest
			|| binding.metadata_policy.as_bytes() != &entry.metadata_policy_digest
			|| binding.expires_at != Some(expiry)
			|| (created.seconds(), created.nanoseconds())
				< (fields.created_at.seconds(), fields.created_at.nanoseconds())
			|| binding.public_entry != host.public_entry
			|| request.profile.id != host.owner_profile
			|| request.profile.signer.verifying_key() != *host.owner_key
			|| binding.source_root != host.source.alias
			|| binding.destination_root != host.destination.alias
			|| !matches_root(host.source, roots.source_id, roots.source.identity())
			|| !matches_root(
				host.destination,
				roots.destination_id,
				roots.destination.identity(),
			)
			|| source.root_id != host.source.alias
			|| source.root_identity != host.source.identity
			|| source.component.as_bytes() != host.source.name.as_bytes()
			|| target.root.id != host.destination.alias
			|| target.root.identity != host.destination.identity
			|| target.component.as_bytes() != host.destination.name.as_bytes()
			|| binding.private_entry != attempt.entry
			|| binding.epoch != attempt.epoch
		{
			return Err(Scope);
		}

		Ok(Self {
			binding,
			copy: CopyBinding::new(
				JobId::try_from_bytes(*attempt.job.as_bytes()).map_err(|_| Scope)?,
				EntryId::new(1),
				RunEpoch::new(attempt.epoch.get()),
				StageId::from_bytes(*attempt.entry.as_bytes()),
			),
			private_plan: private.digest(),
			max_buffer: fields.resource_limits.buffer_budget_bytes(),
			source_file: source.file_identity,
			owner_profile: host.owner_profile,
			owner_key: *host.owner_key,
			owner_token: request.profile.owner_token,
			created,
		})
	}

	pub(super) fn matches(
		&self,
		selected: CopyRoots<'_>,
		roots: CopyRoots<'_>,
		request: &PublicApplyStageRequest<'_, '_, '_>,
	) -> bool {
		ptr::eq(selected.source, roots.source)
			&& ptr::eq(selected.destination, roots.destination)
			&& selected.source_id == roots.source_id
			&& selected.destination_id == roots.destination_id
			&& request.approved.body().digest() == *self.binding.public_plan.as_bytes()
			&& request.approved.entry().entry_id.as_bytes() == self.binding.public_entry.as_bytes()
			&& request.binding == self.binding
			&& request.private_plan.digest() == self.private_plan
			&& request.profile.id == self.owner_profile
			&& request.profile.signer.verifying_key() == self.owner_key
			&& request.profile.owner_token == self.owner_token
			&& request.profile.created == self.created
	}
}

fn matches_root(
	host: LocalApplyRootSelection<'_>,
	alias: exacopy_journal::RootCapabilityId,
	actual: FileIdentity,
) -> bool {
	host.alias == alias && host.identity == LinuxFileIdentity::new(actual.device(), actual.inode())
}
