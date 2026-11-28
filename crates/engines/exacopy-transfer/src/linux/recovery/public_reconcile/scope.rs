use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::{ApplyRequestedDurability, LinuxFileIdentity, PublicApplyOwnerRecord};
use exacopy_plan::PlanIdentityPlatform;

use super::{LocalCopyPlan, PublicApplyReconcileSelection};

pub(super) fn select_owner(
	owner: &PublicApplyOwnerRecord,
	selected: &PublicApplyReconcileSelection<'_, '_, '_>,
) -> bool {
	let body = selected.approved.body();
	let fields = body.fields();
	let entry = selected.approved.entry();
	let manifest = owner.manifest();
	let binding = manifest.binding;
	let created = (
		manifest.owner.created.seconds(),
		manifest.owner.created.nanoseconds(),
	);
	let expiry = fields
		.expires_at
		.map(|time| (time.seconds(), time.nanoseconds()));
	binding.public_plan.as_bytes() == &body.digest()
		&& binding.public_entry.as_bytes() == entry.entry_id.as_bytes()
		&& binding.source_root.as_bytes() == entry.source.root_id.as_bytes()
		&& binding.destination_root.as_bytes() == entry.destination.root_id.as_bytes()
		&& binding.destination_root == selected.destination.id
		&& binding.stream_length.get() == entry.stream_length
		&& binding.stream_digest.as_bytes() == &entry.stream_digest
		&& binding.metadata_policy.as_bytes() == &entry.metadata_policy_digest
		&& binding.requested_durability == ApplyRequestedDurability::ProcessCrash
		&& binding
			.expires_at
			.map(|time| (time.seconds(), time.nanoseconds()))
			== expiry
		&& (fields.created_at.seconds(), fields.created_at.nanoseconds()) <= created
		&& expiry.is_none_or(|time| created < time)
}

pub(super) fn select_plan(
	plan: &LocalCopyPlan<'_>,
	selected: &PublicApplyReconcileSelection<'_, '_, '_>,
) -> bool {
	let source = plan.source();
	let destination = plan.destination();
	let entry = selected.approved.entry();
	plan.digest() == selected.private_plan
		&& plan.attempt().job_name == selected.job_name
		&& destination.root == selected.destination
		&& source.root_id.as_bytes() == entry.source.root_id.as_bytes()
		&& source.component.as_bytes() == entry.source.basename
		&& destination.component.as_bytes() == entry.destination.basename
		&& source.length == entry.stream_length
		&& entry.source_identity.is_some_and(|historical| {
			historical.platform == PlanIdentityPlatform::Linux
				&& historical.generation.is_none()
				&& historical.volume_id == source.file_identity.device().to_le_bytes()
				&& historical.object_id == source.file_identity.inode().to_le_bytes()
		})
}

pub(super) const fn identity(file: LinuxFileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: file.device(),
		inode: file.inode(),
	}
}
