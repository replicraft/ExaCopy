use core::num::NonZeroU32;

use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_journal::{
	DarwinEntryPrepared, DarwinFileIdentity, DarwinJobPrepared, DarwinPreparedError,
	DarwinRootBinding, DarwinSourceMetadata, DarwinSourceView, DarwinVolumeIdentity, JournalEpoch,
	JournalJobId, PlanDigest, PreparedError, RootCapabilityId,
};
use exacopy_model::StageId;

use super::fixtures::{
	context, destination, entry_id, identity, origin_volume, output_volume, owner, preparation,
	time,
};

#[test]
fn job_preparation_requires_the_exact_authenticated_owner_and_destination_volume() {
	let context = context();
	let signed = owner(0xcd);
	let destination = destination();
	let job = DarwinJobPrepared::new(context, &signed, destination).unwrap();
	assert_eq!(job.owner_digest(), signed.digest());
	assert_eq!(job.validate_owner(&signed), Ok(()));
	assert_eq!(
		job.validate_owner(&owner(0xcc)),
		Err(DarwinPreparedError::OwnerMismatch)
	);

	let mut wrong_context = context;
	wrong_context.plan_digest = PlanDigest::from_bytes([0xaa; 32]);
	assert_eq!(
		DarwinJobPrepared::new(wrong_context, &signed, destination),
		Err(DarwinPreparedError::OwnerMismatch)
	);

	wrong_context = context;
	let mut different_job = *context.job.as_bytes();
	different_job[15] ^= 1;
	wrong_context.job = JournalJobId::from_bytes(different_job).unwrap();
	assert_eq!(
		DarwinJobPrepared::new(wrong_context, &signed, destination),
		Err(DarwinPreparedError::OwnerMismatch)
	);

	let wrong_volume = DarwinRootBinding {
		identity: identity(origin_volume(), 31, Some(17)),
		..destination
	};
	assert_eq!(
		DarwinJobPrepared::new(context, &signed, wrong_volume),
		Err(DarwinPreparedError::VolumeMismatch)
	);

	let state_root = signed.manifest().state_root;
	let state_root_alias = DarwinFileIdentity::new(
		state_root.volume(),
		state_root.inode(),
		None,
		time(999, 111),
	);
	let wrong_root = DarwinRootBinding {
		identity: state_root_alias,
		..destination
	};
	assert_eq!(
		DarwinJobPrepared::new(context, &signed, wrong_root),
		Err(DarwinPreparedError::IdentityAlias)
	);
}

#[test]
fn replay_cannot_reuse_preparation_across_epochs_owner_records_or_root_capabilities() {
	let context = context();
	let signed = owner(0xcd);
	let job = DarwinJobPrepared::new(context, &signed, destination()).unwrap();
	let entry = DarwinEntryPrepared::new(&job, entry_id(), preparation()).unwrap();
	assert_eq!(entry.validate_job(&job), Ok(()));
	assert_eq!(entry.owner_digest(), signed.digest());

	let mut epoch = context;
	epoch.epoch = JournalEpoch::new(context.epoch.get() + 1);
	let mut wrong_capability = destination();
	let mut id = *wrong_capability.id.as_bytes();
	id[15] ^= 1;
	wrong_capability.id = RootCapabilityId::from_bytes(id).unwrap();
	let wrong_directory = DarwinRootBinding {
		identity: identity(output_volume(), 42, Some(17)),
		..destination()
	};
	for wrong_job in [
		DarwinJobPrepared::new(epoch, &signed, destination()).unwrap(),
		DarwinJobPrepared::new(context, &owner(0xde), destination()).unwrap(),
		DarwinJobPrepared::new(context, &signed, wrong_capability).unwrap(),
		DarwinJobPrepared::new(context, &signed, wrong_directory).unwrap(),
	] {
		assert_eq!(
			entry.validate_job(&wrong_job),
			Err(DarwinPreparedError::JobMismatch)
		);
	}
}

#[test]
fn the_stage_observation_cannot_alias_either_root_or_the_source_file() {
	let job = DarwinJobPrepared::new(context(), &owner(0xcd), destination()).unwrap();
	let original = preparation();
	let mut altered = original;
	altered.stage.directory = job.destination_root().identity;
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::IdentityAlias)
	);
	altered = original;
	altered.stage.identity = altered.stage.directory;
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::IdentityAlias)
	);
	altered = original;
	altered.stage.identity = identity(origin_volume(), 22, Some(18));
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::VolumeMismatch)
	);
	altered = original;
	altered.stage.directory = identity(origin_volume(), 32, None);
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::VolumeMismatch)
	);

	altered = original;
	let source = original.source;
	let root = DarwinRootBinding {
		identity: altered.stage.directory,
		..source.root()
	};
	altered.source = DarwinSourceView::new(
		root,
		source.component(),
		identity(output_volume(), 22, Some(18)),
		source.length(),
		source.times(),
		source.metadata(),
	)
	.unwrap();
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::IdentityAlias)
	);

	altered = original;
	let root = DarwinRootBinding {
		identity: identity(output_volume(), 21, None),
		..source.root()
	};
	let stage = altered.stage.identity;
	let alias = DarwinFileIdentity::new(stage.volume(), stage.inode(), None, time(999, 111));
	altered.source = DarwinSourceView::new(
		root,
		source.component(),
		alias,
		source.length(),
		source.times(),
		source.metadata(),
	)
	.unwrap();
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::IdentityAlias)
	);

	altered = original;
	altered.source = DarwinSourceView::new(
		job.destination_root(),
		altered.target_component,
		identity(output_volume(), 22, None),
		0,
		source.times(),
		source.metadata(),
	)
	.unwrap();
	assert_eq!(
		DarwinEntryPrepared::new(&job, entry_id(), altered),
		Err(DarwinPreparedError::IdentityAlias)
	);
}

#[test]
fn source_binding_rejects_mismatched_volume_bad_permissions_and_inconsistent_extent() {
	let source = preparation().source;
	assert_eq!(
		DarwinSourceView::new(
			source.root(),
			source.component(),
			source.identity(),
			MAX_FILE_LENGTH + 1,
			source.times(),
			source.metadata()
		),
		Err(PreparedError::InvalidSourceLength.into())
	);
	assert_eq!(
		DarwinSourceView::new(
			source.root(),
			source.component(),
			identity(output_volume(), 22, None),
			source.length(),
			source.times(),
			source.metadata()
		),
		Err(DarwinPreparedError::VolumeMismatch)
	);
	assert_eq!(
		DarwinSourceView::new(
			source.root(),
			source.component(),
			source.root().identity,
			source.length(),
			source.times(),
			source.metadata()
		),
		Err(DarwinPreparedError::IdentityAlias)
	);
	assert_eq!(
		DarwinSourceMetadata::new(0o644, source.metadata().owner(), source.metadata().group()),
		Err(PreparedError::UnsupportedSourceMetadata)
	);
	assert_eq!(
		DarwinSourceMetadata::new(0o600, NonZeroU32::MAX, source.metadata().group()),
		Err(PreparedError::UnsupportedSourceMetadata)
	);
}

#[test]
fn entry_preparation_requires_consistent_root_observations() {
	let destination = destination();
	let job = DarwinJobPrepared::new(context(), &owner(0xcd), destination).unwrap();
	let mut entry = preparation();
	let source = entry.source;
	let volume = destination.identity.volume();
	let conflicting_device = DarwinVolumeIdentity::new(77, volume.physical_fsid()).unwrap();
	let conflicting_fsid = DarwinVolumeIdentity::new(volume.device(), [77, 88]).unwrap();

	for root in [
		DarwinRootBinding {
			id: destination.id,
			identity: source.root().identity,
		},
		DarwinRootBinding {
			identity: identity(conflicting_device, destination.identity.inode().get(), None),
			..source.root()
		},
		DarwinRootBinding {
			identity: identity(conflicting_fsid, destination.identity.inode().get(), None),
			..source.root()
		},
	] {
		entry.source = DarwinSourceView::new(
			root,
			source.component(),
			identity(root.identity.volume(), 22, None),
			source.length(),
			source.times(),
			source.metadata(),
		)
		.unwrap();
		assert_eq!(
			DarwinEntryPrepared::new(&job, entry_id(), entry),
			Err(DarwinPreparedError::RootBindingMismatch),
		);
	}

	entry.source = DarwinSourceView::new(
		DarwinRootBinding {
			id: source.root().id,
			identity: destination.identity,
		},
		source.component(),
		identity(volume, 22, None),
		source.length(),
		source.times(),
		source.metadata(),
	)
	.unwrap();
	let record = DarwinEntryPrepared::new(&job, entry_id(), entry).unwrap();
	assert_eq!(
		DarwinEntryPrepared::decode(&record.encode()).unwrap(),
		record
	);
}

#[test]
fn stage_token_bytes_are_preserved_exactly_as_the_model_id() {
	let stage = preparation().stage;
	assert_eq!(
		*stage.id.as_bytes(),
		[
			0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
			0x8e, 0x8f,
		]
	);
	assert_eq!(
		stage.id.model_id(),
		StageId::from_bytes(*stage.id.as_bytes())
	);
}
