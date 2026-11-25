use std::num::{NonZeroU32, NonZeroU64};

use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DarwinEntryPrepared, DarwinFileIdentity, DarwinMetadataRecorded, DarwinPhaseError,
	DarwinPublishIntent, DarwinRequiredMetadata, DarwinStageSealed, DarwinStreamEvidence,
	DarwinVerificationRecorded, OwnerTimestamp, StreamDigest, StreamLength,
};

use super::fixture::{ENTRY, Fixture, PUBLIC_NAME, frame, native};

#[test]
fn accepted_phases_bind_exactly_to_the_prepared_entry() {
	let fixture = Fixture::new(MAX_FILE_LENGTH, PUBLIC_NAME);
	let seal = fixture.seal();
	let verification = fixture.verify(&seal);
	let metadata = fixture.metadata(&seal, &verification);
	let intent = fixture.intent(&seal, &verification, &metadata);
	assert_eq!(
		seal.binding().stage_id.model_id(),
		exacopy_model::StageId::from_bytes([0x44; 16])
	);
	assert_eq!(
		seal.binding().owner_digest,
		DarwinEntryPrepared::from_frame(&fixture.frame)
			.unwrap()
			.owner_digest()
	);
	assert_eq!(seal.binding().entry, ENTRY);
	assert_eq!(seal.binding(), verification.binding());
	assert_eq!(verification.binding(), metadata.binding());
	assert_eq!(metadata.binding(), intent.binding());
	assert_eq!(intent.target().stage, fixture.stage.identity);
	assert_eq!(intent.target().stage_directory, fixture.stage.directory);
	assert_eq!(intent.target().parent, fixture.parent);
	assert_eq!(intent.target().component.as_bytes(), PUBLIC_NAME);

	let seal_payload = seal.encode();
	let verify_payload = verification.encode();
	let metadata_payload = metadata.encode();
	let intent_payload = intent.encode();
	let decoded_seal = DarwinStageSealed::decode(&seal_payload).unwrap();
	let decoded_verification = DarwinVerificationRecorded::decode(&verify_payload).unwrap();
	let decoded_metadata = DarwinMetadataRecorded::decode(&metadata_payload).unwrap();
	let decoded_intent = DarwinPublishIntent::decode(&intent_payload).unwrap();
	assert_eq!(decoded_seal, seal);
	assert_eq!(decoded_verification, verification);
	assert_eq!(decoded_metadata, metadata);
	assert_eq!(decoded_intent, intent);
	assert_eq!(
		decoded_intent.check_prerequisites(
			NonZeroU64::MAX,
			&fixture.frame,
			&decoded_seal,
			&decoded_verification,
			&decoded_metadata,
		),
		Ok(())
	);
}

#[test]
fn initial_preparation_frame_and_current_stage_observation_must_both_match() {
	let fixture = Fixture::new(10, PUBLIC_NAME);
	let seal = fixture.seal();
	let alternate_head = ChainHead::after(10, [9; 32]).unwrap();
	let alternate = frame(
		FrameKind::EntryPrepared,
		fixture.frame.payload(),
		alternate_head,
	);
	assert_ne!(alternate.head().digest(), fixture.frame.head().digest());
	assert_eq!(
		seal.check_prerequisite(&alternate),
		Err(DarwinPhaseError::BindingMismatch)
	);

	let changed_birth = DarwinFileIdentity::new(
		fixture.stage.identity.volume(),
		fixture.stage.identity.inode(),
		fixture.stage.identity.generation(),
		OwnerTimestamp::new(1, 50).unwrap(),
	);
	assert_eq!(
		DarwinStageSealed::new(&fixture.frame, changed_birth, fixture.length),
		Err(DarwinPhaseError::IdentityMismatch)
	);
	assert_eq!(
		DarwinStageSealed::new(
			&fixture.frame,
			fixture.stage.identity,
			StreamLength::new(9).unwrap()
		),
		Err(DarwinPhaseError::StreamMismatch)
	);
}

#[test]
fn verification_refuses_switched_files_even_if_bytes_and_extents_agree() {
	let fixture = Fixture::new(10, PUBLIC_NAME);
	let seal = fixture.seal();
	let (source, stage) = fixture.measurements();
	let alternate_inode = native(10);
	let alias = DarwinFileIdentity::new(
		stage.identity.volume(),
		stage.identity.inode(),
		NonZeroU32::new(25),
		OwnerTimestamp::new(1, 50).unwrap(),
	);
	for (source, stage, expected) in [
		(
			DarwinStreamEvidence {
				identity: alias,
				..source
			},
			stage,
			DarwinPhaseError::AliasedIdentity,
		),
		(
			DarwinStreamEvidence {
				identity: alternate_inode,
				..source
			},
			stage,
			DarwinPhaseError::IdentityMismatch,
		),
		(
			source,
			DarwinStreamEvidence {
				identity: alternate_inode,
				..stage
			},
			DarwinPhaseError::IdentityMismatch,
		),
		(
			source,
			DarwinStreamEvidence {
				digest: StreamDigest::from_bytes([3; 32]),
				..stage
			},
			DarwinPhaseError::StreamMismatch,
		),
		(
			source,
			DarwinStreamEvidence {
				length: StreamLength::new(0).unwrap(),
				..stage
			},
			DarwinPhaseError::StreamMismatch,
		),
	] {
		assert_eq!(
			DarwinVerificationRecorded::new(&fixture.frame, &seal, source, stage),
			Err(expected),
			"source {source:?}, stage {stage:?}"
		);
	}
}

#[test]
fn metadata_refuses_changed_ownership_times_and_identity() {
	let fixture = Fixture::new(0, PUBLIC_NAME);
	let seal = fixture.seal();
	let verification = fixture.verify(&seal);
	let mut changed_access = fixture.required;
	changed_access.accessed_at = OwnerTimestamp::new(12, 5).unwrap();
	let mut changed_modification = fixture.required;
	changed_modification.modified_at = changed_access.accessed_at;
	let observed = fixture.required;
	let changed_owner = DarwinRequiredMetadata::new(
		0o600,
		NonZeroU32::new(502).unwrap(),
		20,
		observed.accessed_at,
		observed.modified_at,
	)
	.unwrap();
	let changed_group = DarwinRequiredMetadata::new(
		0o600,
		NonZeroU32::new(501).unwrap(),
		21,
		observed.accessed_at,
		observed.modified_at,
	)
	.unwrap();
	for required in [
		changed_owner,
		changed_group,
		changed_access,
		changed_modification,
	] {
		assert_eq!(
			DarwinMetadataRecorded::new(
				&fixture.frame,
				&seal,
				&verification,
				fixture.stage.identity,
				required
			),
			Err(DarwinPhaseError::MetadataMismatch),
			"observed {required:?}"
		);
	}
	assert_eq!(
		DarwinMetadataRecorded::new(&fixture.frame, &seal, &verification, native(18), observed),
		Err(DarwinPhaseError::IdentityMismatch)
	);
	assert_eq!(
		DarwinRequiredMetadata::new(
			0o644,
			observed.permissions().owner(),
			20,
			observed.accessed_at,
			observed.modified_at
		),
		Err(DarwinPhaseError::MetadataMismatch)
	);
}

#[test]
fn intent_refuses_rebound_phases_names_and_effect_sequences() {
	let fixture = Fixture::new(10, PUBLIC_NAME);
	let seal = fixture.seal();
	let verification = fixture.verify(&seal);
	let metadata = fixture.metadata(&seal, &verification);
	let intent = fixture.intent(&seal, &verification, &metadata);
	let changed_name = Fixture::new(10, b"target-\x81");
	let other_seal = changed_name.seal();
	let other_verification = changed_name.verify(&other_seal);
	let (source, stage) = fixture.measurements();
	let different_source = DarwinStreamEvidence {
		digest: StreamDigest::from_bytes([4; 32]),
		..source
	};
	let different_stage = DarwinStreamEvidence {
		digest: different_source.digest,
		..stage
	};
	let different_verification =
		DarwinVerificationRecorded::new(&fixture.frame, &seal, different_source, different_stage)
			.unwrap();
	assert_eq!(
		verification.check_prerequisites(&fixture.frame, &other_seal),
		Err(DarwinPhaseError::BindingMismatch)
	);
	assert_eq!(
		metadata.check_prerequisites(&fixture.frame, &seal, &different_verification),
		Err(DarwinPhaseError::BindingMismatch)
	);
	assert_eq!(
		DarwinPublishIntent::new(
			NonZeroU64::MAX,
			&fixture.frame,
			&seal,
			&other_verification,
			&metadata
		),
		Err(DarwinPhaseError::BindingMismatch)
	);
	assert_eq!(
		intent.check_prerequisites(
			NonZeroU64::new(1).unwrap(),
			&fixture.frame,
			&seal,
			&verification,
			&metadata
		),
		Err(DarwinPhaseError::BindingMismatch)
	);

	let mut forged_name = intent.encode();
	let name_at = unique_offset(&forged_name, PUBLIC_NAME);
	forged_name[name_at] ^= 1;
	assert_eq!(
		DarwinPublishIntent::decode(&forged_name)
			.unwrap()
			.check_prerequisites(
				NonZeroU64::MAX,
				&fixture.frame,
				&seal,
				&verification,
				&metadata,
			),
		Err(DarwinPhaseError::BindingMismatch)
	);
	for digest in [
		seal.record_digest(),
		verification.record_digest(),
		metadata.record_digest(),
	] {
		let mut forged_digest = intent.encode();
		let at = unique_offset(&forged_digest, digest.as_bytes());
		forged_digest[at] ^= 1;
		assert_eq!(
			DarwinPublishIntent::decode(&forged_digest)
				.unwrap()
				.check_prerequisites(
					NonZeroU64::MAX,
					&fixture.frame,
					&seal,
					&verification,
					&metadata
				),
			Err(DarwinPhaseError::BindingMismatch)
		);
	}
}

#[test]
fn changed_context_and_stage_token_cannot_reuse_phase_evidence() {
	let fixture = Fixture::new(10, PUBLIC_NAME);
	let seal = fixture.seal();
	let verification = fixture.verify(&seal);
	let metadata = fixture.metadata(&seal, &verification);
	let intent = fixture.intent(&seal, &verification, &metadata);
	let binding = seal.binding();
	for identifier in [
		&binding.context.job.as_bytes()[..],
		&binding.context.plan_digest.as_bytes()[..],
		&binding.entry.as_bytes()[..],
		&binding.owner_digest.as_bytes()[..],
		&binding.stage_id.as_bytes()[..],
	] {
		let mut forged = verification.encode();
		let at = unique_offset(&forged, identifier);
		forged[at] ^= 1;
		assert_eq!(
			DarwinVerificationRecorded::decode(&forged)
				.unwrap()
				.check_prerequisites(&fixture.frame, &seal),
			Err(DarwinPhaseError::BindingMismatch)
		);
	}
	let mut forged_epoch = intent.encode();
	let epoch_key_and_value = [0x02, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
	let at = unique_offset(&forged_epoch, &epoch_key_and_value);
	forged_epoch[at + epoch_key_and_value.len() - 1] ^= 1;
	assert_eq!(
		DarwinPublishIntent::decode(&forged_epoch)
			.unwrap()
			.check_prerequisites(
				NonZeroU64::MAX,
				&fixture.frame,
				&seal,
				&verification,
				&metadata,
			),
		Err(DarwinPhaseError::BindingMismatch)
	);
}

#[test]
fn intent_handles_the_maximum_raw_component_at_the_maximum_logical_extent() {
	let name = [0xff; MAX_UNIX_COMPONENT_BYTES];
	let fixture = Fixture::new(MAX_FILE_LENGTH, &name);
	let seal = fixture.seal();
	let verification = fixture.verify(&seal);
	let metadata = fixture.metadata(&seal, &verification);
	let intent = fixture.intent(&seal, &verification, &metadata);
	assert_eq!(
		DarwinPublishIntent::decode(&intent.encode()).unwrap(),
		intent
	);
}

fn unique_offset(bytes: &[u8], needle: &[u8]) -> usize {
	let mut positions = bytes
		.windows(needle.len())
		.enumerate()
		.filter(|(_, window)| *window == needle);
	let (start, _) = positions.next().expect("fixture value appears");
	assert!(positions.next().is_none(), "fixture value must be unique");
	start
}
