use exacopy_cli::assembly::linux::managed_sync::{
	ManagedSyncSelection, ManualRecreateCandidate, ManualRecreateError, ManualRecreatePlanIds,
	prepare_manual_recreate,
};
use exacopy_manifest::sync_baseline::LinuxOwnerMode;
use exacopy_model::SyncConflict;
use exacopy_plan::{PlanBody, PlanEntriesPage, PlanOperation, PlanPublication, UnixTimestamp};
use uuid::{Builder, Uuid};

use super::*;

const RETAINED: &[u8] = b"manual-recreate-held-fixture-subject";

pub(super) fn exercise(
	sandbox: &mut Sandbox,
	policy: &ManagedPolicy,
	live: [&File; 2],
	selection: &ManagedSyncSelection,
) -> TestResult {
	use SyncConflict::{DeletionAgainstUnchanged, EditAgainstDeletion};
	use SyncSide::{Left, Right};

	let original = [
		open_child(live[0], SUBJECT, OFlags::RDONLY)?,
		open_child(live[1], SUBJECT, OFlags::RDONLY)?,
	];
	let original_ids = [
		object(&original[0].metadata()?),
		object(&original[1].metadata()?),
	];
	assert!(matches!(
		prepare_manual_recreate(
			selection,
			Left,
			DeletionAgainstUnchanged { absent: Right },
			ids(),
			&mut [0; 16]
		),
		Err(ManualRecreateError::ReviewChanged)
	));
	for (source, from, expected, wrong, payload) in [
		(
			0,
			Left,
			DeletionAgainstUnchanged { absent: Right },
			EditAgainstDeletion { edited: Left },
			b"abc",
		),
		(
			1,
			Right,
			EditAgainstDeletion { edited: Right },
			DeletionAgainstUnchanged { absent: Left },
			b"xyz",
		),
	] {
		let target = 1 - source;
		move_fixture_subject(sandbox, live[target], SUBJECT, RETAINED)?;
		let result = (|| {
			assert_missing(live[target], SUBJECT);
			let candidate =
				prepare_manual_recreate(selection, from, expected, ids(), &mut [0; 16])?;
			let other = match from {
				Left => Right,
				Right => Left,
			};
			for (side, review) in [(other, expected), (from, wrong)] {
				assert!(matches!(
					prepare_manual_recreate(selection, side, review, ids(), &mut [0; 16]),
					Err(ManualRecreateError::ReviewChanged)
				));
			}
			assert_missing(live[target], SUBJECT);
			assert_eq!(read(live[source], SUBJECT)?, payload);
			assert_eq!(
				read(live[target], RETAINED)?,
				if target == 0 { b"abc" } else { b"xyz" }
			);
			Ok::<_, Box<dyn Error>>(candidate)
		})();
		move_fixture_subject(sandbox, live[target], RETAINED, SUBJECT)?;
		let candidate = result?;
		assert_candidate(
			&candidate,
			selection,
			policy,
			live,
			(source, from, expected, payload),
		)?;
		assert_live(live, [b"abc", b"xyz"])?;
		for (root, id) in live.into_iter().zip(original_ids) {
			assert_eq!(
				object(&open_child(root, SUBJECT, OFlags::RDONLY)?.metadata()?),
				id
			);
			assert_missing(root, RETAINED);
		}
	}
	Ok(())
}

fn move_fixture_subject(
	sandbox: &mut Sandbox,
	held_root: &File,
	from: &[u8],
	to: &[u8],
) -> TestResult {
	let writer = open_child(
		&sandbox.directory,
		b"live",
		OFlags::RDONLY | OFlags::DIRECTORY,
	)?;
	flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
	sandbox.rename(held_root, from, to)
}

fn assert_candidate(
	result: &ManualRecreateCandidate,
	selection: &ManagedSyncSelection,
	policy: &ManagedPolicy,
	live: [&File; 2],
	expected: (usize, SyncSide, SyncConflict, &[u8]),
) -> TestResult {
	let (source, from, conflict, payload) = expected;
	assert_eq!(result.policy_digest, selection.policy_digest());
	assert_eq!(
		result.predecessor_digest,
		policy.history.root.reference.digest
	);
	assert_eq!(result.subject, SUBJECT);
	assert_eq!(result.from, from);
	assert_eq!(result.conflict, conflict);
	for (index, actual) in result.roots.iter().enumerate() {
		let metadata = live[index].metadata()?;
		assert_eq!(actual.managed_locator, policy.endpoints[index].root);
		assert_eq!(
			(
				actual.observed_identity.device(),
				actual.observed_identity.inode()
			),
			(metadata.dev(), metadata.ino())
		);
		assert_eq!(
			actual.child_alias,
			copy_alias(selection.owner_key(), &metadata)
		);
	}
	let target = 1 - source;
	let file = open_child(live[source], SUBJECT, OFlags::RDONLY)?.metadata()?;
	assert_eq!(
		(
			result.source_identity.device(),
			result.source_identity.inode()
		),
		(file.dev(), file.ino())
	);
	assert_eq!(result.source.byte_len, payload.len() as u64);
	assert_eq!(
		result.source.content_digest,
		*blake3::hash(payload).as_bytes()
	);
	let required = LinuxOwnerMode {
		mode: u16::try_from(file.mode() & 0o777)?,
		uid: file.uid(),
		gid: file.gid(),
	};
	assert_eq!(result.source.required_metadata_digest, required.digest()?);

	let child = &result.child;
	let body = PlanBody::from_canonical_cbor(child.digest(), child.canonical_body())?;
	let fields = body.fields();
	assert!(fields.approval_required);
	assert_eq!(fields.operation, PlanOperation::Copy);
	assert_eq!(fields.policy.publication, PlanPublication::PerFile);
	assert_eq!(fields.source_roots, [result.roots[source].child_alias]);
	assert_eq!(fields.destination_root, result.roots[target].child_alias);
	assert_eq!(fields.entry_pages, [child.page_ref()]);
	let page =
		PlanEntriesPage::from_canonical_cbor(child.page_ref(), child.canonical_page())?.entry();
	assert_eq!(
		(page.source.basename, page.destination.basename),
		(SUBJECT, SUBJECT)
	);
	assert_eq!(
		(page.source.root_id, page.destination.root_id),
		(
			result.roots[source].child_alias,
			result.roots[target].child_alias
		)
	);
	let native = page.source_identity.unwrap();
	assert_eq!(native.volume_id, file.dev().to_le_bytes());
	assert_eq!(native.object_id, file.ino().to_le_bytes());
	assert_eq!(page.stream_digest, *blake3::hash(payload).as_bytes());
	Ok(())
}

fn copy_alias(key: [u8; 32], metadata: &std::fs::Metadata) -> Uuid {
	let mut encoded = [0; 16];
	blake3::Hasher::new_derive_key("ExaCopy local CLI root ID v1")
		.update(&key)
		.update(&metadata.dev().to_le_bytes())
		.update(&metadata.ino().to_le_bytes())
		.finalize_xof()
		.fill(&mut encoded);
	Builder::from_custom_bytes(encoded).into_uuid()
}

fn ids() -> ManualRecreatePlanIds {
	let mut bytes = [0x31; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	ManualRecreatePlanIds {
		plan: Uuid::from_bytes(bytes),
		entry: Uuid::from_bytes([0x42; 16]),
		source_view: Uuid::from_bytes([0x43; 16]),
		measurement: Uuid::from_bytes([0x44; 16]),
		observed_at: UnixTimestamp::new(1, 0).unwrap(),
	}
}
