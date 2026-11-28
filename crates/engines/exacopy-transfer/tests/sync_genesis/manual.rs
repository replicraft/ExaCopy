use core::num::NonZeroU16;
use std::io::{self, Cursor};

use exacopy_plan::workflow_sync::{
	MAX_MEMBER_BYTES, WorkflowError, WorkflowKind, WorkflowRef, decode_envelope, decode_root,
};
use exacopy_transfer::sync_genesis::{
	SelectedSyncGenesisMember, inspect_selected_sync_genesis,
	inspect_selected_sync_genesis_retained,
};

use super::{ExpectedSyncGenesis, Fixture, SyncGenesisError, first, owner};

#[cfg(target_os = "linux")]
#[path = "manual/preview.rs"]
mod preview;

fn selected_members(fixture: &Fixture<'_>) -> [SelectedSyncGenesisMember<usize>; 3] {
	// These commitments locate only the fixture resource. The independent
	// expected root digest, key, and endpoint facts still control trust.
	let envelope = decode_envelope(&fixture.root).expect("canonical fixture envelope");
	let root = decode_root(envelope.body).expect("canonical fixture root");
	[
		SelectedSyncGenesisMember {
			reference: root.leaf,
			locator: 2,
		},
		SelectedSyncGenesisMember {
			reference: root.endpoints[1],
			locator: 1,
		},
		SelectedSyncGenesisMember {
			reference: root.endpoints[0],
			locator: 0,
		},
	]
}

fn extent(length: usize) -> NonZeroU16 {
	NonZeroU16::new(u16::try_from(length).expect("fixture extent fits"))
		.expect("fixture extent is nonzero")
}

#[test]
fn manual_selection_reads_exactly_the_three_committed_resources_in_signed_order() {
	let fixture = first();
	let key = owner();
	let expected = fixture.expected(&key);
	let mut root_buffer = [0; MAX_MEMBER_BYTES];
	let mut opened = Vec::new();
	let result = inspect_selected_sync_genesis(
		Cursor::new(fixture.root.as_slice()),
		extent(fixture.root.len()),
		&mut root_buffer,
		&expected,
		selected_members(&fixture),
		|locator| {
			opened.push(locator);
			Ok(Cursor::new(fixture.members[locator].as_slice()))
		},
	)
	.expect("admit complete explicitly selected historical evidence");
	assert_eq!(opened, [0, 1, 2]);
	assert_eq!(result.digest(), expected.root_digest);
	assert_eq!(result.endpoints(), &expected.endpoints);
	assert_eq!(result.root().name, expected.subject);
	assert_eq!(
		result.root().scan,
		expected.scan.expect("selected fixture scan")
	);
	let [left, right] = result.sides();
	assert_ne!(left.measured.identity.root, right.measured.identity.root);
	assert_ne!(left.measured.identity.file, right.measured.identity.file);
	assert_eq!(left.length, fixture.length);
	assert_eq!(right.length, fixture.length);
	assert_eq!(left.stream_digest, right.stream_digest);
}

#[test]
fn manual_root_boundary_and_selection_refuse_before_opening_any_child() {
	let fixture = first();
	let key = owner();
	let expected = fixture.expected(&key);
	let wrong_digest = ExpectedSyncGenesis {
		root_digest: [0; 32],
		..expected
	};
	let wrong_subject = ExpectedSyncGenesis {
		subject: exacopy_endpoint::UnixComponent::new(b"different-subject")
			.expect("valid independent subject"),
		..expected
	};
	let refusal = |length, selection: &ExpectedSyncGenesis<'_>| {
		let mut root_buffer = [0; MAX_MEMBER_BYTES];
		match inspect_selected_sync_genesis(
			Cursor::new(fixture.root.as_slice()),
			extent(length),
			&mut root_buffer,
			selection,
			selected_members(&fixture),
			|_| -> io::Result<Cursor<&[u8]>> { panic!("opened child before root admission") },
		) {
			Ok(_) => panic!("unexpected admission at root boundary"),
			Err(error) => error,
		}
	};
	assert!(matches!(
		refusal(MAX_MEMBER_BYTES + 1, &expected),
		SyncGenesisError::Wire(WorkflowError::Size)
	));
	assert!(matches!(
		refusal(fixture.root.len() - 1, &expected),
		SyncGenesisError::Closure
	));
	assert!(matches!(
		refusal(fixture.root.len() + 1, &expected),
		SyncGenesisError::Read(_)
	));
	assert!(matches!(
		refusal(fixture.root.len(), &wrong_digest),
		SyncGenesisError::Closure
	));
	assert!(matches!(
		refusal(fixture.root.len(), &wrong_subject),
		SyncGenesisError::Selection
	));
}

#[test]
fn wrong_manual_inventory_refuses_before_opening_any_child() {
	let fixture = first();
	let key = owner();
	let expected = fixture.expected(&key);
	let [_, right, left] = selected_members(&fixture);
	for unrelated in [
		left.reference,
		WorkflowRef {
			kind: WorkflowKind::Leaf,
			..right.reference
		},
		WorkflowRef {
			digest: [0; 32],
			..right.reference
		},
		WorkflowRef {
			byte_len: right.reference.byte_len + 1,
			..right.reference
		},
	] {
		let mut members = selected_members(&fixture);
		members[1].reference = unrelated;
		let mut root_buffer = [0; MAX_MEMBER_BYTES];
		let result = inspect_selected_sync_genesis(
			Cursor::new(fixture.root.as_slice()),
			extent(fixture.root.len()),
			&mut root_buffer,
			&expected,
			members,
			|_| -> io::Result<Cursor<&[u8]>> { panic!("opened child before inventory admission") },
		);
		assert!(matches!(result, Err(SyncGenesisError::Closure)));
	}
}

#[test]
fn retained_selection_copies_the_same_verified_bounded_bytes_without_reopening() {
	let fixture = first();
	let key = owner();
	let expected = fixture.expected(&key);
	let mut buffer = [0; MAX_MEMBER_BYTES];
	let mut calls = Vec::new();
	let (history, retained) = inspect_selected_sync_genesis_retained(
		Cursor::new(&fixture.root),
		extent(fixture.root.len()),
		&mut buffer,
		&expected,
		selected_members(&fixture),
		|locator| {
			assert!(!calls.contains(&locator));
			calls.push(locator);
			Ok(Cursor::new(&fixture.members[locator]))
		},
	)
	.unwrap();
	let [left, right, leaf] = fixture.members.each_ref().map(Vec::as_slice);
	assert_eq!(calls, [0, 1, 2]);
	assert_eq!(history.digest(), expected.root_digest);
	assert_eq!(
		retained.members(),
		[fixture.root.as_slice(), left, right, leaf]
	);

	let mut tailed = fixture.members[2].clone();
	tailed.push(0);
	assert!(matches!(
		inspect_selected_sync_genesis_retained(
			Cursor::new(&fixture.root),
			extent(fixture.root.len()),
			&mut buffer,
			&expected,
			selected_members(&fixture),
			|locator| Ok(Cursor::new(if locator == 2 {
				&tailed
			} else {
				&fixture.members[locator]
			})),
		),
		Err(SyncGenesisError::Closure)
	));
}
