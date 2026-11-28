//! Scope and time controls from the owned managed preparation fixture.

use std::cell::Cell;
use std::fs::{File, Permissions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::managed_sync::activation::{
	ApprovalEnrollment, ApprovalError, ApprovalInput, ApprovalOperation, ApprovalProfile,
	ApprovalSelection, PreparedApprovalInput, PreparedRecreate, encode_host_selection,
	prepare_recreate_approval, with_scoped_prepared_recreate,
};
use exacopy_cli::assembly::linux::{CopyRoots, plan_new_file};
use exacopy_endpoint::UnixComponent;
use rustix::fs::FlockOperation::{NonBlockingLockExclusive, NonBlockingLockShared, Unlock};
use rustix::fs::{OFlags, flock};

use super::{
	ManagedSyncError, ManagedSyncPreviewError, PreparedManagedActionError, SUBJECT, Sandbox,
	SelectedSlot, SyncPreviewError, SyncProfileStoreError, SyncSide, TestResult, UnixTimestamp,
	assert_missing, exact, expected_identity, open_child, read,
};

pub(super) fn exercise_boundaries<'input>(
	selection: &ApprovalSelection<'_>,
	make: impl Fn() -> PreparedApprovalInput<'input>,
	roots: CopyRoots<'_>,
	scratch: &mut [u8],
	[profile, parent, slot]: [&File; 3],
) -> TestResult {
	let start = selection.review.ids.observed_at;
	let refused = |_: PreparedRecreate<'_>| -> Result<(), ApprovalError> {
		panic!("refused native custody reached the callback")
	};
	// Use independent descriptions of the real fixture directories. Shared
	// parent contention would admit another SH and therefore detects downgrade.
	flock(parent, NonBlockingLockShared)?;
	let busy =
		with_scoped_prepared_recreate(selection, make(), roots, scratch, || Some(start), refused);
	flock(parent, Unlock)?;
	assert!(matches!(
		busy,
		Err(ApprovalError::Prepared(PreparedManagedActionError::Pair(
			ManagedSyncError::Busy
		)))
	));
	flock(slot, NonBlockingLockExclusive)?;
	let busy =
		with_scoped_prepared_recreate(selection, make(), roots, scratch, || Some(start), refused);
	flock(slot, Unlock)?;
	assert!(matches!(
		busy,
		Err(ApprovalError::Prepared(
			PreparedManagedActionError::Directory(SyncProfileStoreError::Busy)
		))
	));
	for directory in [profile, parent, slot] {
		flock(directory, NonBlockingLockExclusive)?;
		flock(directory, Unlock)?;
	}

	let later = UnixTimestamp::new(start.seconds() + 1, start.nanoseconds())?;
	let [first, end] = selection.enrollment.window;
	assert!(first <= start && start < later && later < end);
	for (samples, entered) in [
		(
			[
				Some(start),
				Some(start),
				Some(start),
				Some(later),
				Some(start),
			],
			true,
		),
		(
			[
				Some(start),
				Some(start),
				Some(start),
				Some(start),
				Some(end),
			],
			true,
		),
		(
			[Some(start), Some(start), Some(start), Some(start), None],
			true,
		),
		([Some(start), Some(start), Some(start), None, None], false),
	] {
		let sampled = Cell::new(0);
		let attended = Cell::new(0);
		let time = || {
			let index = sampled.get();
			sampled.set(index + 1);
			samples.get(index).copied().flatten()
		};
		let result =
			with_scoped_prepared_recreate(selection, make(), roots, scratch, time, |held| {
				assert_eq!(held.origin().head, selection.enrollment.prepared);
				attended.set(attended.get() + 1);
				Ok(())
			});
		assert!(matches!(result, Err(ApprovalError::Time)));
		assert_eq!(attended.get(), u8::from(entered));
		assert_eq!(sampled.get(), if entered { 5 } else { 4 });
	}
	Ok(())
}

pub(in super::super) struct ClockMutationFixture<'fixture, 'selection> {
	pub(in super::super) profile_dir: &'fixture File,
	pub(in super::super) live: [&'fixture File; 2],
	pub(in super::super) selection: &'fixture ApprovalSelection<'selection>,
	pub(in super::super) review: [&'fixture [u8]; 8],
	pub(in super::super) approver: &'fixture SigningKey,
	pub(in super::super) roots: CopyRoots<'fixture>,
}

pub(in super::super) fn exercise_clock_mutations(
	sandbox: &mut Sandbox,
	fixture: ClockMutationFixture<'_, '_>,
	scratch: &mut [u8],
) -> TestResult {
	let [source_root, peer] = match fixture.selection.review.from {
		SyncSide::Left => fixture.live,
		SyncSide::Right => [fixture.live[1], fixture.live[0]],
	};
	let source = open_child(source_root, SUBJECT, OFlags::RDONLY)?;
	let metadata = source.metadata()?;
	let identity = expected_identity(&source)?;
	assert_eq!(metadata.mode() & 0o777, 0o600);
	let original = read(source_root, SUBJECT)?;
	assert_eq!(original, b"xyz");
	let start = fixture.selection.review.ids.observed_at;
	for (inject_at, name) in [
		(4_u8, b"approval-clock-ingress".as_slice()),
		(5_u8, b"approval-clock-postflight".as_slice()),
	] {
		// chmod advances ctime. Each fault starts with fresh independent
		// fixture approval and origin for the then-current private Plan.
		let enrollment = fixture.selection.enrollment;
		let subject = UnixComponent::new(SUBJECT)?;
		let plan = plan_new_file(fixture.roots, enrollment.attempt, subject, subject)?;
		let slot = SelectedSlot::new_named(sandbox, fixture.profile_dir, name)?;
		let salt = 0x60 + inject_at;
		let mut enrolled = ApprovalEnrollment {
			origin_ids: [enrollment.origin_ids[0], [salt; 16]],
			activation: [salt + 8; 16],
			private_plan: plan.digest(),
			role_projections: slot.roles,
			..*enrollment
		};
		enrolled.prepared = slot.establish_origin(fixture.selection.review, &enrolled)?;
		let profile = &fixture.selection.profile;
		let selected = ApprovalSelection {
			profile: ApprovalProfile {
				path: profile.path,
				owner_key: profile.owner_key,
				selection: profile.selection,
				acknowledgement: profile.acknowledgement,
			},
			review: fixture.selection.review,
			enrollment: &enrolled,
		};
		let (host, host_digest) = encode_host_selection(&selected)?;
		let input = || ApprovalInput {
			host: &host,
			host_digest,
			review: fixture.review,
		};
		let now = || Some(start);
		let draft = prepare_recreate_approval(
			&selected,
			input(),
			ApprovalOperation::Preview,
			fixture.roots,
			scratch,
			now,
		)?;
		let signed = prepare_recreate_approval(
			&selected,
			input(),
			ApprovalOperation::Sign {
				confirmed_body: draft.body_digest,
				signer: fixture.approver,
			},
			fixture.roots,
			scratch,
			now,
		)?;
		let (activation, activation_digest) =
			signed.activation.ok_or("missing fixture approval")?;
		let expected_origin = exact(&slot.segment)?;
		let sampled = Cell::new(0);
		let attended = Cell::new(0);
		let fault = || {
			let count = sampled.get() + 1;
			sampled.set(count);
			if count == inject_at {
				source
					.set_permissions(Permissions::from_mode(0o400))
					.expect("change only the owned source mode during the clock sample");
			}
			Some(start)
		};
		let observed = with_scoped_prepared_recreate(
			&selected,
			PreparedApprovalInput {
				approval: input(),
				slot: slot.native,
				grant: &signed.grant,
				parent: &signed.parent,
				activation: &activation,
				activation_digest,
			},
			fixture.roots,
			scratch,
			fault,
			|held| {
				assert_eq!(held.origin().head, enrolled.prepared);
				attended.set(attended.get() + 1);
				Ok(())
			},
		);
		let changed_mode = source.metadata()?.mode() & 0o777;
		source.set_permissions(metadata.permissions())?;
		assert_eq!(changed_mode, 0o400, "clock mode fault did not take effect");
		assert!(
			matches!(
				observed,
				Err(ApprovalError::Scope(ManagedSyncPreviewError::Managed(
					ManagedSyncError::Preview(SyncPreviewError::Changed)
				)))
			),
			"clock sample {inject_at} must refuse changed source"
		);
		assert_eq!(sampled.get(), inject_at);
		assert_eq!(attended.get(), u8::from(inject_at == 5));
		let named = open_child(source_root, SUBJECT, OFlags::RDONLY)?;
		assert_eq!(expected_identity(&named)?, identity);
		assert_eq!(named.metadata()?.mode() & 0o777, 0o600);
		assert_eq!(read(source_root, SUBJECT)?, original);
		assert_missing(peer, SUBJECT);
		assert_missing(peer, enrolled.attempt.job_name.as_bytes());
		let named_segment = open_child(&slot.directory, super::SEGMENT, OFlags::RDONLY)?;
		assert_eq!(
			expected_identity(&named_segment)?,
			expected_identity(&slot.segment)?
		);
		assert_eq!(exact(&named_segment)?, expected_origin);
		assert_missing(&slot.directory, b"activation.claim");
	}
	Ok(())
}
