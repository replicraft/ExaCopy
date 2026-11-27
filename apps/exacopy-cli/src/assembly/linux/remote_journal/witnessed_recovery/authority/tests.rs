use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::TryLockError;
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{RetryBlock, RetryError};
use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::qualification::continuation::RemoteContinuationQualificationError;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::WitnessRetentionCommitment;
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteScopeDigest};
use exacopy_journal::{JournalEntryId, JournalJobId, OwnerDigest};

use super::{ApprovalDeadline, AuthorityError, ClockSample, Error, RecoveryApproval, RemoteGrant};

const SCOPE: RemoteScopeDigest = RemoteScopeDigest::from_bytes([0x44; 32]);
const GRANT: [u8; 32] = [0x55; 32];
const TEN_MINUTES: Duration = Duration::from_secs(600);

fn context() -> RemoteDownloadContext {
	RemoteDownloadContext {
		owner: OwnerDigest::from_bytes([0x11; 32]),
		job: JournalJobId::from_bytes([
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd,
		])
		.unwrap(),
		entry: JournalEntryId::from_bytes([0x22; 16]),
	}
}

fn intent() -> RemoteReplayBoundary {
	RemoteReplayBoundary {
		head: ChainHead::after(12, [0x33; 32]).unwrap(),
		offset: 4096,
	}
}

fn commitment() -> WitnessRetentionCommitment {
	let clock = ClockSample::now().unwrap();
	let deadline = NonZeroU64::new((clock.wall + TEN_MINUTES).as_secs()).unwrap();
	WitnessRetentionCommitment::measure(context(), SCOPE, GRANT, deadline).unwrap()
}

fn grant_for(duration: Duration) -> RemoteGrant {
	RemoteGrant::new(SCOPE, GRANT, Instant::now() + duration).unwrap()
}

fn selected(grant: &RemoteGrant) -> RecoveryApproval<'_> {
	RecoveryApproval::select(intent(), context(), SCOPE, commitment(), grant).unwrap()
}

#[test]
fn consuming_approval_requires_the_exact_original_cut_scope_owner_and_commitment() {
	let grant = grant_for(TEN_MINUTES);
	let commitment = commitment();
	let selected =
		RecoveryApproval::select(intent(), context(), SCOPE, commitment, &grant).unwrap();
	assert_eq!(selected.intent(), intent());
	assert!(selected.matches_cut(intent(), context(), SCOPE, commitment));

	let different_head = RemoteReplayBoundary {
		head: ChainHead::after(12, [0x99; 32]).unwrap(),
		..intent()
	};
	let different_offset = RemoteReplayBoundary {
		offset: intent().offset + 1,
		..intent()
	};
	assert!(!selected.matches_cut(different_head, context(), SCOPE, commitment));
	assert!(!selected.matches_cut(different_offset, context(), SCOPE, commitment));

	let different_context = RemoteDownloadContext {
		owner: OwnerDigest::from_bytes([0x99; 32]),
		..context()
	};
	assert!(!selected.matches_cut(intent(), different_context, SCOPE, commitment));
	let different_scope = RemoteScopeDigest::from_bytes([0x99; 32]);
	assert!(!selected.matches_cut(intent(), context(), different_scope, commitment));

	let different_commitment = WitnessRetentionCommitment::measure(
		context(),
		SCOPE,
		GRANT,
		commitment.deadline.checked_add(1).unwrap(),
	)
	.unwrap();
	assert!(!selected.matches_cut(intent(), context(), SCOPE, different_commitment));
	assert!(matches!(
		RecoveryApproval::select(intent(), different_context, SCOPE, commitment, &grant),
		Err(AuthorityError::Binding)
	));
	assert!(matches!(
		RecoveryApproval::select(
			different_offset,
			context(),
			different_scope,
			commitment,
			&grant
		),
		Err(AuthorityError::Binding)
	));
}

#[test]
fn expired_archived_commitment_cannot_arm_live_approval() {
	let grant = grant_for(TEN_MINUTES);
	let past = NonZeroU64::MIN;
	let commitment = WitnessRetentionCommitment::measure(context(), SCOPE, GRANT, past).unwrap();
	assert!(matches!(
		RecoveryApproval::select(intent(), context(), SCOPE, commitment, &grant),
		Err(AuthorityError::Clock)
	));
}

#[test]
fn grant_must_match_and_one_successful_entry_consumes_the_approval() {
	let end = Instant::now() + TEN_MINUTES;
	let foreign_grant = RemoteGrant::new(SCOPE, [0x99; 32], end).unwrap();
	let foreign_scope =
		RemoteGrant::new(RemoteScopeDigest::from_bytes([0x99; 32]), GRANT, end).unwrap();
	let grant = grant_for(TEN_MINUTES);
	let commitment = commitment();

	assert!(matches!(
		RecoveryApproval::select(intent(), context(), SCOPE, commitment, &foreign_grant),
		Err(AuthorityError::Binding)
	));
	assert!(matches!(
		RecoveryApproval::select(intent(), context(), SCOPE, commitment, &foreign_scope),
		Err(AuthorityError::Grant(_))
	));
	let selected =
		RecoveryApproval::select(intent(), context(), SCOPE, commitment, &grant).unwrap();
	let mut guard = selected.enter_once(|| Ok(())).unwrap();
	assert!(selected.state.try_lock().is_err());
	guard.confirm().unwrap();
	drop(guard);
	assert!(matches!(
		selected.enter_once(|| Ok(())),
		Err(AuthorityError::ApprovalInactive)
	));
}

#[test]
fn withdrawal_or_revocation_of_the_original_instance_refuses_before_the_append() {
	let grant = grant_for(TEN_MINUTES);
	let withdrawn = selected(&grant);
	withdrawn.withdraw();
	assert!(matches!(
		withdrawn.enter_once(|| Ok(())),
		Err(AuthorityError::ApprovalInactive)
	));

	let still_armed = selected(&grant);
	let same_digest_replacement = grant_for(TEN_MINUTES);
	grant.revoke();
	drop(same_digest_replacement.enter(SCOPE, GRANT).unwrap());
	assert!(matches!(
		still_armed.enter_once(|| Ok(())),
		Err(AuthorityError::Grant(_))
	));
}

#[test]
fn qualification_drift_under_held_guards_refuses_and_spends_the_attempt() {
	let grant = grant_for(TEN_MINUTES);
	let selected = selected(&grant);
	let checked = selected.enter_once(|| {
		assert!(matches!(
			selected.state.try_lock(),
			Err(TryLockError::WouldBlock)
		));
		Err(AuthorityError::Qualification(
			RemoteContinuationQualificationError::LiveDestination,
		))
	});
	assert!(matches!(
		checked,
		Err(AuthorityError::Qualification(
			RemoteContinuationQualificationError::LiveDestination
		))
	));
	assert!(matches!(
		selected.enter_once(|| panic!("spent approval repeated qualification")),
		Err(AuthorityError::ApprovalInactive)
	));
}

#[test]
fn final_gate_rejects_a_shorter_grant_that_expires_during_custody_checks() {
	let end = Instant::now() + Duration::from_secs(60);
	let grant = RemoteGrant::new(SCOPE, GRANT, end).unwrap();
	let selected = selected(&grant);
	let mut guard = selected.enter_once(|| Ok(())).unwrap();
	let expired = ClockSample {
		before: end,
		after: end,
		wall: guard.last.wall + Duration::from_secs(60),
	};
	assert!(guard.deadline.check(expired, guard.last).is_ok());
	assert!(matches!(
		guard.confirm_at(expired),
		Err(AuthorityError::Grant(Error::Grant(RetryError::Blocked(
			RetryBlock::GrantExpired
		))))
	));
}

#[test]
fn poisoned_authority_locks_refuse_admission() {
	let grant = grant_for(TEN_MINUTES);
	let approval = selected(&grant);
	assert!(
		catch_unwind(AssertUnwindSafe(|| {
			let _guard = approval.state.lock().unwrap();
			panic!("synthetic approval lock poison");
		}))
		.is_err()
	);
	assert!(matches!(
		approval.enter_once(|| Ok(())),
		Err(AuthorityError::ApprovalInactive)
	));

	let approval = selected(&grant);
	assert!(
		catch_unwind(AssertUnwindSafe(|| {
			let _guard = grant.enter(SCOPE, GRANT).unwrap();
			panic!("synthetic grant lock poison");
		}))
		.is_err()
	);
	assert!(matches!(
		approval.enter_once(|| Ok(())),
		Err(AuthorityError::Grant(_))
	));
}

#[test]
fn deadline_is_exclusive_on_either_clock_and_rejects_wall_rollback() {
	let start = Instant::now();
	let sample = |before, wall, after| ClockSample {
		before: start + Duration::from_millis(before),
		wall: Duration::from_millis(wall),
		after: start + Duration::from_millis(after),
	};
	let first = sample(0, 120_500, 20);
	let deadline = ApprovalDeadline::at(first, NonZeroU64::new(122).unwrap()).unwrap();
	assert!(deadline.check(sample(100, 120_700, 110), first).is_ok());
	for bad in [
		sample(100, 120_499, 110),
		sample(100, 122_000, 110),
		sample(1490, 121_800, 1500),
		sample(19, 120_700, 110),
		sample(110, 120_700, 100),
	] {
		assert!(matches!(
			deadline.check(bad, first),
			Err(AuthorityError::Clock)
		));
	}
	assert!(matches!(
		ApprovalDeadline::at(sample(0, 121_998, 20), NonZeroU64::new(122).unwrap()),
		Err(AuthorityError::Clock)
	));
}
