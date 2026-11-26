use std::cell::Cell;
use std::time::Duration;

use super::*;

#[test]
fn a_later_attempt_has_its_own_budget_within_the_original_grant() {
	let invocation = Instant::now();
	let grant = invocation + Duration::from_secs(32);
	let next_attempt = invocation + Duration::from_secs(25);
	assert_eq!(
		connection_deadline(invocation, grant),
		Some(invocation + authentication::CONNECTION_BUDGET)
	);
	assert_eq!(connection_deadline(next_attempt, grant), Some(grant));
}

#[test]
fn direct_peer_must_be_the_exact_signed_endpoint() {
	let endpoint = "192.0.2.8:22".parse().unwrap();
	let other = "192.0.2.8:2222".parse().unwrap();
	let route = RemoteDownloadRoute::ResolvedDirect { endpoint };
	assert!(BoundRoute::admit(route, RemoteRoutePeer::Direct(endpoint)).is_ok());
	assert!(matches!(
		BoundRoute::admit(route, RemoteRoutePeer::Direct(other)),
		Err(RetryError::Blocked(RetryBlock::Permanent(
			PermanentFailure::RouteAuthorityRefused
		)))
	));
}

struct Embedded(Cell<Option<EmbeddedStreamObservation>>);

impl CurrentEmbeddedStream for Embedded {
	fn observe(&self) -> Option<EmbeddedStreamObservation> {
		self.0.get()
	}
}

#[test]
fn embedded_observations_refuse_peer_revision_and_transport_generation_changes() {
	let inner = "192.0.2.83:22".parse().unwrap();
	let original = EmbeddedStreamObservation {
		stream: NonZeroU128::MIN,
		peer: [4; 32],
		revision: [5; 32],
		inner,
	};
	let route = RemoteDownloadRoute::EmbeddedWireGuard {
		peer: original.peer,
		revision: original.revision,
		inner,
	};
	let observed = Embedded(Cell::new(Some(original)));
	let bound = BoundRoute::admit(route, RemoteRoutePeer::Embedded(&observed)).unwrap();
	bound.check().unwrap();
	for changed in [
		EmbeddedStreamObservation {
			peer: [9; 32],
			..original
		},
		EmbeddedStreamObservation {
			revision: [7; 32],
			..original
		},
		EmbeddedStreamObservation {
			stream: NonZeroU128::new(2).unwrap(),
			..original
		},
	] {
		observed.0.set(Some(changed));
		assert!(bound.check().is_err());
	}
	observed.0.set(None);
	assert!(bound.check().is_err());
}

#[test]
fn expired_connect_lease_fences_effects_even_with_time_left_in_the_grant() {
	let scope = RemoteScopeDigest::from_bytes([1; 32]);
	let now = Instant::now();
	let grant = RemoteGrant::new(scope, [2; 32], now + Duration::from_secs(60)).unwrap();
	let expired = super::route_lifetime::RouteLease::connecting(now);
	let activity = expired.activity();
	assert!(!activity.is_active());
	let effects = Cell::new(0);
	activity.with_grant(&grant, scope, |current| {
		if current {
			effects.set(effects.get() + 1);
		}
	});
	assert_eq!(effects.get(), 0);
	assert!(grant.check_source(scope).is_ok());

	let active = super::route_lifetime::RouteLease::connecting(now + Duration::from_secs(10));
	active.activity().with_grant(&grant, scope, |current| {
		if current {
			effects.set(effects.get() + 1);
		}
	});
	assert_eq!(effects.get(), 1);
	grant.revoke();
	active.activity().with_grant(&grant, scope, |current| {
		if current {
			effects.set(effects.get() + 1);
		}
	});
	assert_eq!(effects.get(), 1);
}

fn admitted_binding(supervisor: &Supervisor) -> ConnectionBinding {
	use exacopy_endpoint::remote_source::SourceEpoch;
	use std::num::NonZeroU64;

	let RetryDecision::Start(attempt) = supervisor.observe(RetrySupervisor::poll).unwrap() else {
		panic!("first attempt was not ready")
	};
	supervisor
		.observe(|retry, now| {
			retry.admit(
				now,
				attempt,
				ReconnectEvidence {
					route_checked_for: attempt,
					ssh_authenticated_for: attempt,
					source_checked_for: attempt,
					source_epoch: SourceEpoch::new(NonZeroU64::MIN),
				},
			)
		})
		.unwrap()
}

#[tokio::test]
async fn revocation_while_waiting_stays_revoked_for_the_same_invocation() {
	let scope = retry_scope();
	let digest = scope.digest().unwrap();
	let start = Instant::now();
	let remaining = Duration::from_secs(20);
	let grant = Arc::new(RemoteGrant::new(digest, [2; 32], start + remaining).unwrap());
	let invocation = SourceInvocation::new(&scope, &grant).unwrap();
	let binding = admitted_binding(&invocation.supervisor);
	let mut wait = std::pin::pin!(invocation.backoff(binding));
	std::future::poll_fn(|cx| {
		assert!(wait.as_mut().poll(cx).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	grant.revoke();
	assert!(wait.await.is_err());
	assert!(invocation.claim().is_err());
}

#[tokio::test]
async fn a_due_retry_preserves_the_grant_and_advances_the_same_generation() {
	let scope = retry_scope();
	let digest = scope.digest().unwrap();
	let deadline = Instant::now() + Duration::from_secs(60);
	let grant = Arc::new(RemoteGrant::new(digest, [2; 32], deadline).unwrap());
	let invocation = SourceInvocation::new(&scope, &grant).unwrap();
	let binding = admitted_binding(&invocation.supervisor);
	assert_eq!(binding.attempt().generation().get(), 1);
	assert!(invocation.claim().is_err());
	invocation.backoff(binding).await.unwrap();
	let mut next = invocation.claim().unwrap();
	assert_eq!(next.attempt().generation().get(), 2);
	assert!(Arc::ptr_eq(&grant, &next.supervisor.grant));
	assert_eq!(next.supervisor.grant.deadline(), deadline);
	assert!(
		next.connect_deadline()
			.is_some_and(|bound| bound < deadline)
	);
	assert!(invocation.backoff(binding).await.is_err());
	next.check_current().unwrap();
}

fn retry_scope() -> RemoteDownloadScope {
	use exacopy_endpoint::{UnixComponent, ssh_sftp::SshAuthority};
	use exacopy_journal::remote_download::{
		RemoteDownloadDestination, RemoteDownloadDurability, RemoteDownloadSource,
	};
	use exacopy_journal::{JournalEntryId, LinuxFileIdentity, RootCapabilityId, StreamLength};
	use std::num::NonZeroU16;

	let endpoint = "192.0.2.8:22".parse().unwrap();
	let source = RemoteDownloadSource::new(
		SshAuthority::new("local.example", NonZeroU16::new(22).unwrap(), "reader").unwrap(),
		[3; 32],
		RemoteDownloadRoute::ResolvedDirect { endpoint },
		b"source",
	)
	.unwrap();
	let destination = RemoteDownloadDestination::new(
		RootCapabilityId::from_bytes([4; 16]).unwrap(),
		LinuxFileIdentity::new(1, 2),
		UnixComponent::new(b"target").unwrap(),
	);
	RemoteDownloadScope::new(
		JournalEntryId::from_bytes([5; 16]),
		source,
		destination,
		StreamLength::new(12).unwrap(),
		exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1::digest(),
		RemoteDownloadDurability::ProcessCrash,
	)
	.unwrap()
}
