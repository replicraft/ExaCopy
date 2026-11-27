use std::num::{NonZeroU64, NonZeroU128};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{
	ConnectionFailure, FailureDecision, FailureSubject, ReconnectEvidence, RetryDecision,
	RetryOwner, RetrySupervisor, TransientFailure,
};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_journal::remote_download::RemoteScopeDigest;

use super::*;
use crate::assembly::linux::remote_download::RemoteGrant;

fn admitted(deadline: Instant, owner: NonZeroU128) -> (Supervisor, ConnectionBinding) {
	let start = Instant::now();
	let duration = Duration::from_secs(30);
	let digest = RemoteScopeDigest::from_bytes([1; 32]);
	let supervisor = Supervisor {
		grant: Arc::new(RemoteGrant::new(digest, [2; 32], deadline).unwrap()),
		digest,
		start,
		retry: Mutex::new(RetrySupervisor::new(RetryOwner::new(owner), duration)),
	};
	let RetryDecision::Start(attempt) = supervisor.observe(RetrySupervisor::poll).unwrap() else {
		panic!("selected retry owner was not ready")
	};
	let binding = supervisor
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
		.unwrap();
	(supervisor, binding)
}

#[test]
fn exact_held_read_timeout_survives_both_direct_socket_close_interleavings() {
	let route = BoundRoute::Direct;
	let deadline = Instant::now() + Duration::from_secs(30);
	let (supervisor, binding) = admitted(deadline, NonZeroU128::MIN);
	for error in [
		// The route observation was live when the failed data read returned.
		SftpSourceError::ReadTimeout,
		// The exact route closed before the failed read's binding observation.
		SftpSourceError::ReadTimeoutBinding(route_refusal()),
	] {
		let check = RetirementCheck::from_read_error(&error);
		assert_ne!(check, RetirementCheck::Live);
		assert_eq!(
			check_before_stop(
				check,
				&route,
				&supervisor,
				binding.attempt(),
				binding,
				false
			),
			Ok(()),
		);
	}
	assert_eq!(
		check_before_stop(
			RetirementCheck::Live,
			&route,
			&supervisor,
			binding.attempt(),
			binding,
			false,
		),
		Err(route_refusal()),
	);
}

#[test]
fn direct_timeout_retirement_refuses_stale_revoked_and_expired_authority() {
	let route = BoundRoute::Direct;
	let deadline = Instant::now() + Duration::from_secs(30);
	let (supervisor, binding) = admitted(deadline, NonZeroU128::MIN);
	let (_, foreign) = admitted(deadline, NonZeroU128::new(2).unwrap());
	assert_eq!(
		check_stopped_direct(&supervisor, binding.attempt(), foreign),
		Err(RetryError::StaleWork),
	);
	let (fenced, previous) = admitted(deadline, NonZeroU128::MIN);
	let decision = fenced
		.observe(|retry, now| {
			retry.failure(
				now,
				FailureSubject::Connection(previous),
				ConnectionFailure::Transient {
					cause: TransientFailure::NonMutatingTimeout,
					jitter_sample: 0,
				},
			)
		})
		.unwrap();
	assert!(matches!(decision, FailureDecision::WaitUntil { .. }));
	assert!(check_stopped_direct(&fenced, previous.attempt(), previous).is_err());
	supervisor.grant.revoke();
	assert!(
		check_before_stop(
			RetirementCheck::DataReadDeadline,
			&route,
			&supervisor,
			binding.attempt(),
			binding,
			false,
		)
		.is_err()
	);

	let cutoff = Instant::now() + Duration::from_millis(200);
	let (expiring, current) = admitted(cutoff, NonZeroU128::MIN);
	std::thread::sleep(cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
	assert!(check_stopped_direct(&expiring, current.attempt(), current).is_err());
}

#[test]
fn non_data_errors_and_other_retirement_refusals_never_admit_a_closed_route() {
	for error in [
		SftpSourceError::Sftp(exacopy_ssh::Error::Timeout),
		SftpSourceError::ReadBinding {
			binding: route_refusal(),
			wire: Box::new(exacopy_ssh::Error::Timeout),
		},
		SftpSourceError::ReadTimeoutBinding(RetryError::StaleWork),
		SftpSourceError::Sftp(exacopy_ssh::Error::Closed),
	] {
		assert!(RetirementCheck::from_read_error(&error) == RetirementCheck::Live);
	}
}

#[test]
fn a_stopped_embedded_route_cannot_use_the_direct_timeout_retirement_path() {
	use super::super::{CurrentEmbeddedStream, EmbeddedStreamObservation};

	struct Embedded(EmbeddedStreamObservation);

	impl CurrentEmbeddedStream for Embedded {
		fn observe(&self) -> Option<EmbeddedStreamObservation> {
			Some(self.0)
		}
	}

	let stream = Embedded(EmbeddedStreamObservation {
		stream: NonZeroU128::MIN,
		peer: [3; 32],
		revision: [4; 32],
		inner: "192.0.2.8:22".parse().unwrap(),
	});
	let route = BoundRoute::Embedded {
		original: stream.0,
		current: &stream,
	};
	let (supervisor, binding) =
		admitted(Instant::now() + Duration::from_secs(30), NonZeroU128::MIN);
	assert_eq!(
		check_before_stop(
			RetirementCheck::DataReadDeadline,
			&route,
			&supervisor,
			binding.attempt(),
			binding,
			false,
		),
		Err(route_refusal())
	);
}
