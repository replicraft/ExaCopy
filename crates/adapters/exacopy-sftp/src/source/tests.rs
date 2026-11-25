use std::num::{NonZeroU64, NonZeroU128};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::connection_retry::{
	ReconnectEvidence, RetryDecision, RetryOwner, RetrySupervisor,
};
use exacopy_ssh::{Password, connect};

use super::{
	CapturedReadAt, ConnectionBinding, ReadOnlySftp, SftpSourceError, SftpSourceRequest,
	SourceEpoch, UnixComponent, with_source,
};

#[path = "../../../../net/exacopy-ssh/tests/in_process/key_auth.rs"]
mod key_auth;
#[path = "../../../../net/exacopy-ssh/tests/in_process/peer.rs"]
mod peer;

use peer::{Calls, Generated, NAME, SECRET, authority, fixture_trust, generated_peer};

mod pending;

const EPOCH: SourceEpoch = SourceEpoch::new(NonZeroU64::MIN);

fn path() -> [UnixComponent<'static>; 1] {
	[UnixComponent::new(NAME).unwrap()]
}

fn admitted() -> (RetrySupervisor, ConnectionBinding) {
	let mut owner =
		RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), Duration::from_secs(30));
	let RetryDecision::Start(attempt) = owner.poll(Duration::ZERO).unwrap() else {
		panic!("one admitted synthetic source requires one connection attempt");
	};
	let binding = owner
		.admit(
			Duration::ZERO,
			attempt,
			ReconnectEvidence {
				route_checked_for: attempt,
				ssh_authenticated_for: attempt,
				source_checked_for: attempt,
				source_epoch: EPOCH,
			},
		)
		.unwrap();
	(owner, binding)
}

async fn peer_source(file: Generated) -> (ReadOnlySftp, Arc<Calls>) {
	let (stream, pin, calls) = generated_peer(file);
	let target = authority("transfer");
	let session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	(session, calls)
}

#[tokio::test]
async fn scoped_source_checks_live_observation_and_reads_high_offset_short_replies() {
	const HIGH: u64 = (1 << 32) + 11;
	let mut file = Generated::new(HIGH + 4);
	file.max_reply = 1;
	let (session, calls) = peer_source(file).await;
	let (mut owner, binding) = admitted();
	let result = with_source(
		session,
		SftpSourceRequest {
			path: &path(),
			epoch: EPOCH,
			binding,
		},
		|binding| owner.check_completion(Duration::ZERO, binding),
		async |source| {
			assert_eq!(source.epoch(), EPOCH);
			assert_eq!(source.length(), HIGH + 4);
			source.recheck().await?;
			let mut prefix = [0; 3];
			source.read_exact_at(0, &mut prefix).await?;
			let mut high = [0; 4];
			source.read_exact_at(HIGH, &mut high).await?;
			source.finish().await?;
			assert_eq!(source.epoch(), EPOCH);
			Ok::<_, SftpSourceError>((prefix, high))
		},
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(result.0, [0, 1, 2]);
	assert_eq!(
		result.1,
		std::array::from_fn(|index| ((HIGH + index as u64) % 251) as u8)
	);
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 8);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn invalid_positive_interval_refuses_before_data_and_retires_scope() {
	for (offset, size) in [(u64::MAX, 2), (4, 2), (0, 0)] {
		let (session, calls) = peer_source(Generated::new(5)).await;
		let (mut owner, binding) = admitted();
		with_source(
			session,
			SftpSourceRequest {
				path: &path(),
				epoch: EPOCH,
				binding,
			},
			|binding| owner.check_completion(Duration::ZERO, binding),
			async |source| {
				assert!(matches!(
					source.read_exact_at(offset, &mut [0; 2][..size]).await,
					Err(SftpSourceError::Window),
				));
				assert!(matches!(
					source.finish().await,
					Err(SftpSourceError::Closed)
				));
			},
		)
		.await
		.unwrap();
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
		assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	}
}
