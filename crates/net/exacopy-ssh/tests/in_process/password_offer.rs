use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::{CredentialSource, InteractionPolicy};
use exacopy_ssh::{Error, Password, connect_with_password_checked};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout};

use super::peer::{SECRET, authority, fixture_trust, peer_with_rekey};

const DRAIN_BUDGET: Duration = Duration::from_secs(10);

#[tokio::test]
async fn checked_password_reobserves_route_and_grant_after_broker() {
	for (route_after, grant_after) in [(false, true), (true, false), (true, true)] {
		let (done, drained) = oneshot::channel();
		let (stream, pin, calls, _) = peer_with_rekey(
			true,
			false,
			russh::server::Config::default().limits.rekey_time_limit,
			Some(done),
		);
		let target = authority("transfer");
		let route = Cell::new(true);
		let grant = Cell::new(true);
		let acquired = Cell::new(false);
		let checked = Cell::new(false);
		let result = connect_with_password_checked(
			stream,
			&target,
			pin,
			fixture_trust(&target, ""),
			&target,
			|request| {
				assert!(route.get() && grant.get());
				assert_eq!(request.authority(), &target);
				assert_eq!(request.fingerprint(), pin);
				assert_eq!(request.source(), CredentialSource::SuppliedPassword);
				assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
				let password = Password::new(SECRET.to_owned())?;
				assert!(!acquired.replace(true));
				route.set(route_after);
				grant.set(grant_after);
				Ok(password)
			},
			|| {
				assert!(acquired.get());
				assert!(!checked.replace(true));
				assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
				assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
				(route.get() && grant.get())
					.then_some(())
					.ok_or(Error::Password)
			},
		)
		.await;
		assert!(acquired.get() && checked.get());
		let permitted = route_after && grant_after;
		if permitted {
			let session = result.expect("an active route and grant can authenticate");
			assert_eq!(session.authenticated_peer().authority(), &target);
			assert_eq!(session.authenticated_peer().fingerprint(), pin);
			session
				.disconnect_before(Instant::now() + DRAIN_BUDGET)
				.await
				.expect("disconnect the permitted peer");
		} else {
			assert!(matches!(result, Err(Error::Password)));
		}
		timeout(DRAIN_BUDGET, drained)
			.await
			.expect("the peer must finish before counting its offers")
			.expect("the peer must report termination");
		assert_eq!(calls.auth.load(Ordering::Relaxed), usize::from(permitted));
		assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);
		assert_eq!(
			calls.subsystem.load(Ordering::Relaxed),
			usize::from(permitted)
		);
	}
}

#[tokio::test]
async fn a_failed_password_broker_keeps_its_error_when_the_route_is_revoked() {
	let (done, drained) = oneshot::channel();
	let (stream, pin, calls, _) = peer_with_rekey(
		true,
		false,
		russh::server::Config::default().limits.rekey_time_limit,
		Some(done),
	);
	let target = authority("transfer");
	let route = Cell::new(true);
	let result = connect_with_password_checked(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| {
			assert!(route.replace(false));
			Err(Error::Password)
		},
		|| {
			assert!(route.get(), "the failed broker must end the attempt");
			Err(Error::Closed)
		},
	)
	.await;
	assert!(!route.get());
	assert!(matches!(result, Err(Error::Password)));
	timeout(DRAIN_BUDGET, drained)
		.await
		.expect("the peer must finish after the broker refusal")
		.expect("the peer must report termination");
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
}
