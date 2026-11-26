use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use exacopy_endpoint::ssh_sftp::CredentialSource;
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_ssh::{Error as SshError, KnownHostTrust, ReadOnlySftp};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::remote_frontdoor::SshProfile;

use super::RemoteGrant;

pub(super) const CONNECTION_BUDGET: Duration = Duration::from_secs(20);

pub(super) async fn authenticate(
	stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
	profile: &SshProfile,
	trust: KnownHostTrust,
	offer: &OfferLease,
	route_current: impl Fn() -> bool,
) -> Result<ReadOnlySftp, SshError> {
	let authority = &profile.authority;
	match profile.credential_source() {
		CredentialSource::SuppliedPassword => {
			exacopy_ssh::connect(
				stream,
				authority,
				profile.pin,
				trust,
				authority,
				|request| profile.password(request, || route_current() && offer.0.current()),
			)
			.await
		}
		CredentialSource::SuppliedKey => {
			let acquisition = Arc::clone(&offer.0);
			let route_current = &route_current;
			exacopy_ssh::connect_with_ed25519_async(
				stream,
				authority,
				profile.pin,
				trust,
				authority,
				async move |request| {
					if !route_current() || !acquisition.current() {
						return Err(SshError::KeyProfile);
					}
					let key = profile.approve_ed25519(request)?;
					tokio::task::spawn_blocking(move || key.acquire(|| acquisition.current()))
						.await
						.map_err(|_| SshError::KeyProfile)?
				},
				|| {
					(route_current() && offer.0.current())
						.then_some(())
						.ok_or(SshError::KeyProfile)
				},
			)
			.await
		}
		_ => Err(SshError::KeyProfile),
	}
}

pub(super) struct OfferLease(Arc<CurrentOffer>);

impl OfferLease {
	pub(super) fn new(
		grant: Arc<RemoteGrant>,
		scope: RemoteScopeDigest,
		deadline: Instant,
	) -> Self {
		Self(Arc::new(CurrentOffer {
			grant,
			scope,
			deadline,
			open: AtomicBool::new(true),
		}))
	}
}

impl Drop for OfferLease {
	fn drop(&mut self) {
		self.0.open.store(false, Ordering::Release);
	}
}

struct CurrentOffer {
	grant: Arc<RemoteGrant>,
	scope: RemoteScopeDigest,
	deadline: Instant,
	open: AtomicBool,
}

impl CurrentOffer {
	fn current(&self) -> bool {
		self.grant.check_source(self.scope).is_ok()
			&& Instant::now() < self.deadline
			&& self.open.load(Ordering::Acquire)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn abandoning_the_connect_attempt_retires_its_worker_offer_without_revoking_grant() {
		let scope = RemoteScopeDigest::from_bytes([3; 32]);
		let deadline = Instant::now() + Duration::from_secs(60);
		let grant = Arc::new(RemoteGrant::new(scope, [4; 32], deadline).unwrap());
		let offer = OfferLease::new(Arc::clone(&grant), scope, deadline);
		let worker = Arc::clone(&offer.0);
		assert!(worker.current());
		drop(offer);
		assert!(!worker.current());
		assert!(grant.check_source(scope).is_ok());
	}
}
