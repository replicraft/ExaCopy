use exacopy_endpoint::ssh_sftp::CredentialSource;
use exacopy_ssh::{Error as SshError, KnownHostTrust, ReadOnlySftp};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::remote_frontdoor::SshProfile;

#[cfg(all(test, unix))]
mod tests;

/// Authenticate a route-owned stream using the selected profile and trust snapshot.
/// Clones of the offer predicate must observe the same attempt retirement,
/// including while a blocking key acquisition outlives the connection future.
pub(crate) async fn authenticate(
	stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
	profile: &SshProfile,
	trust: KnownHostTrust,
	offer_current: impl Fn() -> bool + Clone + Send + 'static,
	route_current: impl Fn() -> bool,
) -> Result<ReadOnlySftp, SshError> {
	let authority = &profile.authority;
	match profile.credential_source() {
		CredentialSource::SuppliedPassword => {
			exacopy_ssh::connect_with_password_checked(
				stream,
				authority,
				profile.pin,
				trust,
				authority,
				|request| profile.password(request, || route_current() && offer_current()),
				|| {
					(route_current() && offer_current())
						.then_some(())
						.ok_or(SshError::Password)
				},
			)
			.await
		}
		CredentialSource::SuppliedKey => {
			let acquisition = offer_current.clone();
			let route_current = &route_current;
			exacopy_ssh::connect_with_ed25519_async(
				stream,
				authority,
				profile.pin,
				trust,
				authority,
				async move |request| {
					if !route_current() || !acquisition() {
						return Err(SshError::KeyProfile);
					}
					let key = profile.approve_ed25519(request)?;
					tokio::task::spawn_blocking(move || key.acquire(acquisition))
						.await
						.map_err(|_| SshError::KeyProfile)?
				},
				|| {
					(route_current() && offer_current())
						.then_some(())
						.ok_or(SshError::KeyProfile)
				},
			)
			.await
		}
		_ => Err(SshError::KeyProfile),
	}
}
