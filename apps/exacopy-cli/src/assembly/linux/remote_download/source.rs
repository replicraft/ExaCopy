use std::net::SocketAddr;
use std::num::NonZeroU128;
use std::sync::Arc;
use std::time::Instant;

use exacopy_endpoint::connection_retry::{
	ConnectionAttempt, ConnectionBinding, PermanentFailure, ReconnectEvidence, RetryBlock,
	RetryDecision, RetryError, RetryOwner, RetrySupervisor,
};
use exacopy_endpoint::ssh_sftp::HostKeyFingerprint;
use exacopy_journal::remote_download::{
	RemoteDownloadRoute, RemoteDownloadScope, RemoteScopeDigest,
};
use exacopy_sftp::{PendingSftpSource, PendingSourceOwner, SftpSourceError};
use exacopy_ssh::{ReadOnlySftp, SshSessionCancellation};

use crate::profile::kernel_random;

use super::super::remote_journal::Error;
use super::{RemoteDownloadFailure, RemoteGrant};

mod authentication;
mod direct;
#[cfg(feature = "experimental-ssh-wireguard")]
mod embedded;
mod route_lifetime;

pub(crate) use direct::DirectConnectError;
#[cfg(feature = "experimental-ssh-wireguard")]
pub(crate) use embedded::EmbeddedConnectError;
use route_lifetime::RouteTask;

/// Current observation of the original approved embedded TCP stream.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EmbeddedStreamObservation {
	/// Unique logical stream identity issued by its owning actor. Transport rekeying
	/// can retain this identity only when the same admitted stream remains active.
	pub stream: NonZeroU128,
	/// Actual peer public reference of the stream's route.
	pub peer: [u8; 32],
	/// Actual public route profile revision.
	pub revision: [u8; 32],
	/// Actual inner destination of this TCP stream.
	pub inner: SocketAddr,
}

/// App-transport-owned current observation of a single embedded TCP stream.
pub trait CurrentEmbeddedStream {
	/// Reobserves the original occupied logical stream under its actor's live route.
	/// Absence or replacement must return None or a different stream identity.
	/// The synchronous check must release any internal locks before returning.
	fn observe(&self) -> Option<EmbeddedStreamObservation>;
}

/// Actual peer evidence from the route that carried this authenticated session.
pub enum RemoteRoutePeer<'route> {
	/// Peer observed on the exact connected TCP stream passed to SSH.
	Direct(SocketAddr),
	/// Current observation of the exact embedded TCP stream passed to SSH.
	Embedded(&'route dyn CurrentEmbeddedStream),
}

/// A unique grant-checked attempt before its actual transport and SSH admission.
pub struct ConnectingRemoteSource<'authorization> {
	scope: &'authorization RemoteDownloadScope,
	supervisor: Supervisor,
}

impl<'authorization> ConnectingRemoteSource<'authorization> {
	/// Claims the initial attempt with a fresh local supervisor identity under this grant.
	/// # Errors
	/// Refuses unsupported routing, an expired or foreign grant, or an unavailable identity.
	pub fn begin(
		scope: &'authorization RemoteDownloadScope,
		grant: &Arc<RemoteGrant>,
	) -> Result<Self, RemoteDownloadFailure> {
		if !matches!(
			scope.source.route(),
			RemoteDownloadRoute::ResolvedDirect { .. }
				| RemoteDownloadRoute::EmbeddedWireGuard { .. }
		) {
			return Err(Error::UnsupportedRoute.into());
		}
		let digest = scope.digest().map_err(Error::from)?;
		grant
			.check_source(digest)
			.map_err(SftpSourceError::Binding)?;
		let mut random = [0; 16];
		kernel_random(&mut random).map_err(Error::from)?;
		let id = NonZeroU128::new(u128::from_ne_bytes(random)).ok_or(Error::Binding)?;
		let start = Instant::now();
		let remaining = grant
			.remaining_from(start)
			.map_err(SftpSourceError::Binding)?;
		let mut retry = RetrySupervisor::new(RetryOwner::new(id), remaining);
		let RetryDecision::Start(attempt) = retry
			.poll(start.elapsed())
			.map_err(SftpSourceError::Binding)?
		else {
			return Err(Error::Binding.into());
		};
		Ok(Self {
			scope,
			supervisor: Supervisor {
				grant: Arc::clone(grant),
				digest,
				start,
				retry,
				attempt,
			},
		})
	}

	/// The exact generation reserved before opening the actual transport.
	#[must_use]
	pub const fn attempt(&self) -> ConnectionAttempt {
		self.supervisor.attempt
	}

	/// Rechecks the exact connecting attempt and shared active authorization.
	/// # Errors
	/// Refuses expired, revoked or obsolete work before or after a transport await.
	pub fn check_current(&mut self) -> Result<(), RetryError> {
		let attempt = self.supervisor.attempt;
		self.supervisor.check_connecting(attempt)
	}

	/// Consumes the session opened by the trusted connector for this exact attempt.
	/// The transport owner supplies only the session returned by the pinned SSH/SFTP
	/// admission for this attempt. Its actual authenticated identity lives on the returned
	/// session. Direct peer is from its connected TCP stream, or
	/// the stream owner reobserves the actual approved embedded connection.
	/// # Errors
	/// Refuses stale work, authority/pin substitutions, or a different route.
	fn bind_authenticated(
		mut self,
		session: ReadOnlySftp,
		peer: RemoteRoutePeer<'authorization>,
		transport: Arc<RouteTask>,
	) -> Result<ConnectedRemoteSource<'authorization>, RetryError> {
		self.check_current()?;
		let host = session.authenticated_peer();
		if host.authority() != self.scope.source.authority()
			|| host.fingerprint()
				!= HostKeyFingerprint::from_sha256(*self.scope.source.host_key_sha256())
		{
			return Err(RetryError::Blocked(RetryBlock::Permanent(
				PermanentFailure::HostIdentityRefused,
			)));
		}
		let route = BoundRoute::admit(self.scope.source.route(), peer)?;
		self.check_current()?;
		if !transport.is_active() {
			return Err(route_refusal());
		}
		Ok(ConnectedRemoteSource {
			session,
			owner: SourceOwner {
				supervisor: self.supervisor,
				route,
				transport,
			},
		})
	}
}

/// Exact accepted SSH capability and its still-current route and retry attempt.
pub struct ConnectedRemoteSource<'authorization> {
	session: ReadOnlySftp,
	owner: SourceOwner<'authorization>,
}

impl<'authorization> ConnectedRemoteSource<'authorization> {
	pub(crate) fn cancellation_handle(&self) -> SshSessionCancellation {
		self.session.cancellation_handle()
	}

	pub(super) fn into_current(
		self,
		scope: RemoteScopeDigest,
		grant: &RemoteGrant,
	) -> Result<(ReadOnlySftp, SourceOwner<'authorization>), SftpSourceError> {
		let Self { session, mut owner } = self;
		if owner.supervisor.digest != scope || !std::ptr::eq(owner.supervisor.grant.as_ref(), grant)
		{
			return Err(SftpSourceError::Binding(RetryError::StaleAdmission));
		}
		owner
			.check_connecting(owner.attempt())
			.map_err(SftpSourceError::Binding)?;
		Ok((session, owner))
	}
}

enum BoundRoute<'route> {
	Direct,
	Embedded {
		original: EmbeddedStreamObservation,
		current: &'route dyn CurrentEmbeddedStream,
	},
}

impl<'route> BoundRoute<'route> {
	fn admit(
		expected: RemoteDownloadRoute,
		peer: RemoteRoutePeer<'route>,
	) -> Result<Self, RetryError> {
		match (expected, peer) {
			(RemoteDownloadRoute::ResolvedDirect { endpoint }, RemoteRoutePeer::Direct(actual))
				if endpoint == actual =>
			{
				Ok(Self::Direct)
			}
			(
				RemoteDownloadRoute::EmbeddedWireGuard {
					peer,
					revision,
					inner,
				},
				RemoteRoutePeer::Embedded(current),
			) => {
				let original = current.observe().ok_or_else(route_refusal)?;
				if original.peer != peer || original.revision != revision || original.inner != inner
				{
					return Err(route_refusal());
				}
				Ok(Self::Embedded { original, current })
			}
			_ => Err(route_refusal()),
		}
	}

	fn check(&self) -> Result<(), RetryError> {
		if let Self::Embedded { original, current } = self
			&& current.observe() != Some(*original)
		{
			return Err(route_refusal());
		}
		// A still-owned connected direct TCP stream cannot change its peer.
		Ok(())
	}
}

fn route_refusal() -> RetryError {
	RetryError::Blocked(RetryBlock::Permanent(
		PermanentFailure::RouteAuthorityRefused,
	))
}

struct Supervisor {
	grant: Arc<RemoteGrant>,
	digest: RemoteScopeDigest,
	start: Instant,
	retry: RetrySupervisor,
	attempt: ConnectionAttempt,
}

impl Supervisor {
	fn check_connecting(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.grant.check_source(self.digest)?;
		self.retry.check_connecting(self.start.elapsed(), attempt)
	}
}

pub(super) struct SourceOwner<'authorization> {
	supervisor: Supervisor,
	route: BoundRoute<'authorization>,
	transport: Arc<RouteTask>,
}

impl SourceOwner<'_> {
	pub(super) const fn attempt(&self) -> ConnectionAttempt {
		self.supervisor.attempt
	}

	pub(super) fn admit_pending(
		&mut self,
		pending: &PendingSftpSource<'_>,
	) -> Result<ConnectionBinding, RetryError> {
		let attempt = pending.attempt();
		self.check_connecting(attempt)?;
		let routed = self.attempt();
		self.supervisor.retry.admit(
			self.supervisor.start.elapsed(),
			attempt,
			ReconnectEvidence {
				route_checked_for: routed,
				ssh_authenticated_for: routed,
				source_checked_for: pending.attempt(),
				source_epoch: pending.epoch(),
			},
		)
	}

	pub(super) fn check_binding(&mut self, binding: ConnectionBinding) -> Result<(), RetryError> {
		self.check_transport()?;
		let state = &mut self.supervisor;
		state.grant.check_source(state.digest)?;
		state.retry.check_completion(state.start.elapsed(), binding)
	}

	pub(super) async fn retire(
		mut self,
		binding: ConnectionBinding,
		session: ReadOnlySftp,
	) -> Result<(), RetryError> {
		let terminal = self.check_binding(binding);
		let task = &self.transport;
		task.stop();
		drop(session);
		if !task.join().await {
			return Err(route_refusal());
		}
		terminal
	}

	fn check_transport(&self) -> Result<(), RetryError> {
		if !self.transport.is_active() {
			return Err(route_refusal());
		}
		self.route.check()
	}
}

impl PendingSourceOwner for SourceOwner<'_> {
	fn check_connecting(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.check_transport()?;
		self.supervisor.check_connecting(attempt)
	}

	fn check_attempt(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.check_transport()?;
		let state = &mut self.supervisor;
		state.grant.check_source(state.digest)?;
		state.retry.check_attempt(state.start.elapsed(), attempt)
	}
}

#[cfg(test)]
mod tests {
	use std::cell::Cell;

	use super::*;

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
}
