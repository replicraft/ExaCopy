use std::net::SocketAddr;
use std::num::NonZeroU128;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{
	ConnectionAttempt, ConnectionBinding, ConnectionFailure, FailureDecision, FailureSubject,
	PermanentFailure, ReconnectEvidence, RetryBlock, RetryDecision, RetryError, RetryOwner,
	RetrySupervisor, TransientFailure, VerifiedHealth,
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
#[cfg(test)]
mod route_binding;
#[cfg(test)]
pub(in crate::assembly::linux) use route_binding::BoundRouteRetirement;
#[cfg(test)]
pub(in crate::assembly::linux) use route_binding::RetiredBoundRoute;
mod read_health;
mod retirement;
mod route_lifetime;

pub(crate) use direct::DirectConnectError;
#[cfg(feature = "experimental-ssh-wireguard")]
pub(crate) use embedded::EmbeddedConnectError;
pub(super) use read_health::VerifiedReads;
pub(super) use retirement::RetirementCheck;
pub use route_lifetime::RemoteRouteCloseError;
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

pub(crate) struct SourceInvocation<'scope> {
	scope: &'scope RemoteDownloadScope,
	supervisor: Arc<Supervisor>,
}

impl<'scope> SourceInvocation<'scope> {
	pub(crate) fn new(
		scope: &'scope RemoteDownloadScope,
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
		grant.check_source(digest).map_err(Error::Grant)?;
		let mut random = [0; 16];
		kernel_random(&mut random).map_err(Error::from)?;
		let id = NonZeroU128::new(u128::from_ne_bytes(random)).ok_or(Error::Binding)?;
		let start = Instant::now();
		let remaining = grant.remaining_from(start).map_err(Error::Grant)?;
		Ok(Self {
			scope,
			supervisor: Arc::new(Supervisor {
				grant: Arc::clone(grant),
				digest,
				start,
				retry: Mutex::new(RetrySupervisor::new(RetryOwner::new(id), remaining)),
			}),
		})
	}

	pub(crate) fn claim(&self) -> Result<ConnectingRemoteSource<'scope>, RemoteDownloadFailure> {
		let RetryDecision::Start(attempt) = self
			.supervisor
			.observe(RetrySupervisor::poll)
			.map_err(Error::Grant)?
		else {
			return Err(Error::Binding.into());
		};
		Ok(ConnectingRemoteSource {
			scope: self.scope,
			supervisor: Arc::clone(&self.supervisor),
			attempt,
			attempt_started: Instant::now(),
		})
	}

	pub(crate) async fn backoff(
		&self,
		binding: ConnectionBinding,
	) -> Result<(), RemoteDownloadFailure> {
		let control = &self.supervisor;
		let mut sample = [0; 4];
		kernel_random(&mut sample).map_err(Error::from)?;
		let failed = control
			.observe(|retry, now| {
				retry.failure(
					now,
					FailureSubject::Connection(binding),
					ConnectionFailure::Transient {
						cause: TransientFailure::NonMutatingTimeout,
						jitter_sample: u32::from_ne_bytes(sample),
					},
				)
			})
			.map_err(Error::Grant)?;
		let wake = match failed {
			FailureDecision::WaitUntil { wake_at, .. } => {
				control.start.checked_add(wake_at).ok_or(Error::Binding)?
			}
			FailureDecision::Blocked(reason) => {
				return Err(Error::Grant(RetryError::Blocked(reason)).into());
			}
		};
		tokio::select! {
			biased;
			() = control.grant.wait_revoked() => {}
			() = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
		}
		control
			.grant
			.check_source(control.digest)
			.map_err(Error::Grant)?;
		Ok(())
	}
}

/// A unique grant-checked attempt before its actual transport and SSH admission.
pub struct ConnectingRemoteSource<'authorization> {
	scope: &'authorization RemoteDownloadScope,
	supervisor: Arc<Supervisor>,
	attempt: ConnectionAttempt,
	attempt_started: Instant,
}

impl<'authorization> ConnectingRemoteSource<'authorization> {
	/// Claims the initial attempt with a fresh local supervisor.
	///
	/// # Errors
	/// Refuses invalid scope, unavailable entropy or invalid authorization.
	pub fn begin(
		scope: &'authorization RemoteDownloadScope,
		grant: &Arc<RemoteGrant>,
	) -> Result<Self, RemoteDownloadFailure> {
		SourceInvocation::new(scope, grant)?.claim()
	}

	/// The exact generation reserved before opening the actual transport.
	#[must_use]
	pub const fn attempt(&self) -> ConnectionAttempt {
		self.attempt
	}

	fn connect_deadline(&self) -> Option<Instant> {
		connection_deadline(self.attempt_started, self.supervisor.grant.deadline())
	}

	/// Rechecks the exact connecting attempt and shared active authorization.
	/// # Errors
	/// Refuses expired, revoked or obsolete work before or after a transport await.
	pub fn check_current(&mut self) -> Result<(), RetryError> {
		self.supervisor.check_connecting(self.attempt)
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
		if !transport.finish_connection() {
			return Err(route_refusal());
		}
		Ok(ConnectedRemoteSource {
			session,
			owner: SourceOwner {
				supervisor: self.supervisor,
				attempt: self.attempt,
				route,
				transport,
				#[cfg(test)]
				retirement_issued: false,
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

	pub(in crate::assembly::linux) fn into_current(
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
	retry: Mutex<RetrySupervisor>,
}

impl Supervisor {
	fn observe<T>(
		&self,
		operation: impl FnOnce(&mut RetrySupervisor, Duration) -> Result<T, RetryError>,
	) -> Result<T, RetryError> {
		self.grant.check_source(self.digest)?;
		let mut retry = self.retry.lock().map_err(|_| RetryError::StaleWork)?;
		operation(&mut retry, self.start.elapsed())
	}

	fn check_connecting(&self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.observe(|retry, now| retry.check_connecting(now, attempt))
	}
}

fn connection_deadline(attempt_started: Instant, grant_deadline: Instant) -> Option<Instant> {
	Some(
		attempt_started
			.checked_add(authentication::CONNECTION_BUDGET)?
			.min(grant_deadline),
	)
}

pub(in crate::assembly::linux) struct SourceOwner<'authorization> {
	supervisor: Arc<Supervisor>,
	attempt: ConnectionAttempt,
	route: BoundRoute<'authorization>,
	transport: Arc<RouteTask>,
	#[cfg(test)]
	retirement_issued: bool,
}

impl SourceOwner<'_> {
	pub(super) fn retry_grant(&self) -> Arc<RemoteGrant> {
		Arc::clone(&self.supervisor.grant)
	}

	pub(in crate::assembly::linux) const fn attempt(&self) -> ConnectionAttempt {
		self.attempt
	}

	pub(in crate::assembly::linux) fn admit_pending(
		&mut self,
		pending: &PendingSftpSource<'_>,
	) -> Result<ConnectionBinding, RetryError> {
		let attempt = pending.attempt();
		self.check_connecting(attempt)?;
		let routed = self.attempt();
		self.supervisor.observe(|retry, now| {
			retry.admit(
				now,
				attempt,
				ReconnectEvidence {
					route_checked_for: routed,
					ssh_authenticated_for: routed,
					source_checked_for: pending.attempt(),
					source_epoch: pending.epoch(),
				},
			)
		})
	}

	pub(in crate::assembly::linux) fn check_binding(
		&self,
		binding: ConnectionBinding,
	) -> Result<(), RetryError> {
		self.check_transport()?;
		self.supervisor
			.observe(|retry, now| retry.check_completion(now, binding))
	}

	pub(super) fn observe_read_health(&self, binding: ConnectionBinding) -> Result<(), RetryError> {
		if binding.attempt() != self.attempt {
			return Err(RetryError::StaleWork);
		}
		self.check_transport()?;
		let control = &self.supervisor;
		let _grant = control.grant.source_lock(control.digest)?;
		let mut retry = control.retry.lock().map_err(|_| RetryError::StaleWork)?;
		retry.observe_health(
			control.start.elapsed(),
			binding,
			VerifiedHealth::SuccessfulOperation,
		)
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
		self.supervisor
			.observe(|retry, now| retry.check_attempt(now, attempt))
	}
}

#[cfg(test)]
mod tests;
