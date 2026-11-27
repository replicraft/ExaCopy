use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU128};
use std::sync::Arc;
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{PermanentFailure, RetryBlock, RetryError};
use exacopy_endpoint::ssh_sftp::HostKeyFingerprint;
use exacopy_endpoint::wireguard::{
	EmbeddedDialCommand, EmbeddedDialConnector, InnerDial, InnerDialKind, ProfileRevision,
	RouteObservation, WireGuardDialPolicy, WireGuardDialSession,
};
use exacopy_journal::remote_download::{RemoteDownloadRoute, RemoteScopeDigest};
use exacopy_ssh::Error as SshError;
use exacopy_wireguard::protocol::{
	MAX_DATAGRAM_BYTES, PeerAddresses, PeerBinding, ProtocolPeer, PublicKey,
};
use exacopy_wireguard::stack::{InnerMtu, RouteRevocation};
use exacopy_wireguard::udp::{RouteOwner, TcpDialSettings, UdpPeer, UdpTcpAdmission, UdpTcpRoute};
use tokio::net::UdpSocket;

use crate::remote_frontdoor::{ApprovedRoute, FrontdoorError, SshProfile, WireGuardRoute};

use super::super::{AttemptAdmission, Error};
use super::authentication::{OfferLease, authenticate};
use super::route_lifetime::{RouteLease, RouteTask, RouteWake};
use super::{
	ConnectedRemoteSource, ConnectingRemoteSource, CurrentEmbeddedStream,
	EmbeddedStreamObservation, RemoteGrant, RemoteRouteCloseError, RemoteRoutePeer, kernel_random,
	route_refusal,
};

mod key;
mod owner;

use owner::EmbeddedOwner;

#[cfg(test)]
mod tests;

const RECEIVE_SLICE: Duration = Duration::from_millis(250);
const HANDSHAKE_STEPS: usize = 1024;
const IPV6_INNER_MIN: usize = 1280;

impl ConnectingRemoteSource<'_> {
	/// Consumes this attempt and runs the caller with the exact carrier's live route lent to SSH.
	pub(crate) async fn with_embedded<'held, T>(
		mut self,
		profile: &SshProfile,
		admission: AttemptAdmission<'held>,
		is_cancelled: impl FnOnce() -> bool,
		consume: impl for<'route> AsyncFnOnce(
			ConnectedRemoteSource<'route>,
			AttemptAdmission<'held>,
		) -> T,
	) -> Result<EmbeddedOutcome<T>, EmbeddedConnectFailure> {
		let approved = self.selected_embedded_route(profile)?;
		let grant = Arc::clone(&self.supervisor.grant);
		let deadline = self
			.connect_deadline()
			.ok_or(EmbeddedConnectError::Timeout)?;
		let scope = self.supervisor.digest;
		check(&mut self, deadline)?;
		let trust = profile
			.read_trust()
			.map_err(EmbeddedConnectError::Profile)?;
		check(&mut self, deadline)?;

		let (binding, settings) = reserve_transport(self.attempt().generation(), approved)?;
		let lease = RouteLease::connecting(deadline);
		let revocation = RouteRevocation::new(binding);
		let owner = EmbeddedOwner::new(
			Arc::clone(&grant),
			scope,
			binding,
			lease.activity(),
			revocation.clone(),
		);
		let carrier = bounded(
			&grant,
			scope,
			deadline,
			prepare_carrier(
				&mut self, approved, binding, settings, owner, deadline, &admission,
			),
		)
		.await?;
		carrier
			.with_confirmed_shutdown()
			.with_stream(async move |stream, driver, live_route| {
				let guard = Arc::new(RouteTask::spawn_draining(
					lease,
					RouteWake::Embedded(revocation),
					Arc::clone(&grant),
					async move { driver.run().await },
				));
				let route = HeldRoute {
					live_route,
					original: binding,
				};
				let use_route = async {
					let offer = OfferLease::new(Arc::clone(&grant), scope, deadline);
					let connected = bounded(&grant, scope, deadline, async {
						check(&mut self, deadline)?;
						let session = authenticate(stream, profile, trust, &offer, || {
							route.observe().is_some()
						})
						.await;
						check(&mut self, deadline)?;
						let session = session.map_err(EmbeddedConnectError::Ssh)?;
						self.bind_authenticated(
							session,
							RemoteRoutePeer::Embedded(&route),
							Arc::clone(&guard),
						)
						.map_err(EmbeddedConnectError::Retry)
					})
					.await?;
					drop(offer);
					Ok(consume(connected, admission).await)
				};
				run_then_retire(&guard, use_route, is_cancelled).await
			})
			.await
	}

	fn selected_embedded_route<'profile>(
		&self,
		profile: &'profile SshProfile,
	) -> Result<&'profile WireGuardRoute, EmbeddedConnectError> {
		let RemoteDownloadRoute::EmbeddedWireGuard {
			peer,
			revision,
			inner,
		} = self.scope.source.route()
		else {
			return Err(EmbeddedConnectError::Authority);
		};
		let ApprovedRoute::EmbeddedWireGuard(approved) = &profile.route else {
			return Err(EmbeddedConnectError::Authority);
		};
		if &profile.authority != self.scope.source.authority()
			|| profile.pin != HostKeyFingerprint::from_sha256(*self.scope.source.host_key_sha256())
			|| approved.peer_public_key != peer
			|| approved.revision != revision
			|| approved.remote_inner != inner
		{
			return Err(EmbeddedConnectError::Authority);
		}
		Ok(approved)
	}
}

/// Result from the route consumer and the final observation of its transport worker.
pub(crate) struct EmbeddedOutcome<T> {
	pub(crate) outcome: T,
	pub(crate) retirement: Result<(), RemoteRouteCloseError>,
}

async fn run_then_retire<T>(
	guard: &RouteTask,
	use_route: impl Future<Output = Result<T, EmbeddedConnectError>>,
	is_cancelled: impl FnOnce() -> bool,
) -> Result<EmbeddedOutcome<T>, EmbeddedConnectFailure> {
	let outcome = use_route.await.map_err(|cause| (cause, is_cancelled()));
	guard.stop();
	let retirement = guard.join().await;
	match outcome {
		// The consumer may already have used the exact binding's retirement.
		// Reobserving the worker returns its cached result independently.
		Ok(outcome) => Ok(EmbeddedOutcome {
			outcome,
			retirement,
		}),
		Err((cause, cancelled)) => Err(EmbeddedConnectFailure {
			cause,
			cancelled_at_refusal: Some(cancelled),
			route_failure: retirement.err(),
		}),
	}
}

async fn bounded<T>(
	grant: &RemoteGrant,
	scope: RemoteScopeDigest,
	deadline: Instant,
	future: impl Future<Output = Result<T, EmbeddedConnectError>>,
) -> Result<T, EmbeddedConnectError> {
	tokio::select! {
		biased;
		() = grant.wait_revoked() => Err(EmbeddedConnectError::Retry(RetryError::Blocked(
			RetryBlock::Permanent(PermanentFailure::GrantRevoked),
		))),
		result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future) => {
			result.map_err(|_| {
				grant.check_source(scope).err()
					.map_or(EmbeddedConnectError::Timeout, EmbeddedConnectError::Retry)
			})?
		}
	}
}

fn check(
	source: &mut ConnectingRemoteSource<'_>,
	deadline: Instant,
) -> Result<(), EmbeddedConnectError> {
	source
		.check_current()
		.map_err(EmbeddedConnectError::Retry)?;
	if Instant::now() >= deadline {
		return Err(EmbeddedConnectError::Timeout);
	}
	Ok(())
}

fn reserve_transport(
	generation: std::num::NonZeroU64,
	approved: &WireGuardRoute,
) -> Result<(PeerBinding, TcpDialSettings), EmbeddedConnectError> {
	let mut actor = [0; 16];
	let mut port = [0; 2];
	let mut sequence = [0; 8];
	for bytes in [&mut actor[..], &mut port[..], &mut sequence[..]] {
		kernel_random(bytes).map_err(|_| EmbeddedConnectError::Entropy)?;
	}
	let binding = PeerBinding {
		revision: approved.revision,
		actor: NonZeroU128::new(u128::from_ne_bytes(actor)).ok_or(EmbeddedConnectError::Entropy)?,
		generation,
	};
	let settings = TcpDialSettings {
		local_port: ephemeral_port(port),
		outer_path_mtu: approved.outer_mtu,
		random_seed: u64::from_ne_bytes(sequence),
	};
	Ok((binding, settings))
}

fn ephemeral_port(bytes: [u8; 2]) -> NonZeroU16 {
	NonZeroU16::MIN.saturating_add(49_151 + (u16::from_ne_bytes(bytes) & 0x3fff))
}

async fn prepare_carrier(
	source: &mut ConnectingRemoteSource<'_>,
	approved: &WireGuardRoute,
	binding: PeerBinding,
	settings: TcpDialSettings,
	owner: EmbeddedOwner,
	deadline: Instant,
	admission: &AttemptAdmission<'_>,
) -> Result<UdpTcpAdmission<EmbeddedOwner>, EmbeddedConnectError> {
	let mtu = InnerMtu::from_outer(approved.outer, approved.outer_mtu)
		.map_err(|_| EmbeddedConnectError::Mtu)?;
	if approved.remote_inner.is_ipv6() && mtu.bytes() < IPV6_INNER_MIN {
		return Err(EmbeddedConnectError::Mtu);
	}
	let local_private = key::read_private(&approved.private_key_file, approved.local_public_key)?;
	check(source, deadline)?;
	let protocol = ProtocolPeer::new(
		binding,
		PeerAddresses {
			outer: approved.outer,
			local: approved.local_inner,
			remote: approved.remote_inner.ip(),
		},
		local_private,
		PublicKey::from(approved.peer_public_key),
	)
	.map_err(|_| EmbeddedConnectError::KeyProfile)?;

	let local_ip = if approved.outer.is_ipv4() {
		IpAddr::V4(Ipv4Addr::UNSPECIFIED)
	} else {
		IpAddr::V6(Ipv6Addr::UNSPECIFIED)
	};
	let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await;
	check(source, deadline)?;
	let socket = socket.map_err(EmbeddedConnectError::Udp)?;
	let result = socket.connect(approved.outer).await;
	check(source, deadline)?;
	result.map_err(EmbeddedConnectError::Udp)?;

	let command = approved_dial(&owner, binding, approved.remote_inner)?;
	let mut peer =
		UdpPeer::from_connected(owner, socket, protocol).map_err(EmbeddedConnectError::Peer)?;
	let mut packets = [0; MAX_DATAGRAM_BYTES];
	admission
		.check_before_dial()
		.map_err(EmbeddedConnectError::Native)?;
	check(source, deadline)?;
	let _ = peer
		.initiate(&mut packets)
		.map_err(EmbeddedConnectError::Peer)?;
	for _ in 0..HANDSHAKE_STEPS {
		if peer.session_ready().map_err(EmbeddedConnectError::Peer)? {
			check(source, deadline)?;
			return peer
				.into_tcp(command, settings)
				.map_err(EmbeddedConnectError::Tcp);
		}
		let step = peer.receive_one(RECEIVE_SLICE, &mut packets).await;
		check(source, deadline)?;
		let _ = step.map_err(EmbeddedConnectError::Peer)?;
		let _ = peer
			.tick(&mut packets)
			.map_err(EmbeddedConnectError::Peer)?;
	}
	Err(EmbeddedConnectError::HandshakeBudget)
}

struct Dispatch<'a>(&'a EmbeddedOwner);

impl EmbeddedDialConnector for Dispatch<'_> {
	type Pending = EmbeddedDialCommand;
	type Error = std::convert::Infallible;

	fn observation(&self) -> RouteObservation {
		self.0.with_observation(|value| value)
	}

	fn enqueue(&mut self, command: EmbeddedDialCommand) -> Result<Self::Pending, Self::Error> {
		Ok(command)
	}
}

fn approved_dial(
	owner: &EmbeddedOwner,
	binding: PeerBinding,
	address: SocketAddr,
) -> Result<EmbeddedDialCommand, EmbeddedConnectError> {
	let dial =
		InnerDial::new(InnerDialKind::Stream, address).ok_or(EmbeddedConnectError::Authority)?;
	let targets = [dial];
	let policy = WireGuardDialPolicy::new(ProfileRevision::from_bytes(binding.revision), &targets)
		.map_err(|_| EmbeddedConnectError::Authority)?;
	let mut connector = Dispatch(owner);
	let current = connector.observation();
	let session = WireGuardDialSession::bind(&policy, binding.actor, binding.generation, current)
		.map_err(|_| EmbeddedConnectError::Retry(route_refusal()))?;
	let permit = session
		.authorize(dial, current)
		.map_err(|_| EmbeddedConnectError::Authority)?;
	session
		.dispatch(permit, &mut connector)
		.map_err(|_| EmbeddedConnectError::Retry(route_refusal()))
}

struct HeldRoute<'scope> {
	live_route: &'scope UdpTcpRoute<EmbeddedOwner>,
	original: PeerBinding,
}

impl CurrentEmbeddedStream for HeldRoute<'_> {
	fn observe(&self) -> Option<EmbeddedStreamObservation> {
		let peer = self.live_route.current()?;
		let binding = peer.binding();
		(binding == self.original).then(|| EmbeddedStreamObservation {
			stream: binding.actor,
			peer: peer.remote_public_key(),
			revision: binding.revision,
			inner: peer.inner(),
		})
	}
}

#[derive(Debug)]
pub(crate) struct EmbeddedConnectFailure {
	pub(crate) cause: EmbeddedConnectError,
	pub(crate) cancelled_at_refusal: Option<bool>,
	pub(crate) route_failure: Option<RemoteRouteCloseError>,
}

impl From<EmbeddedConnectError> for EmbeddedConnectFailure {
	fn from(cause: EmbeddedConnectError) -> Self {
		Self {
			cause,
			cancelled_at_refusal: None,
			route_failure: None,
		}
	}
}

impl fmt::Display for EmbeddedConnectFailure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.cause.fmt(out)?;
		if let Some(route) = self.route_failure {
			write!(out, " (route retirement unconfirmed: {route})")?;
		}
		Ok(())
	}
}

impl std::error::Error for EmbeddedConnectFailure {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(&self.cause)
	}
}

#[derive(Debug)]
pub(crate) enum EmbeddedConnectError {
	Authority,
	Profile(FrontdoorError),
	KeyProfile,
	Entropy,
	Mtu,
	Retry(RetryError),
	Native(Error),
	Timeout,
	HandshakeBudget,
	Udp(io::Error),
	Peer(exacopy_wireguard::udp::UdpError),
	Tcp(exacopy_wireguard::udp::UdpTcpError),
	Ssh(SshError),
}

impl fmt::Display for EmbeddedConnectError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Authority => out.write_str("the exact approved embedded route changed"),
			Self::Profile(cause) => cause.fmt(out),
			Self::KeyProfile => out.write_str("the protected WireGuard key or peer was refused"),
			Self::Entropy => out.write_str("no fresh embedded transport identity was available"),
			Self::Mtu => out.write_str(
				"the approved outer path MTU cannot carry the selected inner address family",
			),
			Self::Retry(cause) => cause.fmt(out),
			Self::Native(cause) => cause.fmt(out),
			Self::Timeout => out.write_str("the embedded SSH connection deadline elapsed"),
			Self::HandshakeBudget => {
				out.write_str("the embedded WireGuard handshake exceeded its operation limit")
			}
			Self::Udp(cause) => write!(out, "embedded UDP admission failed ({cause})"),
			Self::Peer(cause) => cause.fmt(out),
			Self::Tcp(cause) => cause.fmt(out),
			Self::Ssh(cause) => cause.fmt(out),
		}
	}
}

impl std::error::Error for EmbeddedConnectError {}
