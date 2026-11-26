use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use exacopy_endpoint::connection_retry::{PermanentFailure, RetryBlock, RetryError};
use exacopy_endpoint::ssh_sftp::HostKeyFingerprint;
use exacopy_journal::remote_download::RemoteDownloadRoute;
use exacopy_ssh::{Error as SshError, KnownHostTrust};
use tokio::net::TcpStream;

use crate::remote_frontdoor::{ApprovedRoute, FrontdoorError, SshProfile};

use super::super::{AttemptAdmission, Error};
use super::authentication::{OfferLease, authenticate};
use super::route_lifetime::{RouteLease, RouteTask, RouteWake};
use super::{ConnectedRemoteSource, ConnectingRemoteSource, RemoteRoutePeer};

mod stream;

use stream::{GrantedStream, refused};

impl<'authorization> ConnectingRemoteSource<'authorization> {
	/// Opens exactly the selected signed direct TCP endpoint and consumes that stream in SSH.
	pub(crate) async fn connect_direct(
		mut self,
		profile: &SshProfile,
		admission: &AttemptAdmission<'_>,
	) -> Result<ConnectedRemoteSource<'authorization>, DirectConnectError> {
		let endpoint = self.selected_direct_endpoint(profile)?;
		let grant = Arc::clone(&self.supervisor.grant);
		let deadline = self.connect_deadline().ok_or(DirectConnectError::Timeout)?;
		self.check_deadline(deadline)?;
		let trust = profile.read_trust().map_err(DirectConnectError::Profile)?;
		self.check_deadline(deadline)?;
		let scope = self.supervisor.digest;
		let offer = OfferLease::new(Arc::clone(&grant), scope, deadline);

		let connect = self.establish_direct(profile, endpoint, trust, deadline, &offer, admission);
		let result = tokio::select! {
			biased;
			() = grant.wait_revoked() => Err(DirectConnectError::Retry(RetryError::Blocked(
				RetryBlock::Permanent(PermanentFailure::GrantRevoked),
			))),
			result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), connect) => {
				result.map_err(|_| {
					grant
						.check_source(scope)
						.err()
						.map_or(DirectConnectError::Timeout, DirectConnectError::Retry)
				})?
			}
		}?;
		grant
			.check_source(scope)
			.map_err(DirectConnectError::Retry)?;
		if Instant::now() >= deadline {
			return Err(DirectConnectError::Timeout);
		}
		Ok(result)
	}

	fn selected_direct_endpoint(
		&self,
		profile: &SshProfile,
	) -> Result<SocketAddr, DirectConnectError> {
		let RemoteDownloadRoute::ResolvedDirect { endpoint } = self.scope.source.route() else {
			return Err(DirectConnectError::Authority);
		};
		if &profile.authority != self.scope.source.authority()
			|| profile.pin != HostKeyFingerprint::from_sha256(*self.scope.source.host_key_sha256())
		{
			return Err(DirectConnectError::Authority);
		}
		match &profile.route {
			ApprovedRoute::Direct(approved) if *approved == endpoint => Ok(endpoint),
			ApprovedRoute::ResolveAuthority(_) => Ok(endpoint),
			_ => Err(DirectConnectError::Authority),
		}
	}

	fn check_deadline(&mut self, deadline: Instant) -> Result<(), DirectConnectError> {
		self.check_current().map_err(DirectConnectError::Retry)?;
		if Instant::now() >= deadline {
			return Err(DirectConnectError::Timeout);
		}
		Ok(())
	}

	async fn establish_direct(
		mut self,
		profile: &SshProfile,
		endpoint: SocketAddr,
		trust: KnownHostTrust,
		deadline: Instant,
		offer: &OfferLease,
		admission: &AttemptAdmission<'_>,
	) -> Result<ConnectedRemoteSource<'authorization>, DirectConnectError> {
		self.check_deadline(deadline)?;
		admission
			.check_before_dial()
			.map_err(DirectConnectError::Native)?;
		let lease = RouteLease::connecting(deadline);
		let route = lease.activity();
		let grant = Arc::clone(&self.supervisor.grant);
		let scope = self.supervisor.digest;
		let mut dial = std::pin::pin!(TcpStream::connect(endpoint));
		let connected = poll_fn(|cx| {
			route.with_grant(&grant, scope, |current| {
				if current {
					dial.as_mut().poll(cx)
				} else {
					refused()
				}
			})
		})
		.await;
		self.check_deadline(deadline)?;
		let stream = connected.map_err(DirectConnectError::Dial)?;
		let peer = stream.peer_addr().map_err(DirectConnectError::Dial)?;
		self.scope
			.source
			.recheck_resolved_direct_peer(peer)
			.map_err(|_| DirectConnectError::Authority)?;
		self.check_deadline(deadline)?;
		let (stream, closed) =
			GrantedStream::new(stream, Arc::clone(&grant), scope, Arc::clone(&route));
		let session = authenticate(stream, profile, trust, offer, || {
			route.is_active() && self.scope.source.recheck_resolved_direct_peer(peer).is_ok()
		})
		.await;
		self.check_deadline(deadline)?;
		let session = session.map_err(DirectConnectError::Ssh)?;
		let task = RouteTask::spawn(
			lease,
			RouteWake::Ssh(session.cancellation_handle()),
			grant,
			Some(closed),
			std::future::pending(),
		);
		self.bind_authenticated(session, RemoteRoutePeer::Direct(peer), Arc::new(task))
			.map_err(DirectConnectError::Retry)
	}
}

#[derive(Debug)]
pub(crate) enum DirectConnectError {
	Authority,
	Profile(FrontdoorError),
	Retry(RetryError),
	Native(Error),
	Timeout,
	Dial(io::Error),
	Ssh(SshError),
}

impl fmt::Display for DirectConnectError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Authority => out.write_str("the exact approved direct SSH route changed"),
			Self::Profile(cause) => cause.fmt(out),
			Self::Retry(cause) => cause.fmt(out),
			Self::Native(cause) => cause.fmt(out),
			Self::Timeout => out.write_str("the direct SSH connection deadline elapsed"),
			Self::Dial(cause) => write!(out, "direct TCP connection failed ({cause})"),
			Self::Ssh(cause) => cause.fmt(out),
		}
	}
}

impl std::error::Error for DirectConnectError {}
