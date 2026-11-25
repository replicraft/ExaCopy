use std::{fmt, io};

use exacopy_endpoint::wireguard::WireGuardDialError;

use crate::protocol::ProtocolError;

/// The operation that encountered a native UDP failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketPhase {
	/// Checking the bound outer endpoint.
	Admit,
	/// Observing readiness or reading one datagram.
	Receive,
	/// Sending one BoringTun output.
	Send,
}

/// A bounded UDP actor refusal. Display never includes addresses or packet bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum UdpError {
	/// A revoked, unavailable or changed route observation.
	RouteChanged,
	/// The route owner could not reserve the requested generation.
	GenerationUnavailable,
	/// A previously retired generation.
	Retired,
	/// The connected peer or protocol destination differs from the pinned peer.
	EndpointMismatch,
	/// The requested readiness wait exceeds the actor bound.
	WaitLimit,
	/// A datagram arrived outside the transport byte bound.
	DatagramLimit,
	/// The endpoint permit is stale or scoped to a different actor.
	Dial(WireGuardDialError),
	/// The fixed peer cannot serve this inner address or purpose.
	InnerTargetUnsupported,
	/// The protocol operation was refused.
	Protocol(ProtocolError),
	/// A native socket operation failed.
	Socket(SocketPhase, io::Error),
}

impl UdpError {
	pub(super) fn retires_peer(&self) -> bool {
		matches!(
			self,
			Self::RouteChanged
				| Self::EndpointMismatch
				| Self::Socket(..)
				| Self::Protocol(
					ProtocolError::ClockUnavailable
						| ProtocolError::Expired
						| ProtocolError::OperationLimit
				)
		)
	}
}

impl fmt::Display for UdpError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::RouteChanged => formatter.write_str("the authorized WireGuard route changed"),
			Self::GenerationUnavailable => {
				formatter.write_str("the WireGuard UDP generation cannot be reserved")
			}
			Self::Retired => formatter.write_str("the WireGuard UDP generation is retired"),
			Self::EndpointMismatch => formatter.write_str("connected WireGuard peer mismatch"),
			Self::WaitLimit => formatter.write_str("the WireGuard socket wait exceeds its bound"),
			Self::DatagramLimit => formatter.write_str("the WireGuard datagram exceeds its bound"),
			Self::Dial(error) => error.fmt(formatter),
			Self::InnerTargetUnsupported => {
				formatter.write_str("the fixed WireGuard peer cannot serve this inner target")
			}
			Self::Protocol(error) => error.fmt(formatter),
			Self::Socket(phase, _) => write!(formatter, "WireGuard UDP {phase:?} failed"),
		}
	}
}

impl std::error::Error for UdpError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Dial(error) => Some(error),
			Self::Protocol(error) => Some(error),
			Self::Socket(_, error) => Some(error),
			_ => None,
		}
	}
}
