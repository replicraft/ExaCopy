use std::{error::Error, fmt};

use crate::stack::TcpError;
use crate::udp::UdpError;

/// A typed refusal while composing the fixed UDP and inner TCP capabilities.
#[derive(Debug)]
#[non_exhaustive]
pub enum UdpTcpError {
	/// The connected peer could not confirm a permitted operation.
	Udp(UdpError),
	/// The inner flow could not be admitted.
	Tcp(TcpError),
	/// A protocol result was incompatible with the admitted operation.
	Output,
	/// The next periodic timer could not be represented.
	Clock,
}

impl fmt::Display for UdpTcpError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Udp(error) => error.fmt(formatter),
			Self::Tcp(error) => error.fmt(formatter),
			Self::Output => formatter.write_str("unexpected WireGuard output for inner TCP flow"),
			Self::Clock => formatter.write_str("inner TCP protocol timer exceeded its clock range"),
		}
	}
}

impl Error for UdpTcpError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Udp(error) => Some(error),
			Self::Tcp(error) => Some(error),
			_ => None,
		}
	}
}

impl From<UdpError> for UdpTcpError {
	fn from(error: UdpError) -> Self {
		Self::Udp(error)
	}
}

impl From<TcpError> for UdpTcpError {
	fn from(error: TcpError) -> Self {
		Self::Tcp(error)
	}
}
