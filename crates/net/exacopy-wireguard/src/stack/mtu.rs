use std::net::SocketAddr;

use crate::protocol::INNER_MTU;

use super::TcpError;

const IPV4_BASE_HEADER: usize = 20;
const IPV6_BASE_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const WG_TRANSPORT_OVERHEAD: usize = 32;
const WG_PADDING_ALIGNMENT: usize = 16;
pub(super) const IPV4_INNER_MIN: usize = 576;
pub(super) const IPV6_INNER_MIN: usize = 1280;

/// An inner packet ceiling derived from the selected outer path budget.
#[derive(Clone, Copy)]
pub struct InnerMtu(usize);

impl InnerMtu {
	/// Computes an inner MTU from the reported path MTU and outer address family.
	///
	/// This budgets only base IP headers. The route owner must deduct any
	/// known additional enclosure or option bytes from the path MTU first.
	///
	/// # Errors
	/// Refuses a path budget too small to carry the supported IPv4 minimum.
	/// Open also checks the selected inner address family's minimum.
	pub fn from_outer(peer: SocketAddr, path_mtu: u16) -> Result<Self, TcpError> {
		let ip_header = if peer.is_ipv4() {
			IPV4_BASE_HEADER
		} else {
			IPV6_BASE_HEADER
		};
		let budget = usize::from(path_mtu)
			.checked_sub(ip_header + UDP_HEADER + WG_TRANSPORT_OVERHEAD)
			.ok_or(TcpError::Mtu)?;
		let aligned = budget / WG_PADDING_ALIGNMENT * WG_PADDING_ALIGNMENT;
		let inner = aligned.min(INNER_MTU);
		if inner < IPV4_INNER_MIN {
			return Err(TcpError::Mtu);
		}
		Ok(Self(inner))
	}

	/// The exact packet ceiling for this path budget.
	#[must_use]
	pub const fn bytes(self) -> usize {
		self.0
	}
}
