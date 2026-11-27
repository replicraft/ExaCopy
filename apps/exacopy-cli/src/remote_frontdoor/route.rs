use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::PathBuf;

use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_endpoint::wireguard::{InnerDial, InnerDialKind};
use serde::Deserialize;

use super::FrontdoorError;
use super::profile::{PublicDigest, protected_path};

pub(crate) const MAX_OUTER_MTU: u16 = 1500;
const MAX_ADDRESSES: usize = 64;
const WG_REVISION_DOMAIN: &[u8] = b"ExaCopy/ssh-profile/embedded-route/v2\0";

/// The explicitly approved order for an independently supervised host lookup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AddressOrder {
	Ipv4First,
	Ipv6First,
}

impl AddressOrder {
	/// Selects the first usable literal in the preferred family from the complete lookup.
	///
	/// # Errors
	/// Refuses an oversized lookup or one without a usable address for the approved port.
	pub(crate) fn select_address(
		self,
		addresses: impl Iterator<Item = SocketAddr>,
		port: NonZeroU16,
	) -> Result<SocketAddr, FrontdoorError> {
		let (mut v4, mut v6) = (None, None);
		for (index, address) in addresses.take(MAX_ADDRESSES + 1).enumerate() {
			if index == MAX_ADDRESSES {
				return Err(FrontdoorError::Route);
			}
			if address.port() != port.get() || !valid_socket(address) {
				continue;
			}
			if address.is_ipv4() {
				v4.get_or_insert(address);
			} else {
				v6.get_or_insert(address);
			}
		}
		match self {
			Self::Ipv4First => v4.or(v6),
			Self::Ipv6First => v6.or(v4),
		}
		.ok_or(FrontdoorError::Route)
	}
}

/// An exact route request. It cannot open a socket or issue route authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ApprovedRoute {
	Direct(SocketAddr),
	ResolveAuthority(AddressOrder),
	EmbeddedWireGuard(WireGuardRoute),
}

/// The protected file selection and approved public parameters of one fixed peer.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WireGuardRoute {
	pub(crate) outer: SocketAddr,
	pub(crate) outer_mtu: u16,
	pub(crate) local_inner: IpAddr,
	pub(crate) remote_inner: SocketAddr,
	pub(crate) local_public_key: [u8; 32],
	pub(crate) peer_public_key: [u8; 32],
	pub(crate) private_key_file: PathBuf,
	pub(crate) revision: [u8; 32],
}

impl std::fmt::Debug for WireGuardRoute {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WireGuardRoute").finish_non_exhaustive()
	}
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum WireRoute {
	Direct {
		endpoint: SocketAddr,
	},
	ResolveAuthority {
		order: AddressOrder,
	},
	EmbeddedWireguard {
		outer: SocketAddr,
		outer_mtu: u16,
		local_inner: IpAddr,
		remote_inner: SocketAddr,
		local_public_key: PublicDigest,
		peer_public_key: PublicDigest,
		private_key_file: PathBuf,
	},
}

impl WireRoute {
	pub(super) fn admit(self, authority: &SshAuthority) -> Result<ApprovedRoute, FrontdoorError> {
		let literal = authority.host().parse::<IpAddr>().ok();
		let port = authority.port();
		match self {
			Self::Direct { endpoint } => {
				if endpoint.port() != port.get()
					|| !valid_socket(endpoint)
					|| literal.is_some_and(|ip| endpoint.ip() != ip)
				{
					return Err(FrontdoorError::Route);
				}
				Ok(ApprovedRoute::Direct(endpoint))
			}
			Self::ResolveAuthority { order } if literal.is_none() => {
				Ok(ApprovedRoute::ResolveAuthority(order))
			}
			Self::ResolveAuthority { .. } => Err(FrontdoorError::Route),
			Self::EmbeddedWireguard {
				outer,
				outer_mtu,
				local_inner,
				remote_inner,
				local_public_key,
				peer_public_key,
				private_key_file,
			} => {
				let peer = remote_inner.ip();
				if !valid_socket(outer)
					|| !(1..=MAX_OUTER_MTU).contains(&outer_mtu)
					|| !valid_socket(remote_inner)
					|| remote_inner.port() != port.get()
					|| literal.is_some_and(|ip| peer != ip)
					|| !valid_socket(SocketAddr::new(local_inner, NonZeroU16::MIN.get()))
					|| local_inner.is_ipv4() != peer.is_ipv4()
					|| local_inner == peer
					|| local_public_key == peer_public_key
				{
					return Err(FrontdoorError::Route);
				}
				let private_key_file = protected_path(private_key_file)?;
				let mut route = WireGuardRoute {
					outer,
					outer_mtu,
					local_inner,
					remote_inner,
					local_public_key: local_public_key.0,
					peer_public_key: peer_public_key.0,
					private_key_file,
					revision: [0; 32],
				};
				route.revision = route_revision(&route);
				Ok(ApprovedRoute::EmbeddedWireGuard(route))
			}
		}
	}
}

fn valid_socket(address: SocketAddr) -> bool {
	InnerDial::new(InnerDialKind::Stream, address).is_some()
		&& !matches!(address.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
}

fn route_revision(route: &WireGuardRoute) -> [u8; 32] {
	let mut hash = blake3::Hasher::new();
	hash.update(WG_REVISION_DOMAIN);
	hash.update(&route.local_public_key);
	hash.update(&route.peer_public_key);
	hash_ip(&mut hash, route.outer.ip());
	hash.update(&route.outer.port().to_be_bytes());
	hash.update(&route.outer_mtu.to_be_bytes());
	hash_ip(&mut hash, route.local_inner);
	hash_ip(&mut hash, route.remote_inner.ip());
	hash.update(&route.remote_inner.port().to_be_bytes());
	*hash.finalize().as_bytes()
}

fn hash_ip(hash: &mut blake3::Hasher, ip: IpAddr) {
	match ip {
		IpAddr::V4(ip) => {
			hash.update(&[4]);
			hash.update(&ip.octets());
		}
		IpAddr::V6(ip) => {
			hash.update(&[6]);
			hash.update(&ip.octets());
		}
	}
}

#[cfg(test)]
mod tests {
	use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
	use std::num::NonZeroU16;

	use super::{AddressOrder, FrontdoorError, MAX_ADDRESSES};

	const SSH_PORT: NonZeroU16 = NonZeroU16::new(22).unwrap();

	#[test]
	fn bounded_resolution_selects_first_usable_literal_in_preferred_family() {
		let v4 = "192.0.2.20:22".parse().unwrap();
		let v6 = "[2001:db8::20]:22".parse().unwrap();
		let later_v4 = "192.0.2.21:22".parse().unwrap();
		let wrong_port = "192.0.2.22:2222".parse().unwrap();
		let values = [wrong_port, v6, v4, later_v4];
		assert_eq!(
			AddressOrder::Ipv6First
				.select_address(values.into_iter(), SSH_PORT)
				.ok(),
			Some(v6)
		);
		assert_eq!(
			AddressOrder::Ipv4First
				.select_address(values.into_iter(), SSH_PORT)
				.ok(),
			Some(v4)
		);
		assert_eq!(
			AddressOrder::Ipv6First
				.select_address(std::iter::repeat_n(v4, MAX_ADDRESSES), SSH_PORT)
				.ok(),
			Some(v4)
		);
		assert!(matches!(
			AddressOrder::Ipv4First
				.select_address(std::iter::repeat_n(v4, MAX_ADDRESSES + 1), SSH_PORT),
			Err(FrontdoorError::Route)
		));
		let oversized = std::iter::once(v4).chain(std::iter::repeat_n(wrong_port, MAX_ADDRESSES));
		assert!(matches!(
			AddressOrder::Ipv4First.select_address(oversized, SSH_PORT),
			Err(FrontdoorError::Route)
		));
	}

	#[test]
	fn resolution_refuses_empty_and_unsupported_answers() {
		let global_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
		let unusable: [SocketAddr; 9] = [
			"192.0.2.20:2222".parse().unwrap(),
			"0.0.0.0:22".parse().unwrap(),
			"224.0.0.1:22".parse().unwrap(),
			"255.255.255.255:22".parse().unwrap(),
			"[::]:22".parse().unwrap(),
			"[::ffff:192.0.2.20]:22".parse().unwrap(),
			"[fe80::20]:22".parse().unwrap(),
			SocketAddrV6::new(global_v6, SSH_PORT.get(), 0, 1).into(),
			SocketAddrV6::new(global_v6, SSH_PORT.get(), 1, 0).into(),
		];
		assert!(matches!(
			AddressOrder::Ipv4First.select_address(std::iter::empty(), SSH_PORT),
			Err(FrontdoorError::Route)
		));
		for address in unusable {
			assert!(
				matches!(
					AddressOrder::Ipv4First.select_address(std::iter::once(address), SSH_PORT),
					Err(FrontdoorError::Route)
				),
				"unexpected route for {address:?}"
			);
		}
	}
}
