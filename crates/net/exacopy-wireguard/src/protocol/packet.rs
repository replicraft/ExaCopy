use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ProtocolError;

const HANDSHAKE_INITIATION: [u8; 4] = 1_u32.to_le_bytes();
const HANDSHAKE_RESPONSE: [u8; 4] = 2_u32.to_le_bytes();
const INITIATION_BYTES: usize = 148;
const RESPONSE_BYTES: usize = 92;
const INITIATION_EPHEMERAL_OFFSET: usize = 8;
const RESPONSE_EPHEMERAL_OFFSET: usize = 12;
const TRANSPORT_MESSAGE: [u8; 4] = 4_u32.to_le_bytes();
// WireGuard whitepaper section 6.1. A key serves counters zero through limit - 1.
pub(super) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

pub(super) fn admitted_counter(datagram: &[u8]) -> bool {
	if !datagram.starts_with(&TRANSPORT_MESSAGE) {
		return true;
	}
	let Some(counter) = datagram.get(8..).and_then(<[u8]>::first_chunk::<8>) else {
		return false;
	};
	u64::from_le_bytes(*counter) < REJECT_AFTER_MESSAGES
}

// BoringTun 0.7.1's parser requires this same type and whole packet length.
// Only project the public ephemeral. Authentication stays inside Tunn.
pub(super) fn handshake_ephemeral(datagram: &[u8]) -> Result<Option<&[u8; 32]>, ProtocolError> {
	let (length, offset) = match datagram.first_chunk::<4>() {
		Some(&HANDSHAKE_INITIATION) => (INITIATION_BYTES, INITIATION_EPHEMERAL_OFFSET),
		Some(&HANDSHAKE_RESPONSE) => (RESPONSE_BYTES, RESPONSE_EPHEMERAL_OFFSET),
		_ => return Ok(None),
	};
	if datagram.len() != length {
		return Err(ProtocolError::Rejected);
	}
	datagram
		.get(offset..)
		.and_then(<[u8]>::first_chunk::<32>)
		.map(Some)
		.ok_or(ProtocolError::Rejected)
}

const IPV4_BASE_HEADER: usize = 20;
const IPV6_BASE_HEADER: usize = 40;

pub(super) fn is_literal_unicast(ip: IpAddr) -> bool {
	!ip.is_unspecified()
		&& !ip.is_multicast()
		&& match ip {
			IpAddr::V4(v4) => !v4.is_broadcast(),
			IpAddr::V6(v6) => v6.to_ipv4_mapped().is_none(),
		}
}

pub(super) fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
	match packet.first()? >> 4 {
		4 => ipv4(packet),
		6 => ipv6(packet),
		_ => None,
	}
}

fn ipv4(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
	let header = packet.first_chunk::<IPV4_BASE_HEADER>()?;
	let header_len = usize::from(header[0] & 0x0f) * 4;
	let packet_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
	if header_len < IPV4_BASE_HEADER || header_len > packet_len || packet_len != packet.len() {
		return None;
	}
	let source = Ipv4Addr::from(*header[12..].first_chunk::<4>()?);
	let destination = Ipv4Addr::from(*header[16..].first_chunk::<4>()?);
	Some((source.into(), destination.into()))
}

fn ipv6(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
	let header = packet.first_chunk::<IPV6_BASE_HEADER>()?;
	let payload_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
	if IPV6_BASE_HEADER + payload_len != packet.len() {
		return None;
	}
	let source = Ipv6Addr::from(*header[8..].first_chunk::<16>()?);
	let destination = Ipv6Addr::from(*header[24..].first_chunk::<16>()?);
	Some((source.into(), destination.into()))
}
