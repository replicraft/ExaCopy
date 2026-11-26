use std::net::SocketAddr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

use super::TcpError;
use super::ack::Segment;

const IPV4_HEADER_BYTES: u8 = 20;

pub(super) struct ParsedPacket {
	pub(super) segment: Segment,
	pub(super) reset: bool,
}

pub(super) fn parse(
	bytes: &[u8],
	source: SocketAddr,
	destination: SocketAddr,
	mtu: usize,
) -> Result<ParsedPacket, TcpError> {
	if bytes.len() > mtu {
		return Err(TcpError::Packet);
	}

	let (addresses, payload) = match bytes.first().map(|byte| byte >> 4) {
		Some(4) => {
			let packet = Ipv4Packet::new_checked(bytes).map_err(|_| TcpError::Packet)?;
			if packet.header_len() != IPV4_HEADER_BYTES
				|| usize::from(packet.total_len()) != bytes.len()
				|| packet.more_frags()
				|| packet.frag_offset() != 0
				|| packet.next_header() != IpProtocol::Tcp
				|| !packet.verify_checksum()
			{
				return Err(TcpError::Packet);
			}
			(
				(
					IpAddress::from(packet.src_addr()),
					IpAddress::from(packet.dst_addr()),
				),
				packet.payload(),
			)
		}
		Some(6) => {
			let packet = Ipv6Packet::new_checked(bytes).map_err(|_| TcpError::Packet)?;
			if packet.total_len() != bytes.len() || packet.next_header() != IpProtocol::Tcp {
				return Err(TcpError::Packet);
			}
			(
				(
					IpAddress::from(packet.src_addr()),
					IpAddress::from(packet.dst_addr()),
				),
				packet.payload(),
			)
		}
		_ => return Err(TcpError::Packet),
	};
	if addresses != (source.ip().into(), destination.ip().into()) {
		return Err(TcpError::FlowMismatch);
	}
	let tcp = TcpPacket::new_checked(payload).map_err(|_| TcpError::Packet)?;
	if (tcp.src_port(), tcp.dst_port()) != (source.port(), destination.port()) {
		return Err(TcpError::FlowMismatch);
	}
	if !tcp.verify_checksum(&addresses.0, &addresses.1) {
		return Err(TcpError::Packet);
	}
	Ok(ParsedPacket {
		segment: Segment {
			sequence: u32::from_ne_bytes(tcp.seq_number().0.to_ne_bytes()),
			acknowledgement: tcp
				.ack()
				.then(|| u32::from_ne_bytes(tcp.ack_number().0.to_ne_bytes())),
			payload: u32::try_from(tcp.payload().len()).map_err(|_| TcpError::Packet)?,
			syn: tcp.syn(),
			fin: tcp.fin(),
		},
		reset: tcp.rst(),
	})
}
