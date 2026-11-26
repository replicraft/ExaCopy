use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::protocol::INNER_MTU;

pub(super) struct PacketDevice {
	pub(super) rx: PacketSlot,
	pub(super) tx: PacketSlot,
	mtu: usize,
}

pub(super) struct PacketSlot {
	bytes: [u8; INNER_MTU],
	length: usize,
}

impl PacketSlot {
	const fn new() -> Self {
		Self {
			bytes: [0; INNER_MTU],
			length: 0,
		}
	}

	pub(super) fn get(&self) -> Option<&[u8]> {
		(self.length != 0).then(|| &self.bytes[..self.length])
	}

	pub(super) fn clear(&mut self) {
		self.length = 0;
	}

	pub(super) fn queue(&mut self, bytes: &[u8]) {
		self.bytes[..bytes.len()].copy_from_slice(bytes);
		self.length = bytes.len();
	}
}

impl PacketDevice {
	pub(super) const fn new(mtu: usize) -> Self {
		Self {
			mtu,
			rx: PacketSlot::new(),
			tx: PacketSlot::new(),
		}
	}
}

impl Device for PacketDevice {
	type RxToken<'a> = ReceiveToken<'a>;
	type TxToken<'a> = TransmitToken<'a>;

	fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
		if self.rx.get().is_none() || self.tx.get().is_some() {
			return None;
		}
		Some((ReceiveToken(&mut self.rx), TransmitToken(&mut self.tx)))
	}

	fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
		self.tx
			.get()
			.is_none()
			.then_some(TransmitToken(&mut self.tx))
	}

	fn capabilities(&self) -> DeviceCapabilities {
		let mut capabilities = DeviceCapabilities::default();
		capabilities.medium = Medium::Ip;
		capabilities.max_transmission_unit = self.mtu;
		capabilities
	}
}

pub(super) struct ReceiveToken<'a>(&'a mut PacketSlot);

impl RxToken for ReceiveToken<'_> {
	fn consume<R, F: FnOnce(&[u8]) -> R>(self, receive: F) -> R {
		let used = self.0.length;
		self.0.clear();
		receive(&self.0.bytes[..used])
	}
}

pub(super) struct TransmitToken<'a>(&'a mut PacketSlot);

impl TxToken for TransmitToken<'_> {
	fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, transmit: F) -> R {
		// The pinned stack sizes TCP egress against the advertised IP MTU.
		let result = transmit(&mut self.0.bytes[..length]);
		self.0.length = length;
		result
	}
}
