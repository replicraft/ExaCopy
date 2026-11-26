//! Per-key age, confirmation and budget within one immutable route binding.

use std::time::Duration;

use boringtun::noise::{
	Packet, TransportKey, TransportKeyId, TransportKeyOrigin, TransportKeyResult, TransportKeyUse,
	Tunn, TunnResult,
};

#[cfg(feature = "experimental-udp")]
use super::PacketOutput;
use super::clock::{ClockValue, MAX_GENERATION_AGE, elapsed};
use super::{MAX_GENERATION_OPERATIONS, MAX_INCOMING_HANDSHAKES, ProtocolError, ProtocolPeer};

const RETAINED_SLOTS: usize = 8;
const PROACTIVE_KEY_AGE: Duration = Duration::from_secs(60);
const PROACTIVE_ATTEMPT_INTERVAL: Duration = Duration::from_secs(5);
const REKEY_OPERATION_HEADROOM: u32 = MAX_GENERATION_OPERATIONS / 4;
const REKEY_HANDSHAKE_HEADROOM: u16 = MAX_INCOMING_HANDSHAKES / 4;

#[derive(Clone, Copy)]
struct KeyWindow {
	id: TransportKeyId,
	started: ClockValue,
	deadline: ClockValue,
	confirmed: bool,
}

#[derive(Default)]
pub(super) struct KeyLifetime {
	retained: [Option<KeyWindow>; RETAINED_SLOTS],
	latest_installation: Option<TransportKeyId>,
	active_epoch: Option<(TransportKeyId, ClockValue)>,
	last_proactive: Option<ClockValue>,
	output_key: Option<TransportKeyId>,
}

impl KeyLifetime {
	fn window(&self, id: TransportKeyId) -> Option<KeyWindow> {
		self.retained
			.iter()
			.flatten()
			.find(|entry| entry.id == id)
			.copied()
	}

	fn bounds(&self, key: TransportKey, now: ClockValue) -> Option<(KeyWindow, u64)> {
		let window = self.window(key.id)?;
		let native_age = key.age?;
		let operations = key.next_send_counter.checked_add(key.received_packets)?;
		(now < window.deadline
			&& native_age < MAX_GENERATION_AGE
			&& key.origin != TransportKeyOrigin::PreviousInitiation)
			.then_some((window, operations))
	}

	fn selected(&self, tunnel: &Tunn, now: ClockValue) -> Option<KeyWindow> {
		let (window, operations) = self.bounds(tunnel.current_transport_key()?, now)?;
		(window.confirmed && operations < u64::from(MAX_GENERATION_OPERATIONS)).then_some(window)
	}

	fn fence(&mut self, tunnel: &mut Tunn, now: ClockValue) {
		let mut surviving = [None; RETAINED_SLOTS];
		let mut slots = surviving.iter_mut();
		tunnel.retain_transport_keys(|key| {
			let Some((window, operations)) = self.bounds(key, now) else {
				return false;
			};
			if operations >= u64::from(MAX_GENERATION_OPERATIONS) {
				return false;
			}
			let Some(slot) = slots.next() else {
				return false;
			};
			*slot = Some(window);
			true
		});
		self.retained = surviving;
	}

	fn register_installation(
		&mut self,
		tunnel: &Tunn,
		started: ClockValue,
	) -> Result<(), ProtocolError> {
		let Some(key) = tunnel.newest_transport_key() else {
			return Ok(());
		};
		if self.latest_installation.is_some_and(|id| key.id <= id) {
			return Ok(());
		}
		self.latest_installation = Some(key.id);
		if key.origin == TransportKeyOrigin::PreviousInitiation {
			return Ok(());
		}
		let slot = self
			.retained
			.iter_mut()
			.find(|entry| entry.is_none_or(|window| tunnel.transport_key(window.id).is_none()))
			.ok_or(ProtocolError::Rejected)?;
		*slot = Some(KeyWindow {
			id: key.id,
			started,
			deadline: started
				.checked_add(MAX_GENERATION_AGE)
				.ok_or(ProtocolError::ClockUnavailable)?,
			confirmed: false,
		});
		Ok(())
	}

	fn confirm(&mut self, id: TransportKeyId) -> Result<(), ProtocolError> {
		let window = self
			.retained
			.iter_mut()
			.flatten()
			.find(|window| window.id == id)
			.ok_or(ProtocolError::Rejected)?;
		window.confirmed = true;
		Ok(())
	}

	fn check_result_key(
		&self,
		tunnel: &Tunn,
		id: TransportKeyId,
		now: ClockValue,
	) -> Result<(TransportKey, KeyWindow), ProtocolError> {
		let key = tunnel.transport_key(id).ok_or(ProtocolError::Rejected)?;
		let (window, operations) = self.bounds(key, now).ok_or(ProtocolError::Rejected)?;
		if operations > u64::from(MAX_GENERATION_OPERATIONS) {
			return Err(ProtocolError::OperationLimit);
		}
		Ok((key, window))
	}
}

impl ProtocolPeer {
	pub(super) fn selected_is_admitted(&self) -> bool {
		self.clock
			.current()
			.is_ok_and(|now| self.keys.selected(&self.tunnel, now).is_some())
	}

	pub(super) fn prepare_tunnel(&mut self) -> Result<ClockValue, ProtocolError> {
		self.keys.output_key = None;
		self.clock.advance()?;
		let now = self.clock.observed();
		self.keys.fence(&mut self.tunnel, now);
		Ok(now)
	}

	pub(super) fn tick_tunnel<'buffer>(
		&mut self,
		output: &'buffer mut [u8],
		now: ClockValue,
	) -> TransportKeyResult<'buffer> {
		let selected = self.keys.selected(&self.tunnel, now);
		let should_rekey = selected.is_none_or(|key| {
			elapsed(now, key.started).is_some_and(|age| age >= PROACTIVE_KEY_AGE)
		}) || self.operations_remaining <= REKEY_OPERATION_HEADROOM
			|| self.handshakes_remaining <= REKEY_HANDSHAKE_HEADROOM;
		let paced = self.keys.last_proactive.is_none_or(|last| {
			elapsed(now, last).is_some_and(|age| age >= PROACTIVE_ATTEMPT_INTERVAL)
		});
		if self.keys.active_epoch.is_some() && should_rekey && paced {
			self.keys.last_proactive = Some(now);
			return TransportKeyResult {
				result: self.tunnel.format_handshake_initiation(output, false),
				key_use: None,
			};
		}

		// A reused ring slot can be selected before responder confirmation.
		// Keep it available for ingress but suppress timer encryption with it.
		if selected.is_none() && self.tunnel.current_transport_key().is_some() {
			return TransportKeyResult {
				result: TunnResult::Done,
				key_use: None,
			};
		}
		self.tunnel.update_timers_with_transport_key(output)
	}

	pub(super) fn register_key_installation(
		&mut self,
		started: ClockValue,
	) -> Result<(), ProtocolError> {
		self.keys.register_installation(&self.tunnel, started)
	}

	pub(super) fn admit_result(
		&mut self,
		result: &TunnResult<'_>,
		key_use: Option<TransportKeyUse>,
	) -> Result<(), ProtocolError> {
		let (id, outbound) = match (result, key_use) {
			(TunnResult::Done, None) => return Ok(()),
			(TunnResult::Done, Some(TransportKeyUse::Received(id)))
			| (
				TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..),
				Some(TransportKeyUse::Received(id)),
			) => (id, false),
			(TunnResult::WriteToNetwork(bytes), Some(TransportKeyUse::Sent(id)))
				if matches!(
					Tunn::parse_incoming_packet(bytes),
					Ok(Packet::PacketData(_))
				) =>
			{
				(id, true)
			}
			(TunnResult::WriteToNetwork(bytes), None)
				if matches!(
					Tunn::parse_incoming_packet(bytes),
					Ok(Packet::HandshakeInit(_)
						| Packet::HandshakeResponse(_)
						| Packet::PacketCookieReply(_))
				) =>
			{
				return Ok(());
			}
			_ => return Err(ProtocolError::Rejected),
		};
		let now = self.clock.observed();
		let (key, window) = self.keys.check_result_key(&self.tunnel, id, now)?;
		if !window.confirmed {
			match (outbound, key.origin) {
				(true, TransportKeyOrigin::CurrentInitiation)
				| (false, TransportKeyOrigin::IncomingInitiation) => self.keys.confirm(id)?,
				_ => return Err(ProtocolError::Rejected),
			}
		}

		// Retained old traffic and unselected completions can never replenish the active epoch.
		if let Some(selected) = self.keys.selected(&self.tunnel, now)
			&& selected.id == id
			&& self.keys.active_epoch.is_none_or(|(old, renewed_at)| {
				selected.id > old
					&& elapsed(now, renewed_at).is_some_and(|age| age >= PROACTIVE_ATTEMPT_INTERVAL)
			}) {
			self.clock.attach_epoch(selected.deadline)?;
			self.keys.active_epoch = Some((selected.id, now));
			self.operations_remaining = MAX_GENERATION_OPERATIONS - 1;
			self.handshakes_remaining = MAX_INCOMING_HANDSHAKES - 1;
		}
		if !matches!(result, TunnResult::Done) {
			self.keys.output_key = Some(id);
		}
		Ok(())
	}

	#[cfg(feature = "experimental-udp")]
	pub(in crate::protocol) fn check_output_key(
		&mut self,
		packet: &PacketOutput<'_>,
	) -> Result<(), ProtocolError> {
		self.clock.advance()?;
		let requires_key = match packet {
			PacketOutput::None => false,
			PacketOutput::Inner(_) => true,
			PacketOutput::Outer { bytes, .. } => {
				matches!(
					Tunn::parse_incoming_packet(bytes),
					Ok(Packet::PacketData(_))
				)
			}
		};
		let issued = self.keys.output_key.take();
		if requires_key != issued.is_some() {
			return Err(ProtocolError::Rejected);
		}
		if let Some(id) = issued {
			let (_, window) =
				self.keys
					.check_result_key(&self.tunnel, id, self.clock.observed())?;
			if !window.confirmed {
				return Err(ProtocolError::Rejected);
			}
		}
		Ok(())
	}
}
