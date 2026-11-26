use std::cmp::Ordering;

use super::TcpError;

const SEQUENCE_HALF_RANGE: u32 = 1 << 31;

/// Bounded projection of TCP fields after packet and flow validation.
pub(super) struct Segment {
	pub(super) sequence: u32,
	pub(super) acknowledgement: Option<u32>,
	pub(super) payload: u32,
	pub(super) syn: bool,
	pub(super) fin: bool,
}

#[derive(Default)]
pub(super) struct EmittedSequence {
	high: Option<u32>,
}

impl EmittedSequence {
	// This checks only the upper acknowledgement bound. The TCP stack remains
	// responsible for acceptable windows, the lower bound, and state.
	pub(super) fn admit(&self, segment: &Segment) -> Result<(), TcpError> {
		let Some(acknowledgement) = segment.acknowledgement else {
			return Ok(());
		};
		let high = self.high.ok_or(TcpError::Acknowledgement)?;
		match serial_cmp(acknowledgement, high) {
			Some(Ordering::Less | Ordering::Equal) => Ok(()),
			_ => Err(TcpError::Acknowledgement),
		}
	}

	// A retransmission may extend the frontier but cannot move it backwards.
	// Return a candidate only. The caller advances it after successful egress.
	pub(super) fn outgoing(&self, segment: Segment) -> Result<Option<u32>, TcpError> {
		let controls = u32::from(segment.syn) + u32::from(segment.fin);
		let occupied = segment
			.payload
			.checked_add(controls)
			.ok_or(TcpError::Sequence)?;
		if occupied == 0 {
			return Ok(None);
		}
		let end = segment.sequence.wrapping_add(occupied);
		let Some(high) = self.high else {
			return if segment.syn {
				Ok(Some(end))
			} else {
				Err(TcpError::Sequence)
			};
		};
		if !matches!(
			serial_cmp(segment.sequence, high),
			Some(Ordering::Less | Ordering::Equal)
		) {
			return Err(TcpError::Sequence);
		}
		match serial_cmp(end, high) {
			Some(Ordering::Greater) => Ok(Some(end)),
			Some(Ordering::Less | Ordering::Equal) => Ok(None),
			None => Err(TcpError::Sequence),
		}
	}

	pub(super) fn emitted(&mut self, candidate: Option<u32>) {
		if let Some(candidate) = candidate {
			self.high = Some(candidate);
		}
	}
}

fn serial_cmp(left: u32, right: u32) -> Option<Ordering> {
	// TCP's 32-bit sequence space wraps. Exactly half the space is ambiguous.
	match left.wrapping_sub(right) {
		0 => Some(Ordering::Equal),
		delta if delta < SEQUENCE_HALF_RANGE => Some(Ordering::Greater),
		delta if delta > SEQUENCE_HALF_RANGE => Some(Ordering::Less),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn segment(sequence: u32, payload: u32, syn: bool, fin: bool) -> Segment {
		Segment {
			sequence,
			acknowledgement: None,
			payload,
			syn,
			fin,
		}
	}

	fn ack(acknowledgement: u32) -> Segment {
		Segment {
			acknowledgement: Some(acknowledgement),
			..segment(0, 0, false, false)
		}
	}

	#[test]
	fn syn_and_fin_occupy_sequence_space_across_wrap() {
		let mut emitted = EmittedSequence::default();
		assert_eq!(emitted.admit(&ack(0)), Err(TcpError::Acknowledgement));
		let first = emitted.outgoing(segment(u32::MAX, 0, true, false)).unwrap();
		assert_eq!(first, Some(0));
		assert_eq!(emitted.admit(&ack(0)), Err(TcpError::Acknowledgement));
		emitted.emitted(first);
		assert_eq!(emitted.admit(&ack(0)), Ok(()));
		assert_eq!(emitted.admit(&ack(1)), Err(TcpError::Acknowledgement));
		let end = emitted.outgoing(segment(0, 7, false, true)).unwrap();
		assert_eq!(end, Some(8));
		assert_eq!(emitted.admit(&ack(7)), Err(TcpError::Acknowledgement));
		emitted.emitted(end);
		assert_eq!(emitted.admit(&ack(8)), Ok(()));
		assert_eq!(emitted.admit(&ack(9)), Err(TcpError::Acknowledgement));
	}

	#[test]
	fn stale_ack_and_retransmission_never_move_the_frontier() {
		let mut emitted = EmittedSequence { high: Some(34) };
		assert_eq!(emitted.admit(&ack(30)), Ok(()));
		assert_eq!(
			emitted.admit(&ack(34 + SEQUENCE_HALF_RANGE)),
			Err(TcpError::Acknowledgement)
		);
		assert_eq!(emitted.outgoing(segment(5, 10, false, false)), Ok(None));
		emitted.emitted(None);
		assert_eq!(emitted.admit(&ack(34)), Ok(()));
		assert_eq!(
			emitted.outgoing(segment(35, 1, false, false)),
			Err(TcpError::Sequence)
		);
		assert_eq!(emitted.outgoing(segment(29, 6, false, false)), Ok(Some(35)));
	}
}

#[cfg(test)]
mod independent {
	use super::{EmittedSequence, Segment};

	#[test]
	fn contiguous_submission_with_overlap_and_fin_advances_across_serial_boundaries() {
		for initial in [19u32, i32::MAX as u32 - 2, u32::MAX - 2] {
			let mut accounting = EmittedSequence::default();
			let byte = |sequence, payload, syn, fin| Segment {
				sequence,
				acknowledgement: None,
				payload,
				syn,
				fin,
			};
			let submit = accounting.outgoing(byte(initial, 0, true, false)).unwrap();
			assert_eq!(accounting.high, None);
			accounting.emitted(submit);
			let first = initial.wrapping_add(1);
			assert_eq!(accounting.high, Some(first));

			let initial_data = accounting.outgoing(byte(first, 17, false, false)).unwrap();
			accounting.emitted(initial_data);
			let old_data = accounting.outgoing(byte(first, 17, false, false)).unwrap();
			assert_eq!(old_data, None);
			accounting.emitted(old_data);

			let overlap = first.wrapping_add(12);
			let extended = accounting
				.outgoing(byte(overlap, 10, false, false))
				.unwrap();
			assert_eq!(accounting.high, Some(first.wrapping_add(17)));
			accounting.emitted(extended);
			let next = first.wrapping_add(22);
			assert_eq!(accounting.high, Some(next));
			let fin = accounting.outgoing(byte(next, 0, false, true)).unwrap();
			accounting.emitted(fin);
			assert_eq!(accounting.high, Some(next.wrapping_add(1)));
			for acknowledged in [first, next, next.wrapping_add(1)] {
				let stale_or_exact = Segment {
					acknowledgement: Some(acknowledged),
					..byte(0, 0, false, false)
				};
				assert_eq!(accounting.admit(&stale_or_exact), Ok(()));
			}
		}
	}
}
