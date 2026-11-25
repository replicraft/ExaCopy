//! Sample the same elapsed-time clock as the selected BoringTun backend.

use std::time::Duration;

use super::ProtocolError;

const MAX_GENERATION_AGE: Duration = Duration::from_secs(120);

#[cfg(any(target_os = "linux", target_os = "macos"))]
type ClockValue = Duration;
#[cfg(target_os = "windows")]
type ClockValue = std::time::Instant;

pub(super) struct GenerationClock {
	deadline: ClockValue,
	last_seen: ClockValue,
}

impl GenerationClock {
	pub(super) fn start() -> Result<Self, ProtocolError> {
		let now = sample()?;
		Ok(Self {
			deadline: now
				.checked_add(MAX_GENERATION_AGE)
				.ok_or(ProtocolError::ClockUnavailable)?,
			last_seen: now,
		})
	}

	#[cfg(test)]
	pub(super) fn expire_for_test(&mut self) {
		self.deadline = sample().unwrap();
	}

	pub(super) fn check(&self) -> Result<(), ProtocolError> {
		self.check_sample(sample()?)
	}

	pub(super) fn advance(&mut self) -> Result<(), ProtocolError> {
		let now = sample()?;
		self.check_sample(now)?;
		self.last_seen = now;
		Ok(())
	}

	fn check_sample(&self, now: ClockValue) -> Result<(), ProtocolError> {
		if elapsed(now, self.last_seen).is_none() {
			return Err(ProtocolError::ClockUnavailable);
		}
		if now >= self.deadline {
			return Err(ProtocolError::Expired);
		}
		Ok(())
	}
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn elapsed(now: ClockValue, start: ClockValue) -> Option<Duration> {
	now.checked_sub(start)
}

#[cfg(target_os = "windows")]
fn elapsed(now: ClockValue, start: ClockValue) -> Option<Duration> {
	now.checked_duration_since(start)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sample() -> Result<ClockValue, ProtocolError> {
	use rustix::time::{DynamicClockId, clock_gettime_dynamic};

	#[cfg(target_os = "linux")]
	const GENERATION_CLOCK: DynamicClockId<'static> = DynamicClockId::Boottime;
	#[cfg(target_os = "macos")]
	const GENERATION_CLOCK: DynamicClockId<'static> =
		DynamicClockId::Known(rustix::time::ClockId::Monotonic);

	let raw =
		clock_gettime_dynamic(GENERATION_CLOCK).map_err(|_| ProtocolError::ClockUnavailable)?;
	let seconds = u64::try_from(raw.tv_sec).map_err(|_| ProtocolError::ClockUnavailable)?;
	let nanos = u32::try_from(raw.tv_nsec).map_err(|_| ProtocolError::ClockUnavailable)?;
	if nanos >= 1_000_000_000 {
		return Err(ProtocolError::ClockUnavailable);
	}
	Ok(Duration::new(seconds, nanos))
}

#[cfg(target_os = "windows")]
#[expect(
	clippy::unnecessary_wraps,
	reason = "share the fallible clock contract across targets"
)]
fn sample() -> Result<ClockValue, ProtocolError> {
	Ok(std::time::Instant::now())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deadline_and_backward_samples_fail_closed() {
		let base = sample().unwrap();
		let live = base + MAX_GENERATION_AGE - Duration::from_nanos(1);
		let clock = GenerationClock {
			deadline: base + MAX_GENERATION_AGE,
			last_seen: base + Duration::from_secs(1),
		};
		assert_eq!(clock.check_sample(live), Ok(()));
		assert_eq!(
			clock.check_sample(base + MAX_GENERATION_AGE),
			Err(ProtocolError::Expired)
		);
		assert_eq!(
			clock.check_sample(base),
			Err(ProtocolError::ClockUnavailable)
		);
	}

	#[test]
	fn selected_clock_produces_ordered_samples() {
		let mut clock = GenerationClock::start().unwrap();
		clock.advance().unwrap();
		clock.advance().unwrap();
		clock.check().unwrap();
	}
}
