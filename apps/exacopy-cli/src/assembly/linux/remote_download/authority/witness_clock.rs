use std::num::NonZeroU64;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A wall sample bracketed by the original grant issuer's monotonic timeline.
#[derive(Clone, Copy)]
pub(super) struct ClockSample {
	before: Instant,
	wall: Duration,
	after: Instant,
}

impl ClockSample {
	pub(super) fn now() -> Option<Self> {
		let before = Instant::now();
		let wall = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
		let after = Instant::now();
		Some(Self {
			before,
			wall,
			after,
		})
	}

	pub(super) fn deadline(self, grant_end: Instant) -> Option<WitnessDeadline> {
		let latest = self
			.wall
			.checked_add(grant_end.checked_duration_since(self.after)?)?;
		let wall = NonZeroU64::new(latest.as_secs())?;
		let from_anchor = Duration::from_secs(wall.get()).checked_sub(self.wall)?;
		let monotonic = self.before.checked_add(from_anchor)?;
		(monotonic > self.after && monotonic <= grant_end).then_some(WitnessDeadline {
			wall,
			monotonic,
			first_wall: self.wall,
		})
	}
}

/// Conservative expiration projected once from the original grant's wall sample.
#[derive(Clone, Copy)]
pub(in crate::assembly::linux) struct WitnessDeadline {
	wall: NonZeroU64,
	monotonic: Instant,
	first_wall: Duration,
}

impl WitnessDeadline {
	pub(in crate::assembly::linux) const fn wall_seconds(self) -> NonZeroU64 {
		self.wall
	}

	pub(in crate::assembly::linux) fn check(self, last: Option<Duration>) -> Option<Duration> {
		self.check_sample(ClockSample::now()?, last)
	}

	fn check_sample(self, current: ClockSample, last: Option<Duration>) -> Option<Duration> {
		(current.after < self.monotonic
			&& current.wall >= last.unwrap_or(self.first_wall)
			&& current.wall < Duration::from_secs(self.wall.get()))
		.then_some(current.wall)
	}
}

#[cfg(test)]
mod tests {
	use super::{ClockSample, Duration, Instant};

	#[test]
	fn approval_expires_on_either_clock_and_rollbacks_cannot_extend_it() {
		let before = Instant::now();
		let start = ClockSample {
			before,
			wall: Duration::from_millis(91_750),
			after: before + Duration::from_millis(25),
		};
		let deadline = start
			.deadline(before + Duration::from_millis(2_100))
			.unwrap();
		assert_eq!(deadline.wall_seconds().get(), 93);
		assert_eq!(deadline.monotonic, before + Duration::from_millis(1_250));
		let sample = |mono, wall| ClockSample {
			before,
			after: before + Duration::from_millis(mono),
			wall: Duration::from_millis(wall),
		};
		assert_eq!(
			deadline.check_sample(sample(800, 92_600), None),
			Some(Duration::from_millis(92_600))
		);
		assert!(
			deadline
				.check_sample(sample(900, 92_500), Some(Duration::from_millis(92_600)))
				.is_none()
		);
		assert!(deadline.check_sample(sample(900, 93_000), None).is_none());
		assert!(deadline.check_sample(sample(1_250, 92_650), None).is_none());
	}
}
