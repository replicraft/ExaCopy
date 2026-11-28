use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exacopy_journal::OwnerTimestamp;
use exacopy_model::grant_time::{
	GrantTimeRefusal, MonotonicObservation, UtcWindow, check_grant_time,
};

use super::LocalApplyGrantError;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(super) struct ClockSample {
	pub(super) monotonic: Instant,
	pub(super) utc: OwnerTimestamp,
}

impl ClockSample {
	pub(super) fn now() -> Result<Self, LocalApplyGrantError> {
		use LocalApplyGrantError::Clock;
		let monotonic = Instant::now();
		let elapsed = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|_| Clock)?;
		let seconds = i64::try_from(elapsed.as_secs()).map_err(|_| Clock)?;
		let utc = OwnerTimestamp::new(seconds, elapsed.subsec_nanos()).map_err(|_| Clock)?;
		Ok(Self { monotonic, utc })
	}
}

pub(super) struct GrantClock {
	deadline: Instant,
	not_before: OwnerTimestamp,
	plan_expiry: OwnerTimestamp,
	last: ClockSample,
	qualification: Option<QualificationWindow>,
}

#[derive(Clone, Copy)]
pub(super) struct QualificationWindow {
	pub(super) starts_at: OwnerTimestamp,
	pub(super) expires_at: OwnerTimestamp,
}

impl GrantClock {
	pub(super) fn new(
		initial: ClockSample,
		duration: Duration,
		not_before: OwnerTimestamp,
		plan_expiry: OwnerTimestamp,
	) -> Result<Self, LocalApplyGrantError> {
		let deadline = initial
			.monotonic
			.checked_add(duration)
			.ok_or(LocalApplyGrantError::Clock)?;
		let mut clock = Self {
			deadline,
			not_before,
			plan_expiry,
			last: initial,
			qualification: None,
		};
		clock.observe(initial)?;
		Ok(clock)
	}

	pub(super) fn tighten(
		&mut self,
		sample: ClockSample,
		window: QualificationWindow,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		if self.qualification.is_some() || stamp(window.starts_at) >= stamp(window.expires_at) {
			return Err(LocalApplyGrantError::Phase);
		}
		self.qualification = Some(window);
		self.observe(sample)
	}

	pub(super) fn observe(
		&mut self,
		sample: ClockSample,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		let monotonic = if sample.monotonic < self.last.monotonic {
			MonotonicObservation::Regressed
		} else if sample.monotonic >= self.deadline {
			MonotonicObservation::Expired
		} else {
			MonotonicObservation::Current
		};
		check_grant_time(
			monotonic,
			stamp(sample.utc),
			stamp(self.last.utc),
			UtcWindow {
				starts_at: stamp(self.not_before),
				expires_at: stamp(self.plan_expiry),
			},
			self.qualification.map(|window| UtcWindow {
				starts_at: stamp(window.starts_at),
				expires_at: stamp(window.expires_at),
			}),
		)
		.map_err(|refusal| match refusal {
			GrantTimeRefusal::Regressed => LocalApplyGrantError::Clock,
			GrantTimeRefusal::Expired => LocalApplyGrantError::Expired,
		})?;
		self.last = sample;
		Ok(sample.utc)
	}
}

fn stamp(value: OwnerTimestamp) -> (i64, u32) {
	(value.seconds(), value.nanoseconds())
}
