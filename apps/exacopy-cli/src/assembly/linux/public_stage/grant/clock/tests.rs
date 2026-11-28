use std::time::{Duration, Instant};

use exacopy_journal::OwnerTimestamp;

use super::{ClockSample, GrantClock, LocalApplyGrantError as Failure, QualificationWindow};

fn utc(seconds: i64, nanos: u32) -> OwnerTimestamp {
	OwnerTimestamp::new(seconds, nanos).expect("normalized fixture")
}

fn sample(anchor: Instant, elapsed: u64, utc: OwnerTimestamp) -> ClockSample {
	ClockSample {
		monotonic: anchor + Duration::from_secs(elapsed),
		utc,
	}
}

fn issued(anchor: Instant) -> GrantClock {
	GrantClock::new(
		sample(anchor, 0, utc(100, 500)),
		Duration::from_secs(10),
		utc(100, 500),
		utc(130, 500),
	)
	.expect("opening bound is inclusive")
}

#[test]
fn either_rollback_wins_over_expiry_without_replacing_the_accepted_pair() {
	let anchor = Instant::now();
	let mut clock = issued(anchor);
	let accepted = sample(anchor, 4, utc(104, 500));
	assert_eq!(clock.observe(accepted), Ok(accepted.utc));

	assert_eq!(
		clock.observe(sample(anchor, 10, utc(104, 499))),
		Err(Failure::Clock)
	);
	assert_eq!(
		clock.observe(sample(anchor, 3, utc(130, 500))),
		Err(Failure::Clock)
	);
	assert_eq!(
		clock.observe(sample(anchor, 10, utc(110, 500))),
		Err(Failure::Expired)
	);
	assert_eq!(clock.last.monotonic, accepted.monotonic);
	assert_eq!(clock.last.utc, accepted.utc);
	assert_eq!(clock.observe(accepted), Ok(accepted.utc));
}

#[test]
fn refused_first_tightening_keeps_its_window_without_advancing_the_sample() {
	let anchor = Instant::now();
	let mut clock = issued(anchor);
	let window = QualificationWindow {
		starts_at: utc(104, 500),
		expires_at: utc(105, 500),
	};
	assert_eq!(
		clock.tighten(sample(anchor, 4, utc(104, 499)), window),
		Err(Failure::Expired)
	);
	assert_eq!(clock.last.monotonic, anchor);
	assert_eq!(clock.last.utc, utc(100, 500));
	assert_eq!(
		clock.tighten(sample(anchor, 10, utc(100, 499)), window),
		Err(Failure::Phase)
	);
	assert_eq!(
		clock.observe(sample(anchor, 3, utc(104, 499))),
		Err(Failure::Expired)
	);
	assert_eq!(
		clock.observe(sample(anchor, 3, utc(104, 500))),
		Ok(utc(104, 500))
	);
	assert_eq!(
		clock.observe(sample(anchor, 4, utc(105, 499))),
		Ok(utc(105, 499))
	);
	assert_eq!(
		clock.observe(sample(anchor, 5, utc(105, 500))),
		Err(Failure::Expired)
	);
}

#[test]
fn empty_and_reversed_qualification_refuse_before_observing_or_installing() {
	let anchor = Instant::now();
	let mut clock = issued(anchor);
	let time = utc(104, 500);
	for expires_at in [time, utc(104, 499)] {
		assert_eq!(
			clock.tighten(
				sample(anchor, 10, utc(100, 499)),
				QualificationWindow {
					starts_at: time,
					expires_at,
				},
			),
			Err(Failure::Phase)
		);
	}
	assert!(clock.qualification.is_none());
	assert_eq!(clock.last.monotonic, anchor);
	assert_eq!(clock.last.utc, utc(100, 500));
	assert_eq!(
		clock.tighten(
			sample(anchor, 3, time),
			QualificationWindow {
				starts_at: time,
				expires_at: utc(104, 501),
			},
		),
		Ok(time)
	);
}
