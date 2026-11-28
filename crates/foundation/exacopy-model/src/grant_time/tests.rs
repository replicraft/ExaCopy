use super::{GrantTimeRefusal, MonotonicObservation, UtcWindow, check_grant_time};

fn wide((seconds, nanos): (i64, u32)) -> i128 {
	i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
}

#[test]
fn grant_time_matches_wide_nanosecond_interval() {
	use GrantTimeRefusal::{Expired, Regressed};
	use MonotonicObservation as Mono;

	let timestamps = [
		(i64::MIN, 0),
		(i64::MIN, 1),
		(i64::MIN, 999_999_999),
		(i64::MIN + 1, 0),
		(-2, 999_999_999),
		(-1, 0),
		(-1, 999_999_999),
		(0, 0),
		(0, 1),
		(0, 2),
		(i64::MAX - 1, 999_999_999),
		(i64::MAX, 0),
		(i64::MAX, 999_999_998),
		(i64::MAX, 999_999_999),
	];
	let windows = [
		UtcWindow {
			starts_at: (i64::MIN, 0),
			expires_at: (i64::MAX, 999_999_999),
		},
		UtcWindow {
			starts_at: (i64::MIN, 1),
			expires_at: (i64::MIN + 1, 0),
		},
		UtcWindow {
			starts_at: (-1, 999_999_999),
			expires_at: (0, 1),
		},
		UtcWindow {
			starts_at: (0, 1),
			expires_at: (i64::MAX, 999_999_998),
		},
		UtcWindow {
			starts_at: (0, 1),
			expires_at: (0, 1),
		},
		UtcWindow {
			starts_at: (0, 2),
			expires_at: (-1, 0),
		},
	];
	for original in windows {
		for qualification in [None].into_iter().chain(windows.map(Some)) {
			let original_start = wide(original.starts_at);
			let original_end = wide(original.expires_at);
			let interval = qualification.map_or(original_start..original_end, |window| {
				let start = original_start.max(wide(window.starts_at));
				let end = original_end.min(wide(window.expires_at));
				start..end
			});
			for previous in timestamps {
				for current in timestamps {
					for monotonic in [Mono::Regressed, Mono::Current, Mono::Expired] {
						let expected = match (monotonic, wide(current).cmp(&wide(previous))) {
							(Mono::Regressed, _) | (_, core::cmp::Ordering::Less) => Err(Regressed),
							(Mono::Current, _) if interval.contains(&wide(current)) => Ok(()),
							_ => Err(Expired),
						};
						assert_eq!(
							check_grant_time(monotonic, current, previous, original, qualification),
							expected,
							"{monotonic:?} {previous:?} {current:?} {original:?} {qualification:?}",
						);
					}
				}
			}
		}
	}
}
