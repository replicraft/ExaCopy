use chrono::{DateTime, Datelike as _, SecondsFormat, Utc};

use super::{super::UnixTimestamp, PlanJsonError};

pub(super) fn parse(input: &str) -> Result<UnixTimestamp, PlanJsonError> {
	if !is_rfc3339_spelling(input.as_bytes()) {
		return Err(PlanJsonError::Timestamp);
	}
	let parsed = DateTime::parse_from_rfc3339(input).map_err(|_| PlanJsonError::Timestamp)?;
	let timestamp = UnixTimestamp::new(parsed.timestamp(), parsed.timestamp_subsec_nanos())
		.map_err(|_| PlanJsonError::Timestamp)?;
	check(timestamp)?;
	Ok(timestamp)
}

pub(super) fn check(timestamp: UnixTimestamp) -> Result<(), PlanJsonError> {
	utc(timestamp).map(|_| ())
}

pub(super) fn format(timestamp: UnixTimestamp) -> Result<String, PlanJsonError> {
	Ok(utc(timestamp)?.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn utc(timestamp: UnixTimestamp) -> Result<DateTime<Utc>, PlanJsonError> {
	let time = DateTime::from_timestamp(timestamp.seconds(), timestamp.nanoseconds())
		.ok_or(PlanJsonError::Timestamp)?;
	if !(0..=9_999).contains(&time.year()) {
		return Err(PlanJsonError::Timestamp);
	}
	Ok(time)
}

// Admit only the bounded RFC 3339 grammar before delegating calendar
// arithmetic to Chrono. In particular Chrono can truncate excess fractions.
fn is_rfc3339_spelling(bytes: &[u8]) -> bool {
	if !(20..=35).contains(&bytes.len()) {
		return false;
	}
	let [
		year_a,
		year_b,
		year_c,
		year_d,
		b'-',
		month_a,
		month_b,
		b'-',
		day_a,
		day_b,
		b'T' | b't',
		hour_a,
		hour_b,
		b':',
		minute_a,
		minute_b,
		b':',
		second_a,
		second_b,
		zone @ ..,
	] = bytes
	else {
		return false;
	};
	if ![
		year_a, year_b, year_c, year_d, month_a, month_b, day_a, day_b, hour_a, hour_b, minute_a,
		minute_b, second_a, second_b,
	]
	.into_iter()
	.all(u8::is_ascii_digit)
	{
		return false;
	}
	let zone = if let Some(fraction) = zone.strip_prefix(b".") {
		let count = fraction
			.iter()
			.take_while(|byte| byte.is_ascii_digit())
			.count();
		if !(1..=9).contains(&count) {
			return false;
		}
		&fraction[count..]
	} else {
		zone
	};
	match zone {
		[b'Z' | b'z'] => true,
		[b'+' | b'-', hour_a, hour_b, b':', minute_a, minute_b] => {
			[hour_a, hour_b, minute_a, minute_b]
				.into_iter()
				.all(u8::is_ascii_digit)
		}
		_ => false,
	}
}
