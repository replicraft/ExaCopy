use jiff::{SignedDuration, civil::DateTime, fmt::temporal::DateTimeParser};

use super::{super::UnixTimestamp, PlanJsonError};

const EPOCH: DateTime = DateTime::constant(1970, 1, 1, 0, 0, 0, 0);
const MIN_SECONDS: i64 = -62_167_219_200;
const MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

pub(super) fn parse(input: &str) -> Result<UnixTimestamp, PlanJsonError> {
	let (civil_spelling, offset_seconds) =
		split_rfc3339(input.as_bytes()).ok_or(PlanJsonError::Timestamp)?;
	let local = DateTimeParser::new()
		.parse_datetime(civil_spelling)
		.map_err(|_| PlanJsonError::Timestamp)?;
	let utc_nanos =
		local.duration_since(EPOCH).as_nanos() - i128::from(offset_seconds) * NANOS_PER_SECOND;
	let seconds = i64::try_from(utc_nanos.div_euclid(NANOS_PER_SECOND))
		.map_err(|_| PlanJsonError::Timestamp)?;
	let nanos = u32::try_from(utc_nanos.rem_euclid(NANOS_PER_SECOND))
		.map_err(|_| PlanJsonError::Timestamp)?;
	let timestamp = UnixTimestamp::new(seconds, nanos).map_err(|_| PlanJsonError::Timestamp)?;
	check(timestamp)?;
	Ok(timestamp)
}

pub(super) fn check(timestamp: UnixTimestamp) -> Result<(), PlanJsonError> {
	if (MIN_SECONDS..=MAX_SECONDS).contains(&timestamp.seconds()) {
		Ok(())
	} else {
		Err(PlanJsonError::Timestamp)
	}
}

pub(super) fn format(timestamp: UnixTimestamp) -> Result<String, PlanJsonError> {
	check(timestamp)?;
	let nanos = timestamp.nanoseconds();
	let civil = EPOCH
		.checked_add(SignedDuration::new(
			timestamp.seconds(),
			i32::try_from(nanos).map_err(|_| PlanJsonError::Timestamp)?,
		))
		.map_err(|_| PlanJsonError::Timestamp)?;
	let fraction = if nanos == 0 {
		String::new()
	} else if nanos.is_multiple_of(1_000_000) {
		format!(".{:03}", nanos / 1_000_000)
	} else if nanos.is_multiple_of(1_000) {
		format!(".{:06}", nanos / 1_000)
	} else {
		format!(".{nanos:09}")
	};
	Ok(format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}Z",
		civil.year(),
		civil.month(),
		civil.day(),
		civil.hour(),
		civil.minute(),
		civil.second(),
	))
}

// Admit the Plan spelling and offset before using Jiff's civil calendar.
fn split_rfc3339(bytes: &[u8]) -> Option<(&[u8], i64)> {
	if !(20..=35).contains(&bytes.len()) {
		return None;
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
		return None;
	};
	if ![
		year_a, year_b, year_c, year_d, month_a, month_b, day_a, day_b, hour_a, hour_b, minute_a,
		minute_b, second_a, second_b,
	]
	.into_iter()
	.all(u8::is_ascii_digit)
		|| *second_a > b'5'
	{
		return None;
	}
	let zone = if let Some(fraction) = zone.strip_prefix(b".") {
		let count = fraction
			.iter()
			.take_while(|byte| byte.is_ascii_digit())
			.count();
		if !(1..=9).contains(&count) {
			return None;
		}
		&fraction[count..]
	} else {
		zone
	};
	let offset = match zone {
		[b'Z' | b'z'] => 0,
		[
			sign @ (b'+' | b'-'),
			hour_a,
			hour_b,
			b':',
			minute_a,
			minute_b,
		] => {
			let hour = two_digits(*hour_a, *hour_b).filter(|hour| *hour < 24)?;
			let minute = two_digits(*minute_a, *minute_b).filter(|minute| *minute < 60)?;
			let seconds = hour * 3_600 + minute * 60;
			if *sign == b'-' { -seconds } else { seconds }
		}
		_ => return None,
	};
	Some((&bytes[..bytes.len() - zone.len()], offset))
}

fn two_digits(first: u8, second: u8) -> Option<i64> {
	if !first.is_ascii_digit() || !second.is_ascii_digit() {
		return None;
	}
	Some(i64::from(first - b'0') * 10 + i64::from(second - b'0'))
}
