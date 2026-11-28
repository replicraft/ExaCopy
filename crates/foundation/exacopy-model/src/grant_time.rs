//! Pure time decision for a live local public-apply grant.

#[cfg(test)]
mod tests;

/// Classification of one monotonic sample against the last accepted sample and original deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonotonicObservation {
	/// The sample precedes the last accepted monotonic sample.
	Regressed,
	/// The sample is at or after the last accepted sample and before the deadline.
	Current,
	/// The sample is at or after the deadline without regression.
	Expired,
}

/// A UTC window specified as signed Unix seconds and normalized subsecond nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcWindow {
	/// Inclusive lower bound.
	pub starts_at: (i64, u32),
	/// Exclusive upper bound.
	pub expires_at: (i64, u32),
}

/// Why the combined clock observation could not continue the grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantTimeRefusal {
	/// Either clock regressed.
	Regressed,
	/// The original deadline or an applicable UTC window was violated.
	Expired,
}

/// Checks a sampled clock pair against the previous accepted observation and the selected bounds.
///
/// All UTC pairs use the full signed Unix seconds domain and nanoseconds below one billion.
/// The caller supplies normalized UTC components and classifies the monotonic sample.
///
/// # Errors
/// Returns [`GrantTimeRefusal::Regressed`] before considering any deadline or window if either
/// clock moved backward. Otherwise returns [`GrantTimeRefusal::Expired`] if the monotonic
/// deadline or either applicable UTC window is violated.
pub fn check_grant_time(
	monotonic: MonotonicObservation,
	current_utc: (i64, u32),
	previous_accepted_utc: (i64, u32),
	original: UtcWindow,
	qualification: Option<UtcWindow>,
) -> Result<(), GrantTimeRefusal> {
	if matches!(monotonic, MonotonicObservation::Regressed)
		|| before(current_utc, previous_accepted_utc)
	{
		return Err(GrantTimeRefusal::Regressed);
	}
	if matches!(monotonic, MonotonicObservation::Expired) || !contains(original, current_utc) {
		return Err(GrantTimeRefusal::Expired);
	}
	if let Some(window) = qualification
		&& !contains(window, current_utc)
	{
		return Err(GrantTimeRefusal::Expired);
	}
	Ok(())
}

fn contains(window: UtcWindow, utc: (i64, u32)) -> bool {
	!before(utc, window.starts_at) && before(utc, window.expires_at)
}

fn before(left: (i64, u32), right: (i64, u32)) -> bool {
	left.0 < right.0 || (left.0 == right.0 && left.1 < right.1)
}
