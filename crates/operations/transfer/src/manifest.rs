//! Read-only measurement against a caller-selected single-file baseline.

use std::error::Error as StdError;
use std::fmt;

use exacopy_codec::SingleFileManifest;
use exacopy_content::{MeasureError, measure_at, validate_stream_input};
use exacopy_endpoint::ReadView;

#[cfg(test)]
mod tests;

/// A complete measurement of the unnamed stream from a rechecked live view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measurement {
	/// Measured stream length in bytes.
	pub length: u64,
	/// Standard unkeyed BLAKE3-256 over the stream's logical bytes.
	pub digest: [u8; 32],
}

/// Result of comparing a rechecked live stream to the selected baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyDecision {
	/// The measured length and digest agree with the baseline.
	Match(Measurement),
	/// The measured logical length differs from the baseline.
	LengthMismatch(Measurement),
	/// The measured digest differs from the baseline at equal lengths.
	DigestMismatch(Measurement),
}

/// A failure that prevented a completed live stream measurement.
#[derive(Debug)]
pub enum Error<E> {
	/// The reader could not confirm its admitted observation before measurement.
	InitialObservation(E),
	/// Input bounds or an exact positioned read prevented complete measurement.
	Measure(MeasureError<E>),
	/// The reader could not confirm the observation after the last measured byte.
	FinalObservation(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InitialObservation(error) => {
				write!(formatter, "initial file observation failed ({error})")
			}
			Self::Measure(error) => error.fmt(formatter),
			Self::FinalObservation(error) => {
				write!(formatter, "final file observation failed ({error})")
			}
		}
	}
}

impl<E: StdError + 'static> StdError for Error<E> {
	fn source(&self) -> Option<&(dyn StdError + 'static)> {
		Some(match self {
			Self::InitialObservation(error) | Self::FinalObservation(error) => error,
			Self::Measure(error) => error,
		})
	}
}

/// Measures a complete logical stream through an independently admitted read-only view.
///
/// The caller selects and authorizes the held view. Observation checks bracket
/// the reads and include logical EOF through the view contract. The result
/// describes live content and excludes historical metadata comparison.
///
/// # Errors
/// Refuses invalid length or scratch bounds, incomplete reads, or failed
/// observation checks.
pub fn measure<R: ReadView>(view: &R, scratch: &mut [u8]) -> Result<Measurement, Error<R::Error>> {
	let length = view.length();
	validate_stream_input(length, scratch.len())
		.map_err(MeasureError::InvalidInput)
		.map_err(Error::Measure)?;
	view.recheck_observation()
		.map_err(Error::InitialObservation)?;
	let digest = measure_at(length, scratch, |offset, buffer| {
		view.read_exact_at(offset, buffer)
	})
	.map_err(Error::Measure)?;
	view.recheck_observation()
		.map_err(Error::FinalObservation)?;
	Ok(Measurement {
		length,
		digest: *digest.as_bytes(),
	})
}

/// Compares a rechecked live stream to a previously selected single-file baseline.
///
/// The caller checks the manifest's component against the selected view and
/// supplies its root authority independently. Only stream length and digest
/// are compared. The baseline's metadata omission remains in force.
///
/// # Errors
/// Returns measurement failures without comparing incomplete or stale evidence.
pub fn verify<R: ReadView>(
	view: &R,
	expected: &SingleFileManifest,
	scratch: &mut [u8],
) -> Result<VerifyDecision, Error<R::Error>> {
	let observed = measure(view, scratch)?;
	if observed.length != expected.length() {
		Ok(VerifyDecision::LengthMismatch(observed))
	} else if observed.digest != expected.content_digest() {
		Ok(VerifyDecision::DigestMismatch(observed))
	} else {
		Ok(VerifyDecision::Match(observed))
	}
}
