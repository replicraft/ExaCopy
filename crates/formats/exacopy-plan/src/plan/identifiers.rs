use std::time::Duration;

use uuid::{Builder, Uuid, Variant};

use super::UnixTimestamp;

const MAX_UUIDV7_MILLIS: u64 = (1 << 48) - 1;

/// An observed creation time that fits both a Plan timestamp and its UUIDv7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanCreationTime {
	timestamp: UnixTimestamp,
	identifier_millis: u64,
}

impl PlanCreationTime {
	/// Admits elapsed time since the Unix epoch within the 48-bit UUIDv7 range.
	#[must_use]
	pub fn new(elapsed: Duration) -> Option<Self> {
		let identifier_millis = u64::try_from(elapsed.as_millis()).ok()?;
		if identifier_millis > MAX_UUIDV7_MILLIS {
			return None;
		}
		let seconds = i64::try_from(elapsed.as_secs()).ok()?;
		let timestamp = UnixTimestamp::new(seconds, elapsed.subsec_nanos()).ok()?;
		Some(Self {
			timestamp,
			identifier_millis,
		})
	}

	/// Returns the full observed creation time recorded in the Plan body.
	#[must_use]
	pub const fn timestamp(self) -> UnixTimestamp {
		self.timestamp
	}

	/// Encodes the observed millisecond and ten independently supplied entropy bytes.
	#[must_use]
	pub const fn plan_id(self, entropy: &[u8; 10]) -> Uuid {
		Builder::from_unix_timestamp_millis(self.identifier_millis, entropy).into_uuid()
	}
}

/// Encodes supplied entropy as a UUIDv4 for a new Plan entry, view, or measurement.
#[must_use]
pub const fn plan_reference(entropy: [u8; 16]) -> Uuid {
	Builder::from_random_bytes(entropy).into_uuid()
}

/// Checks the required Plan identifier version and variant.
#[must_use]
pub fn is_plan_id(id: Uuid) -> bool {
	id.get_version_num() == 7 && id.get_variant() == Variant::RFC4122
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn plan_identifiers_preserve_their_exact_versioned_bytes() {
		let elapsed = Duration::from_millis(0x0123_4567_89ab) + Duration::from_nanos(456);
		let creation = PlanCreationTime::new(elapsed).unwrap();
		let id = creation.plan_id(&[0xff; 10]);
		assert_eq!(
			id.into_bytes(),
			[
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7f, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff,
			]
		);
		assert_eq!(creation.timestamp().nanoseconds(), elapsed.subsec_nanos());
		assert_eq!(
			creation.timestamp().seconds(),
			i64::try_from(elapsed.as_secs()).unwrap()
		);

		let reference = plan_reference([0xff; 16]);
		assert_eq!(
			reference.into_bytes(),
			[
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x4f, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff,
			]
		);
		assert!(is_plan_id(id));
		assert!(!is_plan_id(reference));
		let mut wrong_variant = id.into_bytes();
		wrong_variant[8] = 0;
		assert!(!is_plan_id(Uuid::from_bytes(wrong_variant)));
	}

	#[test]
	fn time_at_the_last_millisecond_keeps_its_fraction_and_never_wraps() {
		let last_millis = Duration::from_millis(MAX_UUIDV7_MILLIS);
		let latest = last_millis + Duration::from_nanos(999_999);
		let creation = PlanCreationTime::new(latest).unwrap();
		assert_eq!(&creation.plan_id(&[0; 10]).as_bytes()[..6], &[0xff; 6]);
		assert_eq!(creation.timestamp().nanoseconds(), latest.subsec_nanos());
		assert!(PlanCreationTime::new(latest + Duration::from_nanos(1)).is_none());
		assert!(PlanCreationTime::new(Duration::MAX).is_none());
	}
}
