// Checked representation of the TOKEN_PRIVILEGES count and variable native array.
pub(super) const HEADER_BYTES: usize = 4;
pub(super) const ENTRY_BYTES: usize = 12;

pub(super) fn contains_enabled(
	reported: &[u8],
	disallowed: &[(u32, i32)],
	enabled_flag: u32,
) -> Option<bool> {
	let (header, body) = reported.split_at_checked(HEADER_BYTES)?;
	let count = usize::try_from(u32::from_le_bytes(header.try_into().ok()?)).ok()?;
	let (entries, trailing) = body.as_chunks::<ENTRY_BYTES>();
	if entries.len() != count || !trailing.is_empty() {
		return None;
	}
	Some(entries.iter().any(|&entry| {
		let [low, high, attributes] = entry.as_chunks::<4>().0 else {
			unreachable!()
		};
		let luid = (u32::from_le_bytes(*low), i32::from_le_bytes(*high));
		u32::from_le_bytes(*attributes) & enabled_flag != 0 && disallowed.contains(&luid)
	}))
}

#[cfg(test)]
mod tests {
	use super::contains_enabled;

	const ENABLED: u32 = 2;
	const OTHER: (u32, i32) = (23, 0);
	const DISALLOWED: [(u32, i32); 2] = [(17, 0), (18, 0)];

	fn privilege_report(entries: &[((u32, i32), u32)]) -> Vec<u8> {
		let mut report = u32::try_from(entries.len()).unwrap().to_le_bytes().to_vec();
		for &((low, high), attributes) in entries {
			report.extend(low.to_le_bytes());
			report.extend(high.to_le_bytes());
			report.extend(attributes.to_le_bytes());
		}
		report
	}

	#[test]
	fn checks_enabled_state_and_the_full_luid() {
		let report = privilege_report(&[(DISALLOWED[0], 1), ((17, -1), 2), (OTHER, 2)]);
		assert_eq!(contains_enabled(&report, &DISALLOWED, ENABLED), Some(false));

		for disallowed in DISALLOWED {
			let report = privilege_report(&[(OTHER, 2), (disallowed, 3)]);
			assert_eq!(contains_enabled(&report, &DISALLOWED, ENABLED), Some(true));
		}
		assert_eq!(
			contains_enabled(&0_u32.to_le_bytes(), &DISALLOWED, ENABLED),
			Some(false)
		);
	}

	#[test]
	fn invalid_extent_refuses_admission() {
		let mut report = privilege_report(&[(OTHER, ENABLED)]);
		assert_eq!(contains_enabled(&report[..3], &DISALLOWED, ENABLED), None);
		assert_eq!(contains_enabled(&report[..15], &DISALLOWED, ENABLED), None);
		report.push(0);
		assert_eq!(contains_enabled(&report, &DISALLOWED, ENABLED), None);
		report[..4].copy_from_slice(&u32::MAX.to_le_bytes());
		assert_eq!(contains_enabled(&report, &DISALLOWED, ENABLED), None);
	}
}
