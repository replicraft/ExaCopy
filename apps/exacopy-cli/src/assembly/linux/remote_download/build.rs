use std::io;

use exacopy_platform::linux::RunningExecutable;

const DOMAIN: &str = "ExaCopy remote running executable v1";

/// Measures the exact executable of this Linux process for qualification selection.
/// The digest is BLAKE3 derive-key with context `ExaCopy remote running executable v1`
/// over all bytes of the bounded native held executable.
/// # Errors
/// Refuses unsupported procfs, unbounded images or changed observations.
pub fn measure_running_executable() -> io::Result<[u8; 32]> {
	let image = RunningExecutable::open()?;
	super::super::running_build::measure(&image, blake3::Hasher::new_derive_key(DOMAIN))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn proc_measurement_matches_the_independent_running_image_and_domain() {
		let measured = measure_running_executable().expect("checked proc executable");
		let raw = std::fs::read("/proc/self/exe").expect("independent proc fixture read");
		assert_eq!(measured, blake3::derive_key(DOMAIN, &raw));
	}
}
