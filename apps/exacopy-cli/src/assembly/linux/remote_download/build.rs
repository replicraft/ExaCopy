use std::io;

use exacopy_endpoint::ReadView;
use exacopy_platform::linux::RunningExecutable;

const DOMAIN: &str = "ExaCopy remote running executable v1";

/// Measures the exact executable of this Linux process for qualification selection.
/// The digest is BLAKE3 derive-key with context `ExaCopy remote running executable v1`
/// over all bytes of the bounded native held executable.
/// # Errors
/// Refuses unsupported procfs, unbounded images or changed observations.
pub fn measure_running_executable() -> io::Result<[u8; 32]> {
	let image = RunningExecutable::open()?;
	let mut buffer = vec![0; 64 * 1024];
	let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
	let mut offset = 0;
	let extent = image.length();
	while offset < extent {
		let remaining = usize::try_from(extent - offset).map_err(io::Error::other)?;
		let count = buffer.len().min(remaining);
		image.read_exact_at(offset, &mut buffer[..count])?;
		hasher.update(&buffer[..count]);
		offset += u64::try_from(count).map_err(io::Error::other)?;
	}
	image.recheck_observation()?;
	Ok(*hasher.finalize().as_bytes())
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
