use std::io;

use exacopy_endpoint::ReadView as _;
use exacopy_platform::linux::RunningExecutable;

pub(super) fn measure(
	image: &RunningExecutable,
	mut hasher: blake3::Hasher,
) -> io::Result<[u8; 32]> {
	let mut buffer = vec![0; 64 * 1024];
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
