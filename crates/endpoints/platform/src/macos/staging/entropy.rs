use std::io;

use super::identity::RANDOM_STAGE_ID_BYTES;

pub(super) fn fill_stage_entropy(bytes: &mut [u8; RANDOM_STAGE_ID_BYTES]) -> io::Result<()> {
	getrandom::fill(bytes).map_err(Into::into)
}
