use crate::JournalJobId;

const JOB_PREFIX: &[u8; 9] = b".exacopy-";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The counted UTF-16 owner filename in layout 1.
pub const OWNER_FILE_NAME: [u16; 10] = ascii_units(b"owner.cbor");
/// The counted UTF-16 journal directory name in layout 1.
pub const JOURNAL_DIRECTORY_NAME: [u16; 7] = ascii_units(b"journal");
/// The counted UTF-16 first-segment filename in layout 1.
pub const FIRST_SEGMENT_NAME: [u16; 27] = ascii_units(b"00000000000000000001.exajnl");

/// Derives the counted job component from the independently selected job ID.
#[must_use]
pub fn job_directory_name(job: JournalJobId) -> [u16; 45] {
	let mut name = [0; 45];
	name[..JOB_PREFIX.len()].copy_from_slice(&ascii_units(JOB_PREFIX));
	let mut offset = JOB_PREFIX.len();
	for (index, &byte) in job.as_bytes().iter().enumerate() {
		if matches!(index, 4 | 6 | 8 | 10) {
			name[offset] = u16::from(b'-');
			offset += 1;
		}
		name[offset] = u16::from(HEX[usize::from(byte >> 4)]);
		name[offset + 1] = u16::from(HEX[usize::from(byte & 0x0f)]);
		offset += 2;
	}
	name
}

const fn ascii_units<const N: usize>(ascii: &[u8; N]) -> [u16; N] {
	let mut units = [0; N];
	let mut index = 0;
	while index < N {
		units[index] = ascii[index] as u16;
		index += 1;
	}
	units
}
