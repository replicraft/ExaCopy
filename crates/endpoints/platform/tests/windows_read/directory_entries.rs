use exacopy_platform::windows::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};

// FILE_ID_EXTD_DIR_INFORMATION uses this layout for the native Windows little-endian buffer.
// The Windows build checks these offsets against the generated SDK binding.
pub(crate) const NEXT_OFFSET: usize = 0;
pub(crate) const ATTRIBUTES_OFFSET: usize = 56;
pub(crate) const NAME_BYTES_OFFSET: usize = 60;
pub(crate) const REPARSE_TAG_OFFSET: usize = 68;
pub(crate) const ID_OFFSET: usize = 72;
pub(crate) const NAME_OFFSET: usize = 88;
pub(crate) const ENTRY_ALIGNMENT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntry {
	pub(crate) attributes: u32,
	pub(crate) reparse_tag: u32,
	pub(crate) id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryRefusal {
	Malformed,
	Ambiguous,
	UnknownNtfsId,
}

pub(crate) fn ntfs_reference(id: [u8; 16]) -> Result<[u8; 16], EntryRefusal> {
	// NTFS interprets a 128-bit value with a nonzero high half as an object ID.
	if id == [0; 16] || id[8..] != [0; 8] {
		return Err(EntryRefusal::UnknownNtfsId);
	}
	Ok(id)
}

pub(crate) fn find_in_batch(
	mut bytes: &[u8],
	name: WindowsComponent<'_>,
	found: &mut Option<DirectoryEntry>,
) -> Result<(), EntryRefusal> {
	loop {
		let next = read_u32(bytes, NEXT_OFFSET)? as usize;
		let name_length = read_u32(bytes, NAME_BYTES_OFFSET)? as usize;
		if name_length == 0
			|| !name_length.is_multiple_of(2)
			|| name_length > MAX_WINDOWS_COMPONENT_UNITS * 2
		{
			return Err(EntryRefusal::Malformed);
		}
		let name_end = NAME_OFFSET + name_length;
		if next != 0 && (next < name_end || !next.is_multiple_of(ENTRY_ALIGNMENT)) {
			return Err(EntryRefusal::Malformed);
		}
		let units = bytes
			.get(NAME_OFFSET..name_end)
			.ok_or(EntryRefusal::Malformed)?
			.as_chunks::<2>()
			.0
			.iter()
			.copied()
			.map(u16::from_le_bytes);
		if units.eq(name.as_units().iter().copied()) {
			if found.is_some() {
				return Err(EntryRefusal::Ambiguous);
			}
			*found = Some(DirectoryEntry {
				attributes: read_u32(bytes, ATTRIBUTES_OFFSET)?,
				reparse_tag: read_u32(bytes, REPARSE_TAG_OFFSET)?,
				id: bytes[ID_OFFSET..NAME_OFFSET]
					.try_into()
					.map_err(|_| EntryRefusal::Malformed)?,
			});
		}
		if next == 0 {
			return Ok(());
		}
		bytes = bytes.get(next..).ok_or(EntryRefusal::Malformed)?;
	}
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EntryRefusal> {
	let field = bytes
		.get(offset..offset + size_of::<u32>())
		.and_then(|field| field.try_into().ok())
		.ok_or(EntryRefusal::Malformed)?;
	Ok(u32::from_le_bytes(field))
}

#[path = "directory_entry_tests.rs"]
mod tests;
