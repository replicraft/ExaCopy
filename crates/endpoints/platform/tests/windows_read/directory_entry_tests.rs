use super::{
	ATTRIBUTES_OFFSET, DirectoryEntry, EntryRefusal, ID_OFFSET, NAME_BYTES_OFFSET, NAME_OFFSET,
	NEXT_OFFSET, REPARSE_TAG_OFFSET, find_in_batch, ntfs_reference,
};
use exacopy_platform::windows::WindowsComponent;

fn record(name: &[u16], id: [u8; 16]) -> Vec<u8> {
	let mut bytes = vec![0; NAME_OFFSET + size_of_val(name)];
	bytes[NAME_BYTES_OFFSET..NAME_BYTES_OFFSET + 4]
		.copy_from_slice(&(size_of_val(name) as u32).to_le_bytes());
	bytes[ID_OFFSET..NAME_OFFSET].copy_from_slice(&id);
	for (slot, unit) in bytes[NAME_OFFSET..]
		.as_chunks_mut::<2>()
		.0
		.iter_mut()
		.zip(name)
	{
		slot.copy_from_slice(&unit.to_le_bytes());
	}
	bytes
}

#[test]
fn matches_exact_units_without_using_case_or_lossy_text() {
	let mut id = [0; 16];
	id[0] = 17;
	let input = [u16::from(b'Z'), 0xd800];
	let name = WindowsComponent::new(&input).unwrap();
	let mut bytes = record(&[u16::from(b'z'), 0xd800], id);
	let span = bytes.len().next_multiple_of(8);
	bytes.resize(span, 0);
	bytes[NEXT_OFFSET..NEXT_OFFSET + 4].copy_from_slice(&(span as u32).to_le_bytes());
	let mut matched = record(&input, id);
	let attributes = 0x20_u32;
	let tag = 0xa0000003_u32;
	matched[ATTRIBUTES_OFFSET..ATTRIBUTES_OFFSET + 4].copy_from_slice(&attributes.to_le_bytes());
	matched[REPARSE_TAG_OFFSET..REPARSE_TAG_OFFSET + 4].copy_from_slice(&tag.to_le_bytes());
	bytes.extend(matched);
	let mut found = None;
	find_in_batch(&bytes, name, &mut found).unwrap();
	assert_eq!(
		found,
		Some(DirectoryEntry {
			attributes,
			reparse_tag: tag,
			id
		})
	);
}

#[test]
fn refuses_multiple_exact_observations_across_batches() {
	let units = [u16::from(b'a')];
	let name = WindowsComponent::new(&units).unwrap();
	let mut first = [0; 16];
	first[0] = 1;
	let mut found = None;
	find_in_batch(&record(&units, first), name, &mut found).unwrap();
	assert_eq!(
		find_in_batch(&record(&units, first), name, &mut found),
		Err(EntryRefusal::Ambiguous)
	);
}

#[test]
fn refuses_truncated_odd_or_malformed_entry_boundaries() {
	let units = [u16::from(b'a')];
	let name = WindowsComponent::new(&units).unwrap();
	let valid = record(&units, [0; 16]);
	assert_eq!(
		find_in_batch(&valid[..valid.len() - 1], name, &mut None),
		Err(EntryRefusal::Malformed)
	);
	let mut too_short = valid.clone();
	too_short[NEXT_OFFSET..NEXT_OFFSET + 4].copy_from_slice(&88_u32.to_le_bytes());
	let mut odd = valid.clone();
	odd[NAME_BYTES_OFFSET..NAME_BYTES_OFFSET + 4].copy_from_slice(&1_u32.to_le_bytes());
	let mut past_end = valid;
	past_end[NEXT_OFFSET..NEXT_OFFSET + 4].copy_from_slice(&1024_u32.to_le_bytes());
	for bytes in [too_short, odd, past_end] {
		assert_eq!(
			find_in_batch(&bytes, name, &mut None),
			Err(EntryRefusal::Malformed)
		);
	}
}

#[test]
fn refuses_zero_ntfs_identifiers_and_the_object_id_namespace() {
	let mut id = [0; 16];
	assert_eq!(ntfs_reference(id), Err(EntryRefusal::UnknownNtfsId));
	id[7] = 1;
	assert_eq!(ntfs_reference(id), Ok(id));
	id[8] = 1;
	assert_eq!(ntfs_reference(id), Err(EntryRefusal::UnknownNtfsId));
}
