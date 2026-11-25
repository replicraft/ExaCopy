use exacopy_endpoint::UnixComponent;

use super::ProtectedSnapshotError;

const MAX_PATH_BYTES: usize = 4095;
const MAX_COMPONENTS: usize = 64;

pub(crate) fn checked_components(
	path: &[u8],
) -> Result<Vec<UnixComponent<'_>>, ProtectedSnapshotError> {
	if path.len() > MAX_PATH_BYTES {
		return Err(ProtectedSnapshotError::InvalidPath);
	}
	let relative = path
		.strip_prefix(b"/")
		.ok_or(ProtectedSnapshotError::InvalidPath)?;
	let mut components = Vec::new();
	for name in relative.split(|&byte| byte == b'/') {
		if components.len() == MAX_COMPONENTS {
			return Err(ProtectedSnapshotError::InvalidPath);
		}
		let name = UnixComponent::new(name).map_err(|_| ProtectedSnapshotError::InvalidPath)?;
		components.push(name);
	}
	if components.len() < 2 {
		return Err(ProtectedSnapshotError::InvalidPath);
	}
	Ok(components)
}

#[test]
fn validates_raw_absolute_components_without_normalizing() {
	let components = checked_components(b"/parent/\xff").unwrap();
	assert_eq!(components[0].as_bytes(), b"parent");
	assert_eq!(components[1].as_bytes(), b"\xff");
	for invalid in [
		&b""[..],
		b"/",
		b"/leaf",
		b"relative/file",
		b"//parent/file",
		b"/parent//file",
		b"/parent/file/",
		b"/parent/./file",
		b"/parent/../file",
		b"/parent/\0",
	] {
		assert_eq!(
			checked_components(invalid),
			Err(ProtectedSnapshotError::InvalidPath)
		);
	}
}

#[test]
fn bounds_component_count_component_size_and_path_size() {
	let max_components = b"/a".repeat(MAX_COMPONENTS);
	assert_eq!(
		checked_components(&max_components).unwrap().len(),
		MAX_COMPONENTS
	);
	let excess_components = b"/a".repeat(MAX_COMPONENTS + 1);
	assert_eq!(
		checked_components(&excess_components),
		Err(ProtectedSnapshotError::InvalidPath)
	);

	let excess_component = [b"/parent/".as_slice(), &vec![b'a'; 256]].concat();
	assert_eq!(
		checked_components(&excess_component),
		Err(ProtectedSnapshotError::InvalidPath)
	);
	let excess_path = [b"/".as_slice(), &vec![b'a'; 255]].concat().repeat(16);
	assert_eq!(
		checked_components(&excess_path),
		Err(ProtectedSnapshotError::InvalidPath)
	);
}
