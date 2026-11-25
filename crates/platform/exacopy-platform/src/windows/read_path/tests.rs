use super::*;

#[test]
fn accepts_drive_paths_without_normalizing_the_component_units() {
	let mut units: Vec<_> = r"q:\Parent\".encode_utf16().collect();
	units.extend([0xd800, 0x61, 0xdc00]);
	let path = DrivePath::parse(&units).expect("literal drive path with non-scalar UTF-16");
	assert_eq!(path.letter, b'q');
	assert_eq!(path.parents[0].as_units(), &[80, 97, 114, 101, 110, 116]);
	assert_eq!(path.leaf.as_units(), &[0xd800, 0x61, 0xdc00]);
}

#[test]
fn refuses_ambiguous_path_syntax_and_bounds_component_depth() {
	for path in [
		r"C:a",
		r"\a",
		r"C:\",
		r"C:\a\..\b",
		r"C:\.\b",
		r"C:\a\\b",
		r"C:\a\b\",
		"C:/a/b",
		r"C:\file:stream",
		r"C:\directory\NUL.txt",
		r"\\?\C:\file",
		r"\\.\C:\file",
		r"\\host\share\file",
	] {
		assert!(
			DrivePath::parse(&path.encode_utf16().collect::<Vec<_>>()).is_err(),
			"{path}"
		);
	}
	let bounded = format!(r"C:\{}a", "a\\".repeat(MAX_COMPONENTS - 1));
	assert!(DrivePath::parse(&bounded.encode_utf16().collect::<Vec<_>>()).is_ok());
	let over = format!(r"C:\{}a", "a\\".repeat(MAX_COMPONENTS));
	assert!(matches!(
		DrivePath::parse(&over.encode_utf16().collect::<Vec<_>>()),
		Err(PathError::PathLimit)
	));
	assert!(matches!(
		DrivePath::parse(&vec![0; MAX_PATH_UNITS + 1]),
		Err(PathError::PathLimit)
	));
}
