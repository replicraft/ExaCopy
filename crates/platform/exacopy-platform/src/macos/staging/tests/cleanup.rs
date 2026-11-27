use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, symlink};

use super::{Fixture, PAYLOAD, make_file};

impl Fixture {
	fn remove(&self) -> io::Result<()> {
		// The sticky parent and private fixture root restrict mutation to the test owner.
		let held = self.directory.metadata()?;
		let named = fs::symlink_metadata(&self.path)?;
		if !named.is_dir() || (named.dev(), named.ino()) != (held.dev(), held.ino()) {
			return Err(io::Error::other("synthetic APFS fixture root changed"));
		}
		// Recursive removal unlinks symlinks within this owned tree without visiting their targets.
		fs::remove_dir_all(&self.path)
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		if std::thread::panicking() {
			// Preserve the namespace and staged bytes for diagnosis during unwinding.
			let _ = writeln!(
				io::stderr(),
				"retained synthetic APFS fixture {:?}",
				self.path
			);
			return;
		}
		self.remove().unwrap_or_else(|error| {
			panic!(
				"cannot clean synthetic APFS fixture {:?}: {error}",
				self.path
			);
		});
	}
}

#[test]
fn fixture_drop_removes_owned_tree_and_preserves_external_symlink_target() {
	let outside = Fixture::new();
	let marker = outside.path("outside-marker");
	make_file(&marker, PAYLOAD);
	let fixture = Fixture::new();
	let fixture_path = fixture.path.clone();
	make_file(&fixture.stage_path(), PAYLOAD);
	symlink(outside.path(""), fixture.path("outside-link")).unwrap();

	drop(fixture);

	assert_eq!(
		fs::symlink_metadata(&fixture_path).unwrap_err().kind(),
		io::ErrorKind::NotFound,
		"fixture root must disappear on drop"
	);
	assert_eq!(fs::read(marker).unwrap(), PAYLOAD);
}

#[test]
fn fixture_cleanup_refuses_replaced_root() {
	let fixture = Fixture::new();
	let outside = Fixture::new();
	let original = outside.path("original-fixture");
	let fixture_path = fixture.path.clone();
	let marker = outside.path("outside-marker");
	make_file(&marker, PAYLOAD);
	fs::rename(&fixture_path, &original).unwrap();
	assert_eq!(
		fixture.remove().unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
	fs::create_dir(&fixture_path).unwrap();
	let replacement_marker = fixture_path.join("replacement-marker");
	make_file(&replacement_marker, PAYLOAD);

	assert!(fixture.remove().is_err());
	assert_eq!(fs::read(&replacement_marker).unwrap(), PAYLOAD);
	fs::remove_file(replacement_marker).unwrap();
	fs::remove_dir(&fixture_path).unwrap();
	symlink(outside.path(""), &fixture_path).unwrap();

	assert!(fixture.remove().is_err());
	assert!(fs::symlink_metadata(&fixture_path).unwrap().is_symlink());
	assert_eq!(fs::read(marker).unwrap(), PAYLOAD);
	fs::remove_file(&fixture_path).unwrap();
	fs::rename(original, fixture_path).unwrap();
}
