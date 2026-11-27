use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

use exacopy_endpoint::linux_staging::StagingSource;
use exacopy_endpoint::{ReadView, UnixComponent};

use super::Scratch;
use crate::linux::{NamedReadView, ReadError, ReadRoot};

#[test]
fn named_staging_source_reads_and_rechecks_the_selected_regular_file() {
	let path = std::env::temp_dir().join(format!(
		"exacopy-named-read-coverage-{}",
		std::process::id()
	));
	DirBuilder::new()
		.mode(0o700)
		.create(&path)
		.expect("create a private fixture directory");
	let scratch = Scratch(path);
	let selected = scratch.0.join("selected");
	let contents = b"held file";
	fs::write(&selected, contents).expect("create the owned source fixture");
	let expected = fs::metadata(&selected).expect("observe native source metadata");
	let root = ReadRoot::from_directory(File::open(&scratch.0).expect("open the fixture root"))
		.expect("bind the fixture root");
	let name = UnixComponent::new(b"selected").expect("validate the fixture name");
	let view = NamedReadView::open(&root, name).expect("open the named source view");

	let identity = StagingSource::identity(&view);
	assert_eq!(
		(identity.device(), identity.inode()),
		(expected.dev(), expected.ino())
	);
	let captured = view.metadata();
	assert_eq!(captured.identity(), identity);
	assert_eq!(captured.len(), expected.len());
	assert_eq!(view.length(), expected.len());

	let mut suffix = [0; 4];
	view.read_exact_at(5, &mut suffix)
		.expect("read the last four fixture bytes");
	assert_eq!(&suffix, b"file");
	assert!(matches!(
		view.read_exact_at(expected.len(), &mut suffix),
		Err(ReadError::RangeOutsideFile)
	));
	assert_eq!(&suffix, b"file");

	let direct = root
		.open_regular(name)
		.expect("open the same regular source");
	assert_eq!(
		view.extended_attributes()
			.expect("inspect named source attributes"),
		direct
			.extended_attributes()
			.expect("inspect direct source attributes")
	);
	view.recheck_metadata()
		.expect("confirm the named source metadata");
	assert_eq!(view.metadata(), captured);
	assert_eq!(
		fs::read(&selected).expect("read the untouched fixture"),
		contents
	);

	let changed = b"modified and longer";
	fs::write(&selected, changed).expect("modify the owned source fixture");
	assert!(matches!(
		view.recheck_metadata(),
		Err(ReadError::SourceChanged)
	));

	let original = scratch.0.join("original");
	fs::rename(&selected, &original).expect("retain the original fixture inode");
	fs::write(&selected, changed).expect("create the replacement fixture inode");
	assert!(matches!(
		view.recheck_metadata(),
		Err(ReadError::IdentityChanged)
	));
	assert_eq!(
		fs::read(original).expect("read the retained original"),
		changed
	);
	assert_eq!(fs::read(selected).expect("read the replacement"), changed);
}
