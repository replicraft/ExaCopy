use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;

use super::{NamedReadView, ReadError, ReadRoot, ReadView, UnixComponent};

#[test]
fn recheck_distinguishes_a_changed_source_from_a_rebound_name() {
	let scratch = Scratch::create();
	let selected = scratch.0.join("selected");
	fs::write(&selected, b"held file").unwrap();
	let root = ReadRoot::from_directory(File::open(&scratch.0).unwrap()).unwrap();
	let name = UnixComponent::new(b"selected").unwrap();
	let view = NamedReadView::open(&root, name).unwrap();
	view.recheck_observation().unwrap();

	fs::write(&selected, b"modified and longer").unwrap();
	assert!(matches!(
		view.recheck_observation(),
		Err(ReadError::SourceChanged)
	));

	let replacement = scratch.0.join("replacement");
	fs::write(&replacement, b"held file").unwrap();
	fs::rename(&replacement, &selected).unwrap();
	assert!(matches!(
		view.recheck_observation(),
		Err(ReadError::IdentityChanged)
	));
	assert_eq!(fs::read(selected).unwrap(), b"held file");
}

struct Scratch(PathBuf);

impl Scratch {
	fn create() -> Self {
		let name = format!("exacopy-named-read-{}", std::process::id());
		let path = std::env::temp_dir().join(name);
		DirBuilder::new().mode(0o700).create(&path).unwrap();
		Self(path)
	}
}

impl Drop for Scratch {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[path = "../../../tests/unit/named_read.rs"]
mod coverage;
