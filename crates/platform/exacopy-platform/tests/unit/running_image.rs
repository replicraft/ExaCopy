use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt as _;

use super::super::facts;
use crate::scratch::Scratch;

#[test]
fn image_facts_admit_only_nonempty_files_within_the_running_image_limit() {
	const IMAGE_LIMIT: u64 = 512 * 1024 * 1024;
	let scratch = Scratch::new();
	for (name, length, admitted) in [
		("empty", 0, false),
		("minimum", 1, true),
		("maximum", IMAGE_LIMIT, true),
		("over-limit", IMAGE_LIMIT + 1, false),
	] {
		let path = scratch.path(name);
		File::options()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&path)
			.expect("create a private regular-file fixture")
			.set_len(length)
			.expect("establish the fixture's sparse logical length");
		let file = File::open(&path).expect("open the fixture read-only");
		let observed = facts(&file);

		if admitted {
			assert_eq!(
				observed.expect("accept the boundary length").len(),
				length,
				"fixture {name}"
			);
		} else {
			let error = observed.expect_err("reject the out-of-bounds length");
			assert_eq!(error.kind(), ErrorKind::Other, "fixture {name}");
			assert_eq!(
				error.to_string(),
				"the exact running Linux executable could not be established",
				"fixture {name}"
			);
		}
	}
}
