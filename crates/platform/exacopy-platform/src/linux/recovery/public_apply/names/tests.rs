use std::fs::{self as files, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use exacopy_endpoint::linux_copy::InodeTimestamp;
use rustix::fs::{OFlags, Timespec, Timestamps, fcntl_getfl, futimens};

use crate::scratch::Scratch;

use super::*;

#[test]
fn only_exact_required_candidate_opens_read_only_noatime_stream() {
	let scratch = Scratch::new();
	let root = scratch.open();
	let mount = mount_id(&root).unwrap();
	let path = scratch.path("target");
	let mut created = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(&path)
		.unwrap();
	let expected = b"checked bytes";
	created.write_all(expected).unwrap();
	let times = Timestamps {
		last_access: Timespec {
			tv_sec: 34,
			tv_nsec: 56,
		},
		last_modification: Timespec {
			tv_sec: 53,
			tv_nsec: 79,
		},
	};
	futimens(&created, &times).unwrap();
	drop(created);
	let original = files::symlink_metadata(&path).unwrap();
	let identity = JobFileIdentity {
		device: original.dev(),
		inode: original.ino(),
	};
	let required = ApplyRecoveryMetadata {
		length: expected.len() as u64,
		mode: 0o600,
		uid: original.uid(),
		gid: original.gid(),
		accessed_at: InodeTimestamp {
			seconds: 34,
			nanoseconds: 56,
		},
		modified_at: InodeTimestamp {
			seconds: 53,
			nanoseconds: 79,
		},
	};

	let name = OsStr::new("target");
	for selection in [
		None,
		Some((
			JobFileIdentity {
				inode: identity.inode ^ 1,
				..identity
			},
			required,
		)),
		Some((
			identity,
			ApplyRecoveryMetadata {
				accessed_at: InodeTimestamp {
					seconds: 35,
					..required.accessed_at
				},
				..required
			},
		)),
	] {
		let held = CurrentName::open(&root, name, mount, selection)
			.unwrap()
			.unwrap();
		assert!(fcntl_getfl(&held.pin).unwrap().contains(OFlags::PATH));
		assert!(held.candidate.is_none());
		assert!(
			matches!(view(Some(&held)), ApplyNameObservation::Present(observed) if observed == identity)
		);
	}
	let held = CurrentName::open(&root, name, mount, Some((identity, required)))
		.unwrap()
		.unwrap();
	let ApplyNameObservation::Readable(file) = view(Some(&held)) else {
		panic!("expected no-atime read aperture");
	};
	let flags = fcntl_getfl(&file.file).unwrap();
	assert_eq!(flags & OFlags::ACCMODE, OFlags::RDONLY);
	assert!(flags.contains(OFlags::NOATIME));
	let mut bytes = [0; 13];
	file.read_exact_at(0, &mut bytes).unwrap();
	file.check_logical_eof().unwrap();
	assert_eq!(&bytes, expected);
	recheck_name(&root, name, mount, Some(&held)).unwrap();
	let after = files::symlink_metadata(&path).unwrap();
	assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
	assert_eq!(
		(after.atime(), after.atime_nsec()),
		(original.atime(), original.atime_nsec())
	);
}
