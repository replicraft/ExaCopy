use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

use super::{Error, read, read_into, security};

#[test]
fn path_admission_refuses_aliases_and_non_drive_spellings_without_reading() {
	for path in [
		r"C:\only-leaf",
		r"C:drive-relative\selected",
		r"\\server\share\file",
		r"\\?\C:\private\selected",
		r"C:\private\..\selected",
		r"C:\private\selected:secret",
	] {
		let mut bytes = [0x31; 8];
		let mut scratch = [0x32; 4];
		assert_eq!(
			read_into(Path::new(path), &mut bytes, &mut scratch),
			Err(Error::InvalidPath)
		);
		assert_eq!(bytes, [0x31; 8]);
		assert_eq!(scratch, [0x32; 4]);
	}
}

#[test]
#[ignore = "requires a non-elevated Windows user and an admitted fixed NTFS fixture parent"]
fn native_protects_content_sharing_and_confidentiality() {
	let subject = security::Subject::current().expect("run as a non-elevated Windows user");
	let base = std::env::var_os("EXACOPY_WINDOWS_PROTECTED_FIXTURE_PARENT")
		.map(PathBuf::from)
		.expect("supply the admitted fixed NTFS fixture parent");
	let folder = base.join(format!("ExaCopy-protected-snapshot-{}", std::process::id()));
	fs::create_dir(&folder).expect("exclusively create fixture directory");
	let fixture = Fixture(folder);
	let file = fixture.0.join("selected");
	let alias = fixture.0.join("hardlink");
	let user = format!("*{}", sid_text(&subject.sid));
	secure(&fixture.0, &user);
	fs::write(&file, b"synthetic protected bytes").unwrap();
	secure(&file, &user);
	assert_eq!(read(&file).unwrap(), b"synthetic protected bytes");

	let writer = OpenOptions::new()
		.write(true)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
		.open(&file)
		.unwrap();
	assert_eq!(read(&file), Err(Error::Busy));
	drop(writer);

	fs::hard_link(&file, &alias).unwrap();
	assert_eq!(read(&file), Err(Error::Unprotected));
	fs::remove_file(alias).unwrap();

	icacls(&file, &["/grant", "*S-1-1-0:(R)"]);
	let mut bytes = [0x41; 128];
	let mut scratch = [0x42; 8];
	assert_eq!(
		read_into(&file, &mut bytes, &mut scratch),
		Err(Error::Unprotected)
	);
	assert_eq!(bytes, [0x41; 128]);
	assert_eq!(scratch, [0x42; 8]);
}

fn secure(path: &Path, user: &str) {
	icacls(
		path,
		&["/grant:r", &format!("{user}:(F)"), "/inheritance:r"],
	);
}

fn icacls(path: &Path, args: &[&str]) {
	let system = std::env::var_os("SystemRoot").expect("native Windows SystemRoot");
	let tool = PathBuf::from(system).join("System32").join("icacls.exe");
	let result = Command::new(tool).arg(path).args(args).output().unwrap();
	assert!(
		result.status.success(),
		"could not provision disposable ACL fixture: {:?}",
		result.status
	);
}

fn sid_text(sid: &[u8]) -> String {
	use std::fmt::Write as _;

	let mut authority = [0; 8];
	authority[2..].copy_from_slice(&sid[2..8]);
	let mut text = format!("S-{}-{}", sid[0], u64::from_be_bytes(authority));
	for word in sid[8..].as_chunks::<4>().0 {
		write!(&mut text, "-{}", u32::from_le_bytes(*word)).unwrap();
	}
	text
}

struct Fixture(PathBuf);

impl Drop for Fixture {
	fn drop(&mut self) {
		for member in ["hardlink", "selected"] {
			let _ = fs::remove_file(self.0.join(member));
		}
		let _ = fs::remove_dir(&self.0);
	}
}
