//! Read-only fixture for review of one native Linux destination and CLI build.

use std::env;
use std::fs::{File, Metadata};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use exacopy_endpoint::linux_remote_qualification::RemoteKernelArchitecture;
use exacopy_platform::linux::{DestinationRoot, observe_remote_destination};
use rustix::fs::{self, Mode, OFlags};
use serde_json::{Value, json};

const BUILD_DOMAIN: &str = "ExaCopy remote running executable v1";
const BUILD_LIMIT: u64 = 512 * 1024 * 1024;

/// Emits unsigned observations for independent evidence review.
#[test]
#[ignore = "requires an explicit held native Linux destination and CLI executable"]
fn emit_unsigned_native_facts() -> Result<(), &'static str> {
	let result = observe();
	let value = match &result {
		Ok(destination) => json!({"status": "observed", "facts": destination}),
		Err(reason) => json!({"status": "blocked", "reason": reason}),
	};
	println!("\nEXACOPY_REMOTE_NATIVE_FACTS {value}");
	result.map(|_| ())
}

fn observe() -> Result<Value, &'static str> {
	let destination = absolute_input("EXACOPY_FACTS_DESTINATION")?;
	let binary = absolute_input("EXACOPY_FACTS_BINARY")?;
	let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
	let directory = fs::open(destination, flags, Mode::empty()).map_err(|_| "destination-open")?;
	let root =
		DestinationRoot::from_directory(directory.into()).map_err(|_| "destination-policy")?;
	let facts = observe_remote_destination(&root).map_err(|error| match error {
		exacopy_platform::linux::RemoteDestinationEligibilityError::UnsupportedMount => {
			"unsupported-mount"
		}
		exacopy_platform::linux::RemoteDestinationEligibilityError::UnsupportedKernel => {
			"unsupported-kernel"
		}
		exacopy_platform::linux::RemoteDestinationEligibilityError::Proc(_) => "proc-observation",
		_ => "native-destination-observation",
	})?;
	let build = measure_elf(&binary).map_err(|_| "build-measurement")?;
	if observe_remote_destination(&root).map_err(|_| "destination-recheck")? != facts {
		return Err("destination-changed");
	}
	let architecture = match facts.architecture() {
		RemoteKernelArchitecture::X86_64 => "x86_64",
		RemoteKernelArchitecture::Aarch64 => "aarch64",
		_ => return Err("unsupported-architecture"),
	};
	let ids = facts.ids();
	Ok(json!({
		"build_blake3_derive_key": build.to_hex().as_str(),
		"destination": {
			"architecture": architecture,
			"device": ids.root.device.to_string(),
			"inode": ids.root.inode.to_string(),
			"effective_uid": ids.effective_uid,
			"effective_gid": ids.effective_gid,
			"boot_id_hex": hex(&ids.boot_id),
			"mount_namespace": ids.mount_namespace.to_string(),
			"mount_id": ids.mount_id.to_string(),
			"unique_mount": ids.unique_mount.to_string(),
			"kernel_release_hex": hex(facts.kernel_release()),
			"kernel_build_hex": hex(facts.kernel_build()),
			"mount_record_hex": hex(facts.mount_record()),
		}
	}))
}

fn absolute_input(name: &str) -> Result<PathBuf, &'static str> {
	let path = env::var_os(name).ok_or("input-path")?;
	let path = PathBuf::from(path);
	if !path.is_absolute() || path.canonicalize().ok().as_ref() != Some(&path) {
		return Err("input-path");
	}
	Ok(path)
}

fn measure_elf(path: &Path) -> io::Result<blake3::Hash> {
	let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
	let open = || fs::open(path, flags, Mode::empty()).map(File::from);
	let file: File = open()?;
	let before = file.metadata()?;
	if !(4..=BUILD_LIMIT).contains(&before.len()) || !before.is_file() || before.mode() & 0o111 == 0
	{
		return Err(io::Error::other("invalid bounded executable"));
	}
	let mut reader = BufReader::new(file);
	let mut magic = [0; 4];
	reader.read_exact(&mut magic)?;
	if magic != *b"\x7fELF" {
		return Err(io::Error::other("expected ELF executable"));
	}
	let mut hasher = blake3::Hasher::new_derive_key(BUILD_DOMAIN);
	hasher.update(&magic);
	let mut bounded = reader.by_ref().take(before.len() - 4);
	let mut buffer = vec![0; 64 * 1024];
	while bounded.limit() != 0 {
		let count = bounded.read(&mut buffer)?;
		if count == 0 {
			return Err(io::Error::other("executable ended before its held extent"));
		}
		hasher.update(&buffer[..count]);
	}
	let mut extra = [0; 1];
	if reader.read(&mut extra)? != 0
		|| observation(&before) != observation(&reader.get_ref().metadata()?)
		|| observation(&before) != observation(&open()?.metadata()?)
	{
		return Err(io::Error::other("executable changed while measured"));
	}
	Ok(hasher.finalize())
}

fn observation(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
	(
		metadata.dev(),
		metadata.ino(),
		metadata.len(),
		metadata.mode(),
		metadata.mtime(),
		metadata.mtime_nsec(),
		metadata.ctime(),
		metadata.ctime_nsec(),
	)
}

fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write as _;
	let mut encoded = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(encoded, "{byte:02x}").expect("writing to a string");
	}
	encoded
}
