use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::FixtureResult;

pub(super) struct Settings {
	pub(super) sshd: PathBuf,
	pub(super) keygen: PathBuf,
	pub(super) id: PathBuf,
	pub(super) root: PathBuf,
}

impl Settings {
	pub(super) fn from_env() -> FixtureResult<Self> {
		let sshd = required_path("EXACOPY_TEST_OPENSSH_SSHD", fs::Metadata::is_file)?;
		let keygen = required_path("EXACOPY_TEST_OPENSSH_KEYGEN", fs::Metadata::is_file)?;
		let id = required_path("EXACOPY_TEST_OPENSSH_ID", fs::Metadata::is_file)?;
		let root = required_path("EXACOPY_TEST_OPENSSH_ROOT", fs::Metadata::is_dir)?;
		let system_config = required_path(
			"EXACOPY_TEST_OPENSSH_SYSTEM_CONFIG_DIR",
			fs::Metadata::is_dir,
		)?;
		if !literal_config_path(&root) {
			return Err("fixture root must have a literal ASCII path with no spaces or config metacharacters".into());
		}
		// OpenSSH may run the server's compiled-in system SSH rc even for
		// an internal subsystem. The operator supplies the daemon's sysconfdir.
		match fs::symlink_metadata(system_config.join("sshrc")) {
			Err(error) if error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(error.into()),
			Ok(_) => return Err("OpenSSH fixture requires the system SSH rc to be absent".into()),
		}
		Ok(Self {
			sshd,
			keygen,
			id,
			root,
		})
	}
}

fn required_path(name: &str, expected: fn(&fs::Metadata) -> bool) -> FixtureResult<PathBuf> {
	let value =
		env::var_os(name).ok_or_else(|| format!("set {name} to an absolute fixture path"))?;
	resolve_path(Path::new(&value), name, expected)
}

fn resolve_path(
	path: &Path,
	name: &str,
	expected: fn(&fs::Metadata) -> bool,
) -> FixtureResult<PathBuf> {
	if !path.is_absolute() {
		return Err(format!("{name} requires an absolute fixture path").into());
	}
	let path = path
		.canonicalize()
		.map_err(|error| format!("could not resolve {name} ({error})"))?;
	let metadata = path
		.metadata()
		.map_err(|error| format!("could not inspect {name} ({error})"))?;
	if !expected(&metadata) {
		return Err(format!("{name} refers to the wrong kind of fixture path").into());
	}
	Ok(path)
}

fn literal_config_path(path: &Path) -> bool {
	path.as_os_str()
		.as_encoded_bytes()
		.iter()
		.all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-'))
}

#[test]
fn fixture_paths_reject_default_command_lookup_and_config_injection() {
	assert!(resolve_path(Path::new("sshd"), "fixture", fs::Metadata::is_file).is_err());
	assert!(literal_config_path(Path::new("/clean_root-1.2/scratch")));
	for path in [
		"/with space",
		"/with#comment",
		"/with\nnewline",
		"/with%token",
	] {
		assert!(!literal_config_path(Path::new(path)), "{path:?}");
	}
}
