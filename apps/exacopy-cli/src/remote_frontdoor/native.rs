use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize as _, Zeroizing};

use super::FrontdoorError;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as _;
#[cfg(windows)]
use std::path::{Component, Prefix};

const MAX_PROTECTED_PATH_COMPONENTS: usize = 64;
#[cfg(unix)]
const MAX_PROTECTED_PATH_BYTES: usize = 4095;
#[cfg(windows)]
const MAX_LOCAL_PATH_UNITS: usize = 32_766;

pub(super) fn remote_bytes(value: &OsStr) -> Result<&[u8], FrontdoorError> {
	#[cfg(unix)]
	let bytes = value.as_bytes();
	// Only exact Unicode scalar values leave this host as UTF-8 SFTP bytes.
	// Keep Windows path rules out of the independently parsed remote namespace.
	#[cfg(windows)]
	let bytes = value.to_str().ok_or(FrontdoorError::Operand)?.as_bytes();
	if bytes.is_empty() {
		return Err(FrontdoorError::Operand);
	}
	Ok(bytes)
}

pub(super) fn password_text(raw: OsString) -> Option<String> {
	match raw.into_string() {
		Ok(text) => Some(text),
		Err(raw) => {
			// Wipe the rejected native representation without decoding it again.
			raw.into_encoded_bytes().zeroize();
			None
		}
	}
}

pub(super) fn key_passphrase(raw: OsString, maximum_bytes: usize) -> Option<Zeroizing<Vec<u8>>> {
	#[cfg(unix)]
	let bytes = {
		use std::os::unix::ffi::OsStringExt as _;
		raw.into_vec()
	};
	#[cfg(windows)]
	let bytes = password_text(raw)?.into_bytes();
	let bytes = Zeroizing::new(bytes);
	((1..=maximum_bytes).contains(&bytes.len()) && !bytes.contains(&0)).then_some(bytes)
}

#[cfg(unix)]
pub(super) fn destination_path(path: &Path) -> Result<(), FrontdoorError> {
	crate::unix_path::split(path)
		.map(|_| ())
		.map_err(|_| FrontdoorError::Destination)
}

#[cfg(windows)]
pub(super) fn destination_path(path: &Path) -> Result<(), FrontdoorError> {
	windows_file_path(path, WindowsRole::Destination)
		.then_some(())
		.ok_or(FrontdoorError::Destination)
}

pub(super) fn protected_path(path: PathBuf) -> Result<PathBuf, FrontdoorError> {
	if !path.is_absolute() || !protected_components(&path) {
		return Err(FrontdoorError::ProfilePath);
	}
	Ok(path)
}

#[cfg(unix)]
fn protected_components(path: &Path) -> bool {
	let bytes = path.as_os_str().as_bytes();
	if bytes.len() > MAX_PROTECTED_PATH_BYTES {
		return false;
	}
	let Some(relative) = bytes.strip_prefix(b"/") else {
		return false;
	};
	let mut count = 0;
	for part in relative.split(|&byte| byte == b'/') {
		if exacopy_endpoint::UnixComponent::new(part).is_err() {
			return false;
		}
		count += 1;
	}
	(2..=MAX_PROTECTED_PATH_COMPONENTS).contains(&count)
}

#[cfg(windows)]
fn protected_components(path: &Path) -> bool {
	windows_file_path(path, WindowsRole::Protected)
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowsRole {
	Destination,
	Protected,
}

#[cfg(windows)]
fn windows_file_path(path: &Path, role: WindowsRole) -> bool {
	let ordinary_prefix = match path.components().next() {
		Some(Component::Prefix(prefix)) if path.is_absolute() => match prefix.kind() {
			Prefix::Disk(_) => true,
			Prefix::UNC(server, share) => windows_component(server) && windows_component(share),
			_ => false,
		},
		Some(Component::Normal(_) | Component::CurDir) => {
			role == WindowsRole::Destination && !path.has_root()
		}
		_ => false,
	};
	if !ordinary_prefix || path.file_name().is_none() {
		return false;
	}

	let sep = |unit| unit == u16::from(b'\\') || unit == u16::from(b'/');
	let units: Vec<u16> = path
		.as_os_str()
		.encode_wide()
		.take(MAX_LOCAL_PATH_UNITS + 1)
		.collect();
	if units.len() > MAX_LOCAL_PATH_UNITS || units.last().is_some_and(|&unit| sep(unit)) {
		return false;
	}
	let dot = u16::from(b'.');
	// Path::components normalizes interior dots. Check the original spelling.
	if units
		.split(|&unit| sep(unit))
		.enumerate()
		.any(|(index, part)| {
			part == [dot, dot]
				|| (part == [dot] && (index != 0 || role != WindowsRole::Destination))
		}) {
		return false;
	}

	let mut count = 0;
	for component in path.components() {
		if let Component::Normal(name) = component {
			if !windows_component(name) {
				return false;
			}
			count += 1;
		}
	}
	role == WindowsRole::Destination || count <= MAX_PROTECTED_PATH_COMPONENTS
}

#[cfg(windows)]
fn windows_component(name: &OsStr) -> bool {
	use exacopy_platform::windows::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};
	let units: Vec<u16> = name
		.encode_wide()
		.take(MAX_WINDOWS_COMPONENT_UNITS + 1)
		.collect();
	WindowsComponent::new(&units).is_ok()
}

#[cfg(test)]
mod tests;
