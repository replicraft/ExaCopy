use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read as _};
use std::num::NonZeroU32;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};

use super::handle::mount_id;

const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;
const MAX_MOUNT_RECORDS: usize = 8192;
const PROC_ROOT_INODE: u64 = 1;
const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const BELOW_PROC: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);

pub(super) struct ProcMounts {
	root: OwnedFd,
	thread: OwnedFd,
}

impl ProcMounts {
	pub(super) fn open() -> io::Result<Self> {
		let root = fs::openat2(
			fs::CWD,
			c"/proc",
			DIRECTORY_FLAGS,
			Mode::empty(),
			ResolveFlags::NO_SYMLINKS,
		)?;
		if fs::fstatfs(&root)?.f_type != fs::PROC_SUPER_MAGIC
			|| fs::fstat(&root)?.st_ino != PROC_ROOT_INODE
		{
			return Err(unsupported());
		}
		let thread = fs::openat2(
			&root,
			c"thread-self",
			DIRECTORY_FLAGS,
			Mode::empty(),
			BELOW_PROC,
		)?;
		Ok(Self { root, thread })
	}

	pub(super) fn root_file(&self, name: &CStr, limit: usize) -> io::Result<Vec<u8>> {
		read_proc(&self.root, name, limit)
	}

	pub(super) fn namespace_id(&self) -> io::Result<u64> {
		self.thread_namespace(c"mnt", b"mnt:[")
	}

	pub(super) fn user_namespace_id(&self) -> io::Result<u64> {
		self.thread_namespace(c"user", b"user:[")
	}

	pub(super) fn credential_status(&self) -> io::Result<Vec<u8>> {
		const MAX_CREDENTIAL_STATUS_BYTES: usize = 64 * 1024;
		read_proc(&self.thread, c"status", MAX_CREDENTIAL_STATUS_BYTES)
	}

	#[cfg(feature = "experimental-linux-managed-sync")]
	pub(super) fn identity_maps(&self) -> io::Result<[Vec<u8>; 2]> {
		const IDENTITY_MAP_LIMIT: usize = 128;
		Ok([
			read_proc(&self.thread, c"uid_map", IDENTITY_MAP_LIMIT)?,
			read_proc(&self.thread, c"gid_map", IDENTITY_MAP_LIMIT)?,
		])
	}

	fn thread_namespace(&self, name: &CStr, prefix: &[u8]) -> io::Result<u64> {
		let namespace = fs::openat2(
			&self.thread,
			c"ns",
			DIRECTORY_FLAGS,
			Mode::empty(),
			BELOW_PROC | ResolveFlags::NO_SYMLINKS,
		)?;
		let target = fs::readlinkat(&namespace, name, Vec::new())?;
		target
			.as_bytes()
			.strip_prefix(prefix)
			.and_then(|value| value.strip_suffix(b"]"))
			.and_then(nonzero_decimal)
			.ok_or_else(unsupported)
	}

	pub(super) fn mount_table(&self) -> io::Result<MountObservations> {
		let bytes = read_proc(&self.thread, c"mountinfo", MAX_MOUNTINFO_BYTES)?;
		MountObservations::parse(&bytes)
	}
}

fn read_proc(directory: impl AsFd, name: &CStr, limit: usize) -> io::Result<Vec<u8>> {
	let file = fs::openat2(
		directory,
		name,
		OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
		Mode::empty(),
		BELOW_PROC | ResolveFlags::NO_SYMLINKS,
	)?;
	if FileType::from_raw_mode(fs::fstat(&file)?.st_mode) != FileType::RegularFile {
		return Err(unsupported());
	}
	let mut bytes = Vec::new();
	let limit = u64::try_from(limit)
		.ok()
		.and_then(|limit| limit.checked_add(1))
		.ok_or_else(unsupported)?;
	File::from(file).take(limit).read_to_end(&mut bytes)?;
	if bytes.len() as u64 >= limit {
		return Err(unsupported());
	}
	Ok(bytes)
}

/// One bounded observation of the caller's Linux mount namespace.
pub struct MountObservations {
	bytes: Vec<u8>,
	entries: Vec<(u64, std::ops::Range<usize>)>,
}

#[derive(Debug)]
pub(super) struct MountRecord<'line> {
	pub(super) id: u64,
	pub(super) parent: u64,
	pub(super) device: (u32, u32),
	// Opaque mountinfo field. The exact b"/" value denotes a whole filesystem.
	pub(super) root: &'line [u8],
	pub(super) mount_point: &'line [u8],
	pub(super) mount_options: &'line [u8],
	pub(super) optional_fields: Vec<&'line [u8]>,
	pub(super) filesystem: &'line [u8],
	pub(super) source: &'line [u8],
	pub(super) super_options: &'line [u8],
}

impl MountObservations {
	/// Reads bounded mount facts through verified procfs.
	///
	/// # Errors
	/// Refuses unavailable, inconsistent, oversized, or malformed observations.
	pub fn capture() -> io::Result<Self> {
		let proc = ProcMounts::open()?;
		let namespace = proc.namespace_id()?;
		let table = proc.mount_table()?;
		if proc.namespace_id()? != namespace {
			return Err(unsupported());
		}
		Ok(table)
	}

	/// Returns the native mount ID of a held object on a known whole filesystem.
	///
	/// Whole-filesystem aliases can still refer to the same physical directory.
	/// Compare physical identities separately when checking directory ancestry.
	///
	/// # Errors
	/// Refuses an unknown mount or a mounted subtree.
	pub fn whole_filesystem_mount(&self, descriptor: impl AsFd) -> io::Result<u64> {
		let fd = descriptor.as_fd();
		let id = mount_id(fd)?;
		let stat = fs::fstat(fd)?;
		let record = self.record(id).ok_or_else(unsupported)?;
		if record.root != b"/" || record.device != (fs::major(stat.st_dev), fs::minor(stat.st_dev))
		{
			return Err(unsupported());
		}
		Ok(id)
	}

	pub(super) fn record(&self, id: u64) -> Option<MountRecord<'_>> {
		parse_record(self.record_bytes(id)?)
	}

	pub(super) fn record_bytes(&self, id: u64) -> Option<&[u8]> {
		let index = self
			.entries
			.binary_search_by_key(&id, |entry| entry.0)
			.ok()?;
		Some(&self.bytes[self.entries[index].1.clone()])
	}

	pub(super) fn parse(bytes: &[u8]) -> io::Result<Self> {
		if bytes.is_empty() || bytes.len() > MAX_MOUNTINFO_BYTES || !bytes.ends_with(b"\n") {
			return Err(unsupported());
		}
		let mut entries = Vec::new();
		let mut offset = 0;
		for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
			if entries.len() == MAX_MOUNT_RECORDS {
				return Err(unsupported());
			}
			let past = offset + line.len();
			let record = parse_record(line).ok_or_else(unsupported)?;
			entries.push((record.id, offset..past));
			offset = past + 1;
		}
		entries.sort_unstable_by_key(|entry| entry.0);
		if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
			return Err(unsupported());
		}
		Ok(Self {
			bytes: bytes.to_vec(),
			entries,
		})
	}
}

fn parse_record(line: &[u8]) -> Option<MountRecord<'_>> {
	let mut fields = line.split(|byte| *byte == b' ');
	let id = nonzero_decimal(fields.next()?)?;
	let parent = nonzero_decimal(fields.next()?)?;
	let device = fields.next()?;
	let colon = device.iter().position(|byte| *byte == b':')?;
	let device = (
		std::str::from_utf8(&device[..colon]).ok()?.parse().ok()?,
		std::str::from_utf8(&device[colon + 1..])
			.ok()?
			.parse()
			.ok()?,
	);
	let root = fields.next()?;
	let mount_point = fields.next().filter(|name| name.starts_with(b"/"))?;
	let mount_options = fields.next().filter(|field| !field.is_empty())?;
	let mut optional_fields = Vec::new();
	loop {
		match fields.next()? {
			b"-" => break,
			b"" => return None,
			field => optional_fields.push(field),
		}
	}
	let filesystem = fields.next().filter(|field| !field.is_empty())?;
	if !root.starts_with(b"/") && !(filesystem == b"nsfs" && namespace_handle(root).is_some()) {
		return None;
	}
	let source = fields.next().filter(|field| !field.is_empty())?;
	let super_options = fields.next().filter(|field| !field.is_empty())?;
	if fields.next().is_some() {
		return None;
	}
	Some(MountRecord {
		id,
		parent,
		device,
		root,
		mount_point,
		mount_options,
		optional_fields,
		filesystem,
		source,
		super_options,
	})
}

#[derive(Clone, Copy)]
enum NamespaceKind {
	Cgroup,
	Ipc,
	Mount,
	Network,
	Pid,
	Time,
	User,
	Uts,
}

// Linux nsfs_show_path prints the namespace's canonical kind and inode. The
// inode comes from the unsigned int ns_common.inum. Neither is a path.
fn namespace_handle(root: &[u8]) -> Option<(NamespaceKind, NonZeroU32)> {
	let mut fields = root.splitn(2, |byte| *byte == b':');
	let kind = match fields.next()? {
		b"cgroup" => NamespaceKind::Cgroup,
		b"ipc" => NamespaceKind::Ipc,
		b"mnt" => NamespaceKind::Mount,
		b"net" => NamespaceKind::Network,
		b"pid" => NamespaceKind::Pid,
		b"time" => NamespaceKind::Time,
		b"user" => NamespaceKind::User,
		b"uts" => NamespaceKind::Uts,
		_ => return None,
	};
	let number = fields.next()?.strip_prefix(b"[")?.strip_suffix(b"]")?;
	let inode = NonZeroU32::new(u32::try_from(nonzero_decimal(number)?).ok()?)?;
	Some((kind, inode))
}

pub(super) fn nonzero_decimal(bytes: &[u8]) -> Option<u64> {
	if bytes.is_empty() || bytes.first() == Some(&b'0') || !bytes.iter().all(u8::is_ascii_digit) {
		return None;
	}
	std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn unsupported() -> io::Error {
	io::Error::new(
		io::ErrorKind::Unsupported,
		"mount ancestry could not be established",
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn distinguishes_whole_filesystems_from_subtree_aliases() {
		let table = MountObservations::parse(
			b"21 1 8:1 / / rw shared:2 - ext4 /dev/example rw,commit=30\n23 21 8:2 / /mnt/full rw - ext4 /dev/other rw\n42 21 8:1 /a\\040b /mnt/alias rw - ext4 /dev/example rw\n",
		).unwrap();
		let root = table.record(21).unwrap();
		assert_eq!(root.parent, 1);
		assert_eq!(root.mount_point, b"/");
		assert_eq!(root.mount_options, b"rw");
		assert_eq!(root.optional_fields, [b"shared:2"]);
		assert_eq!(root.filesystem, b"ext4");
		assert_eq!(root.source, b"/dev/example");
		assert_eq!(root.super_options, b"rw,commit=30");
		assert_eq!(table.record(23).unwrap().root, b"/");
		assert_eq!(table.record(42).unwrap().root, b"/a\\040b");
		assert!(table.record(99).is_none());
	}

	#[test]
	fn admits_only_canonical_namespace_handle_roots_for_nsfs() {
		for kind in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"] {
			let row = format!("17 13 0:4 {kind}:[4294967295] /run/handle rw - nsfs nsfs rw\n");
			assert!(MountObservations::parse(row.as_bytes()).is_ok(), "{row:?}");
		}

		for (root, filesystem) in [
			("net:[1]", "ext4"),
			("net:[1]", "nsfs.foreign"),
			("relative", "nsfs"),
			("socket:[1]", "nsfs"),
			("pid_for_children:[1]", "nsfs"),
			("time_for_children:[1]", "nsfs"),
			("Net:[1]", "nsfs"),
			("net:[]", "nsfs"),
			("net:[0]", "nsfs"),
			("net:[01]", "nsfs"),
			("net:[+1]", "nsfs"),
			("net:[-1]", "nsfs"),
			("net:[１]", "nsfs"),
			("net:[4294967296]", "nsfs"),
			("net:[18446744073709551616]", "nsfs"),
			("net:[1", "nsfs"),
			("net:1]", "nsfs"),
			("net:[1]/extra", "nsfs"),
			("net:[1]:[2]", "nsfs"),
		] {
			let row = format!("17 13 0:4 {root} /run/handle rw - {filesystem} nsfs rw\n");
			assert!(MountObservations::parse(row.as_bytes()).is_err(), "{row:?}");
		}
	}

	#[test]
	fn malformed_or_duplicate_mount_facts_fail_closed() {
		for bad in [
			b"1 2 8:1 / / rw - ext4 /dev/example rw".as_slice(),
			b"1 2 8:1 / / rw - ext4 /dev/example rw\n1 2 8:1 / / rw - ext4 /dev/example rw\n",
			b"x 2 8:1 / / rw - ext4 /dev/example rw\n",
			b"1 2 8:1 relative / rw - ext4 /dev/example rw\n",
		] {
			assert!(MountObservations::parse(bad).is_err());
		}
	}
}

#[cfg(test)]
#[path = "../../tests/unit/mount_observation.rs"]
mod coverage_tests;
