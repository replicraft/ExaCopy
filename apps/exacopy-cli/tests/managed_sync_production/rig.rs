//! Descriptor-relative setup and cleanup for the selected native test parent.

use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use exacopy_plan::workflow_sync::NativeObject;
use exacopy_platform::linux::SyncProfileStore;
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, StatVfsMountFlags};
use rustix::io::Errno;

use super::{TestResult, object};

const DIRECTORY: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);
const CHILD: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);

pub(super) struct Sandbox {
	pub(super) path: PathBuf,
	pub(super) directory: File,
	entries: Vec<Entry>,
	cleanup_attempted: bool,
}

struct Entry {
	parent: File,
	held: File,
	name: Vec<u8>,
	identity: (u64, u64),
	flags: AtFlags,
}

impl Sandbox {
	pub(super) fn create<T>(
		admit: impl FnOnce(&Path, &File) -> TestResult<T>,
	) -> TestResult<(Self, T)> {
		let selected = PathBuf::from(
			std::env::var_os("EXACOPY_MANAGED_SYNC_FIXTURE_PARENT")
				.ok_or("independently selected fixture parent is required")?,
		);
		if !selected.is_absolute()
			|| selected == Path::new("/")
			|| selected.canonicalize()? != selected
		{
			return Err("fixture parent must be an exact canonical absolute path beneath /".into());
		}
		let preflight = SyncProfileStore::open(&selected)?;
		let selected_dir = File::from(fs::openat2(
			fs::CWD,
			&selected,
			DIRECTORY,
			Mode::empty(),
			ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
		)?);
		let selected_meta = selected_dir.metadata()?;
		assert_eq!(
			(preflight.identity().device(), preflight.identity().inode()),
			(selected_meta.dev(), selected_meta.ino())
		);
		let admitted = admit(&selected, &selected_dir)?;
		preflight.recheck()?;
		if fs::fstatvfs(&selected_dir)?
			.f_flag
			.contains(StatVfsMountFlags::RDONLY)
		{
			return Err("selected whole ext4 fixture mount is read-only".into());
		}

		let name = format!("managed-sync-fixture-{}", std::process::id());
		let path = selected.join(&name);
		let (directory, entry) = create_directory(&selected_dir, name.as_bytes())?;
		Ok((
			Self {
				path,
				directory,
				entries: vec![entry],
				cleanup_attempted: false,
			},
			admitted,
		))
	}

	pub(super) fn mkdir(&mut self, parent: &File, name: &[u8]) -> TestResult<File> {
		let (directory, entry) = create_directory(parent, name)?;
		self.entries.push(entry);
		Ok(directory)
	}

	pub(super) fn write_new(
		&mut self,
		parent: &File,
		name: &[u8],
		bytes: &[u8],
	) -> TestResult<File> {
		let held_parent = parent.try_clone()?;
		let mut file = File::from(fs::openat2(
			parent,
			name,
			OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL,
			Mode::from_raw_mode(0o600),
			CHILD,
		)?);
		self.entries
			.push(Entry::new(held_parent, name, &file, AtFlags::empty())?);
		file.write_all(bytes)?;
		Ok(file)
	}

	pub(super) fn track_created_slot(&mut self, parent: &File, name: &[u8]) -> TestResult {
		let file = open_child(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
		self.entries.push(Entry::new(
			parent.try_clone()?,
			name,
			&file,
			AtFlags::empty(),
		)?);
		Ok(())
	}

	pub(super) fn rename(&mut self, parent: &File, from: &[u8], to: &[u8]) -> TestResult {
		let source = fs::statat(parent, from, AtFlags::SYMLINK_NOFOLLOW)?;
		let identity = (source.st_dev, source.st_ino);
		let entry = self
			.entries
			.iter_mut()
			.find(|entry| entry.identity == identity && entry.name == from)
			.ok_or("rename source is not a fixture-owned entry")?;
		fs::renameat_with(parent, from, parent, to, fs::RenameFlags::NOREPLACE)?;
		entry.name = to.to_vec();
		Ok(())
	}

	pub(super) fn clean(&mut self) -> TestResult {
		self.cleanup_attempted = true;
		while let Some(entry) = self.entries.last() {
			entry.remove()?;
			self.entries.pop();
		}
		Ok(())
	}
}

impl Drop for Sandbox {
	fn drop(&mut self) {
		if !self.cleanup_attempted
			&& let Err(error) = self.clean()
		{
			eprintln!(
				"fixture cleanup refused at {} ({error})",
				self.path.display()
			);
		}
	}
}

impl Entry {
	fn new(parent: File, name: &[u8], held: &File, flags: AtFlags) -> io::Result<Self> {
		let metadata = held.metadata()?;
		let stat = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
		let identity = (metadata.dev(), metadata.ino());
		if (stat.st_dev, stat.st_ino) != identity {
			return Err(io::Error::other("fixture name differs from held identity"));
		}
		Ok(Self {
			parent,
			held: held.try_clone()?,
			name: name.to_vec(),
			identity,
			flags,
		})
	}

	fn remove(&self) -> TestResult {
		let held = self.held.metadata()?;
		assert_eq!((held.dev(), held.ino()), self.identity);
		let stat = fs::statat(
			&self.parent,
			self.name.as_slice(),
			AtFlags::SYMLINK_NOFOLLOW,
		)?;
		if (stat.st_dev, stat.st_ino) != self.identity {
			return Err("fixture cleanup found a replaced name".into());
		}
		fs::unlinkat(&self.parent, self.name.as_slice(), self.flags)?;
		assert_missing(&self.parent, &self.name);
		Ok(())
	}
}

fn create_directory(parent: &File, name: &[u8]) -> TestResult<(File, Entry)> {
	let held_parent = parent.try_clone()?;
	fs::mkdirat(parent, name, Mode::from_raw_mode(0o700))?;
	let pin_error = |error| {
		io::Error::other(format!(
			"cannot pin newly created fixture directory {:?}; retained for review ({error})",
			OsStr::from_bytes(name),
		))
	};
	let directory =
		open_child(parent, name, OFlags::RDONLY | OFlags::DIRECTORY).map_err(pin_error)?;
	let entry = Entry::new(held_parent, name, &directory, AtFlags::REMOVEDIR).map_err(pin_error)?;
	Ok((directory, entry))
}

pub(super) fn open_child(parent: &File, name: &[u8], flags: OFlags) -> io::Result<File> {
	fs::openat2(
		parent,
		name,
		flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
		Mode::empty(),
		CHILD,
	)
	.map(File::from)
	.map_err(Into::into)
}

pub(super) fn read(parent: &File, name: &[u8]) -> TestResult<Vec<u8>> {
	let mut output = Vec::new();
	open_child(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?
		.take(24 * 1024 + 1)
		.read_to_end(&mut output)?;
	assert!(output.len() <= 24 * 1024);
	Ok(output)
}

pub(super) fn assert_missing(parent: &File, name: &[u8]) {
	assert_eq!(
		fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).unwrap_err(),
		Errno::NOENT
	);
}

pub(super) fn kernel_location() -> TestResult<([u8; 16], NativeObject, NativeObject)> {
	let proc = File::from(fs::openat2(
		fs::CWD,
		c"/proc",
		DIRECTORY,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
	)?);
	if fs::fstatfs(&proc)?.f_type != fs::PROC_SUPER_MAGIC || proc.metadata()?.ino() != 1 {
		return Err("fixture requires the verified procfs root".into());
	}
	let mut boot_text = String::new();
	open_child(
		&proc,
		b"sys/kernel/random/boot_id",
		OFlags::RDONLY | OFlags::NONBLOCK,
	)?
	.take(38)
	.read_to_string(&mut boot_text)?;
	assert_eq!(boot_text.len(), 37);
	let boot = uuid::Uuid::parse_str(boot_text.trim_end())?.into_bytes();
	let thread = File::from(fs::openat2(
		&proc,
		c"thread-self",
		DIRECTORY.difference(OFlags::NOFOLLOW),
		Mode::empty(),
		ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
	)?);
	Ok((
		boot,
		namespace(&thread, c"ns/mnt")?,
		namespace(&thread, c"ns/user")?,
	))
}

fn namespace(thread: &File, name: &CStr) -> TestResult<NativeObject> {
	let ns = File::from(fs::openat(
		thread,
		name,
		OFlags::RDONLY | OFlags::CLOEXEC,
		Mode::empty(),
	)?);
	if fs::fstatfs(&ns)?.f_type != 0x6e73_6673 {
		return Err("fixture namespace descriptor is outside nsfs".into());
	}
	Ok(object(&ns.metadata()?))
}
