//! Native read-only admission of a specifically selected unmapped ext4 sync pair.

#![cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]

use std::error::Error;
use std::ffi::CStr;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{
	FileIdentity, SyncHistoryLocation, SyncPreviewEntry, SyncPreviewError, SyncPreviewRoots,
};
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, StatVfsMountFlags, StatxFlags};
use rustix::process::{geteuid, getuid};

const PARENT: &str = "EXACOPY_SYNC_HISTORY_STATMOUNT_PARENT";
const MARKER: &str = "EXACOPY_SYNC_HISTORY_STATMOUNT_RESULT";
const STATUS_LIMIT: usize = 64 * 1024;
const MOUNTINFO_LIMIT: usize = 1024 * 1024;
const EXT_MAGIC: fs::FsWord = 0xef53;
const NSFS_MAGIC: fs::FsWord = 0x6e73_6673;
const MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
const DIRECTORY: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);
const NO_LINKS: ResolveFlags = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
const CHILD: ResolveFlags = NO_LINKS
	.union(ResolveFlags::BENEATH)
	.union(ResolveFlags::NO_XDEV);
const BELOW_PROC: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_XDEV)
	.union(ResolveFlags::NO_MAGICLINKS);
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
#[ignore = "requires an independently admitted unprivileged ext4 statmount fixture"]
fn held_ext4_history_mount_admits_unmapped_attributes() -> TestResult {
	let result = inspect();
	match &result {
		Ok(observed) => println!(
			"\n{MARKER} schema_version=1 outcome=passed feature=experimental-linux-managed-sync boot={} mount_namespace={}:{} user_namespace={}:{} mount={} unique_mount={} parent={}:{} left={}:{} right={}:{} idmap=clear",
			observed.boot,
			observed.mount_namespace.0,
			observed.mount_namespace.1,
			observed.user_namespace.0,
			observed.user_namespace.1,
			observed.parent.mount,
			observed.parent.unique_mount,
			observed.parent.identity.0,
			observed.parent.identity.1,
			observed.roots[0].identity.0,
			observed.roots[0].identity.1,
			observed.roots[1].identity.0,
			observed.roots[1].identity.1,
		),
		Err(error) => {
			let reason = match error.downcast_ref::<SyncPreviewError>() {
				Some(SyncPreviewError::UnsupportedHistoryMountAttributes) => {
					Some("unsupported_mount_attributes")
				}
				Some(SyncPreviewError::IdMappedHistoryMount) => Some("idmapped_mount"),
				Some(SyncPreviewError::System(error))
					if error.kind() == io::ErrorKind::PermissionDenied =>
				{
					Some("permission_denied")
				}
				_ => None,
			};
			if let Some(reason) = reason {
				println!(
					"\n{MARKER} schema_version=1 outcome=blocked feature=experimental-linux-managed-sync reason={reason}"
				);
			}
		}
	}
	// An unsupported capability is still a nonpassing test. The native runner
	// recognizes the exact blocked marker and retains the nonzero exit.
	result.map(drop)
}

fn inspect() -> TestResult<Observed> {
	let path = PathBuf::from(std::env::var_os(PARENT).ok_or("missing selected ext4 fixture")?);
	if !path.is_absolute()
		|| path != path.canonicalize()?
		|| getuid().is_root()
		|| getuid() != geteuid()
	{
		return Err("fixture requires the selected canonical path and unprivileged UID".into());
	}
	let proc = File::from(fs::openat2(
		fs::CWD,
		c"/proc",
		DIRECTORY,
		Mode::empty(),
		NO_LINKS,
	)?);
	if fs::fstatfs(&proc)?.f_type != fs::PROC_SUPER_MAGIC || proc.metadata()?.ino() != 1 {
		return Err("fixture requires the verified procfs root".into());
	}
	let thread = File::from(fs::openat2(
		&proc,
		c"thread-self",
		DIRECTORY.difference(OFlags::NOFOLLOW),
		Mode::empty(),
		BELOW_PROC,
	)?);
	check_unprivileged(&thread)?;

	let names = [c"left", c"right"];
	let parent = open_directory(&path)?;
	let roots = [
		open_child(&parent, names[0])?,
		open_child(&parent, names[1])?,
	];
	let selected = SyncPreviewRoots::open(
		&path,
		names
			.map(|name| UnixComponent::new(name.to_bytes()).expect("fixed fixture directory name")),
	)?;
	let before = observe(&proc, &thread, &parent, [&roots[0], &roots[1]])?;
	check_selection(&selected, &before)?;
	let admission = selected.require_unmapped_history_mount();

	// Reobserve the same held descriptors first, then independently confirm
	// that reopening their names still reaches those exact objects.
	let after = observe(&proc, &thread, &parent, [&roots[0], &roots[1]])?;
	let rebound_parent = open_directory(&path)?;
	let rebound_roots = [
		open_child(&rebound_parent, names[0])?,
		open_child(&rebound_parent, names[1])?,
	];
	let rebound = observe(
		&proc,
		&thread,
		&rebound_parent,
		[&rebound_roots[0], &rebound_roots[1]],
	)?;
	if before != after || before != rebound {
		return Err("held descriptors or mount changed during admission".into());
	}
	check_unprivileged(&thread)?;
	admission?;
	let subject = UnixComponent::new(b"statmount-probe").expect("fixed absent probe name");
	let pair = selected.observe(subject)?;
	if !matches!(
		pair.entries(),
		[SyncPreviewEntry::Absent, SyncPreviewEntry::Absent]
	) {
		return Err("preprovisioned statmount probe name must remain absent".into());
	}
	let history = pair.recheck_history_location()?;
	check_history(&history.1, &before, names)?;
	if history != pair.recheck_history_location()? {
		return Err("held history observation changed after mount admission".into());
	}
	Ok(after)
}

#[derive(Debug, Eq, PartialEq)]
struct Observed {
	boot: String,
	mount_namespace: (u64, u64),
	user_namespace: (u64, u64),
	parent: Descriptor,
	roots: [Descriptor; 2],
}

#[derive(Debug, Eq, PartialEq)]
struct Descriptor {
	identity: (u64, u64),
	mount: u64,
	unique_mount: u64,
	owner: u32,
	group: u32,
	mode: u32,
	change_time: (i64, i64),
	modified_time: (i64, i64),
}

fn observe(proc: &File, thread: &File, parent: &File, roots: [&File; 2]) -> TestResult<Observed> {
	let boot = str::from_utf8(&bounded_proc(proc, c"sys/kernel/random/boot_id", 37)?)?
		.strip_suffix('\n')
		.filter(|boot| boot.len() == 36)
		.ok_or("missing canonical boot identity")?
		.to_owned();
	let namespace = File::from(fs::openat2(thread, c"ns", DIRECTORY, Mode::empty(), CHILD)?);
	let mount_namespace = namespace_identity(&namespace, c"mnt")?;
	let user_namespace = namespace_identity(&namespace, c"user")?;
	let parent = observe_directory(parent)?;
	let roots = [observe_directory(roots[0])?, observe_directory(roots[1])?];
	if roots.iter().any(|root| {
		root.mount != parent.mount
			|| root.unique_mount != parent.unique_mount
			|| root.identity.0 != parent.identity.0
	}) || roots[0].identity == roots[1].identity
		|| roots.iter().any(|root| root.identity == parent.identity)
	{
		return Err("fixture must keep distinct directories on the one held mount".into());
	}
	confirm_ext4(thread, &parent)?;
	Ok(Observed {
		boot,
		mount_namespace,
		user_namespace,
		parent,
		roots,
	})
}

fn check_selection(selected: &SyncPreviewRoots<'_>, observed: &Observed) -> TestResult {
	let selection = selected.selection();
	if identity(selection.parent) != observed.parent.identity
		|| selection.mount_id != observed.parent.mount
		|| selection.roots.map(identity) != observed.roots.each_ref().map(|root| root.identity)
	{
		return Err("production selection disagrees with independently held directories".into());
	}
	Ok(())
}

fn check_history(
	history: &[SyncHistoryLocation<'_>; 2],
	observed: &Observed,
	names: [&CStr; 2],
) -> TestResult {
	for (side, fact) in history.iter().enumerate() {
		let mut boot = String::with_capacity(36);
		for (index, byte) in fact.boot.into_iter().enumerate() {
			if matches!(index, 4 | 6 | 8 | 10) {
				boot.push('-');
			}
			write!(boot, "{byte:02x}")?;
		}
		if boot != observed.boot
			|| fact.unique_mount.get() != observed.parent.unique_mount
			|| identity(fact.parent) != observed.parent.identity
			|| identity(fact.root) != observed.roots[side].identity
			|| identity(fact.mount_namespace) != observed.mount_namespace
			|| identity(fact.user_namespace) != observed.user_namespace
			|| fact.root_name.as_bytes() != names[side].to_bytes()
		{
			return Err("history location differs from independently held native facts".into());
		}
	}
	Ok(())
}

fn identity(identity: FileIdentity) -> (u64, u64) {
	(identity.device(), identity.inode())
}

fn native_identity(metadata: &Metadata) -> (u64, u64) {
	(metadata.dev(), metadata.ino())
}

fn open_directory(path: &Path) -> io::Result<File> {
	fs::openat2(fs::CWD, path, DIRECTORY, Mode::empty(), NO_LINKS)
		.map(File::from)
		.map_err(Into::into)
}

fn open_child(parent: &File, name: &CStr) -> io::Result<File> {
	fs::openat2(parent, name, DIRECTORY, Mode::empty(), CHILD)
		.map(File::from)
		.map_err(Into::into)
}

fn observe_directory(directory: &File) -> TestResult<Descriptor> {
	let metadata = directory.metadata()?;
	if metadata.uid() != geteuid().as_raw()
		|| metadata.mode() & 0o7777 != 0o700
		|| fs::fstatfs(directory)?.f_type != EXT_MAGIC
		|| fs::fstatvfs(directory)?
			.f_flag
			.contains(StatVfsMountFlags::RDONLY)
	{
		return Err("fixture requires an owned mode-0700 directory on writable ext4".into());
	}
	let mount = |flag: StatxFlags| -> TestResult<u64> {
		let stat = fs::statx(directory, c"", AtFlags::EMPTY_PATH, flag)?;
		if stat.stx_mask & flag.bits() == 0 || stat.stx_mnt_id == 0 {
			return Err("kernel omitted the requested descriptor mount identity".into());
		}
		Ok(stat.stx_mnt_id)
	};
	Ok(Descriptor {
		identity: native_identity(&metadata),
		mount: mount(StatxFlags::MNT_ID)?,
		unique_mount: mount(MNT_ID_UNIQUE)?,
		owner: metadata.uid(),
		group: metadata.gid(),
		mode: metadata.mode(),
		change_time: (metadata.ctime(), metadata.ctime_nsec()),
		modified_time: (metadata.mtime(), metadata.mtime_nsec()),
	})
}

fn confirm_ext4(thread: &File, parent: &Descriptor) -> TestResult {
	let mount = parent.mount.to_string();
	let device = format!(
		"{}:{}",
		fs::major(parent.identity.0),
		fs::minor(parent.identity.0)
	);
	let raw = bounded_proc(thread, c"mountinfo", MOUNTINFO_LIMIT)?;
	let mut rows = raw.split(|byte| *byte == b'\n').filter_map(|line| {
		let mut fields = line.split(|byte| *byte == b' ');
		(fields.next() == Some(mount.as_bytes())).then_some(fields)
	});
	let mut fields = rows.next().ok_or("selected ext4 mount record missing")?;
	let matching_device = fields.nth(1) == Some(device.as_bytes());
	let whole_filesystem = fields.next() == Some(b"/".as_slice());
	let writable = fields.nth(1).is_some_and(has_rw);
	let filesystem = fields
		.find(|field| *field == b"-")
		.and_then(|_| fields.next());
	let super_writable = fields.nth(1).is_some_and(has_rw);
	if !matching_device
		|| !whole_filesystem
		|| !writable
		|| !super_writable
		|| filesystem != Some(b"ext4".as_slice())
		|| rows.next().is_some()
	{
		return Err("fixture is outside the selected whole local ext4 profile".into());
	}
	Ok(())
}

fn has_rw(options: &[u8]) -> bool {
	options
		.split(|byte| *byte == b',')
		.any(|field| field == b"rw")
}

fn namespace_identity(directory: &File, name: &CStr) -> TestResult<(u64, u64)> {
	let descriptor = File::from(fs::openat(
		directory,
		name,
		OFlags::RDONLY | OFlags::CLOEXEC,
		Mode::empty(),
	)?);
	if fs::fstatfs(&descriptor)?.f_type != NSFS_MAGIC {
		return Err("held namespace link did not resolve to nsfs".into());
	}
	Ok(native_identity(&descriptor.metadata()?))
}

fn bounded_proc(parent: &File, name: &CStr, maximum: usize) -> TestResult<Vec<u8>> {
	let mut bytes = Vec::new();
	File::from(fs::openat2(
		parent,
		name,
		OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
		Mode::empty(),
		CHILD,
	)?)
	.take(u64::try_from(maximum)? + 1)
	.read_to_end(&mut bytes)?;
	if bytes.len() > maximum {
		return Err("procfs fixture observation exceeded its bound".into());
	}
	Ok(bytes)
}

fn check_unprivileged(thread: &File) -> TestResult {
	let status = bounded_proc(thread, c"status", STATUS_LIMIT)?;
	let text = str::from_utf8(&status)?;
	for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
		let mut values = text.lines().filter_map(|line| line.strip_prefix(field));
		let value = values
			.next()
			.ok_or("missing effective fixture capability facts")?;
		if values.next().is_some() || u64::from_str_radix(value.trim(), 16)? != 0 {
			return Err(
				"fixture requires zero inheritable, permitted, effective and ambient capabilities"
					.into(),
			);
		}
	}
	Ok(())
}
