//! Hosted native controls for the read-only Linux historical scope seam.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::ffi::{CStr, OsStr};
use std::fs::{self, File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::{Path, PathBuf};

use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_platform::linux::{
	FileIdentity, MountObservations, ReadRoot, SyncHistoryDirectory, SyncPreviewEntry,
	SyncPreviewError, SyncPreviewRoots,
};
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, StatVfsMountFlags, StatxFlags};
use rustix::process::{geteuid, getuid};

const PARENT: &str = "EXACOPY_SYNC_HISTORY_EXT4_PARENT";
const LEFT: &[u8] = b"left-\xff";
const RIGHT: &[u8] = b"right-\xfe";
const SUBJECT: &[u8] = b"subject-\xfd";
const MEMBER: &[u8] = b"member-\xfc";
const LEFT_BYTES: &[u8] = b"left native fixture";
const RIGHT_BYTES: &[u8] = b"right native fixture";
const ARTIFACT: &[u8; 5] = b"bound";
const STATUS_LIMIT: usize = 64 * 1024;
const MOUNTINFO_LIMIT: usize = 1024 * 1024;
const NSFS_MAGIC: rustix::fs::FsWord = 0x6e73_6673;
const EXT_MAGIC: rustix::fs::FsWord = 0xef53;
const STATX_MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);
const BELOW_PROC: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_XDEV)
	.union(ResolveFlags::NO_MAGICLINKS);
const NO_LINKS: ResolveFlags = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
#[ignore = "requires an explicitly selected unprivileged whole-local-ext4 fixture parent"]
fn held_ext4_history_scope_and_named_members_refuse_aliases_and_swaps() -> TestResult {
	let proc = open_verified_proc()?;
	let thread = open_at(
		&proc,
		c"thread-self",
		DIRECTORY_FLAGS.difference(OFlags::NOFOLLOW),
		BELOW_PROC,
	)?;
	let parent = selected_parent(&thread)?;
	let fixture = Fixture::create(&parent, &thread)?;
	let observations = run_fixture(&fixture, &proc, &thread);
	fixture.finish()?;
	let observed = observations?;
	println!(
		"\nEXACOPY_SYNC_HISTORY_EXT4_RESULT schema_version=1 boot={} mount_namespace={}:{} user_namespace={}:{} mount={} unique_mount={} parent={}:{} left={}:{} right={}:{} cleanup=verified_absent",
		observed.boot,
		observed.mount_namespace.0,
		observed.mount_namespace.1,
		observed.user_namespace.0,
		observed.user_namespace.1,
		observed.mount,
		observed.unique_mount,
		observed.parent.0,
		observed.parent.1,
		observed.roots[0].0,
		observed.roots[0].1,
		observed.roots[1].0,
		observed.roots[1].1,
	);
	Ok(())
}

fn selected_parent(thread: &File) -> TestResult<PathBuf> {
	let parent = PathBuf::from(std::env::var_os(PARENT).ok_or("missing approved ext4 parent")?);
	if !parent.is_absolute()
		|| parent.as_os_str() != parent.canonicalize()?.as_os_str()
		|| getuid().is_root()
		|| getuid() != geteuid()
	{
		return Err("requires a canonical absolute parent and an unprivileged invocation".into());
	}
	let status = bounded_proc(thread, c"status", STATUS_LIMIT)?;
	let text = str::from_utf8(&status)?;
	for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
		let prefix = format!("{field}:");
		let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
		let Some(value) = values.next() else {
			return Err("current-thread capability status unavailable".into());
		};
		if values.next().is_some() || u64::from_str_radix(value.trim(), 16)? != 0 {
			return Err(
				"fixture requires zero inheritable, permitted, effective and ambient capabilities"
					.into(),
			);
		}
	}
	Ok(parent)
}

fn open_directory(path: &Path) -> io::Result<File> {
	open_at(rustix::fs::CWD, path, DIRECTORY_FLAGS, NO_LINKS)
}

fn whole_ext4(directory: &File, thread: &File) -> TestResult<u64> {
	let table = MountObservations::capture()?;
	let mount = table.whole_filesystem_mount(directory)?;
	let raw = bounded_proc(thread, c"mountinfo", MOUNTINFO_LIMIT)?;
	let mount_text = mount.to_string();
	let mut matches = raw
		.split(|byte| *byte == b'\n')
		.filter(|row| row.split(|byte| *byte == b' ').next() == Some(mount_text.as_bytes()));
	let Some(row) = matches.next() else {
		return Err("selected mount is absent from current mountinfo".into());
	};
	let mut fields = row.split(|byte| *byte == b' ');
	let whole_root = fields.nth(3) == Some(b"/".as_slice());
	let filesystem = fields
		.find(|field| *field == b"-")
		.and_then(|_| fields.next());
	if matches.next().is_some()
		|| !whole_root
		|| filesystem != Some(b"ext4".as_slice())
		|| rustix::fs::fstatfs(directory)?.f_type != EXT_MAGIC
		|| rustix::fs::fstatvfs(directory)?
			.f_flag
			.contains(StatVfsMountFlags::RDONLY)
	{
		return Err(
			"selected directory is outside the admitted whole local ext4 fixture profile".into(),
		);
	}
	Ok(mount)
}

fn open_verified_proc() -> TestResult<File> {
	let proc = open_directory(Path::new("/proc"))?;
	if rustix::fs::fstatfs(&proc)?.f_type != rustix::fs::PROC_SUPER_MAGIC
		|| proc.metadata()?.ino() != 1
	{
		return Err("expected the verified procfs root".into());
	}
	Ok(proc)
}

fn open_at(
	parent: impl std::os::fd::AsFd,
	name: impl rustix::path::Arg,
	flags: OFlags,
	resolve: ResolveFlags,
) -> io::Result<File> {
	rustix::fs::openat2(parent, name, flags, Mode::empty(), resolve)
		.map(File::from)
		.map_err(Into::into)
}

fn bounded_proc(parent: &File, name: &CStr, maximum: usize) -> TestResult<Vec<u8>> {
	let mut bytes = Vec::new();
	open_at(
		parent,
		name,
		OFlags::RDONLY | OFlags::CLOEXEC,
		BELOW_PROC | NO_LINKS,
	)?
	.take(u64::try_from(maximum)? + 1)
	.read_to_end(&mut bytes)?;
	if bytes.len() > maximum {
		return Err("independent procfs observation exceeded its bound".into());
	}
	Ok(bytes)
}

type Identity = (u64, u64);
struct LiveFacts {
	boot: String,
	mount_namespace: Identity,
	user_namespace: Identity,
	mount: u64,
	unique_mount: u64,
	parent: Identity,
	roots: [Identity; 2],
}

fn run_fixture(fixture: &Fixture, proc: &File, thread: &File) -> TestResult<LiveFacts> {
	let left = fixture.path.join(OsStr::from_bytes(LEFT));
	let right = fixture.path.join(OsStr::from_bytes(RIGHT));
	let artifacts = fixture.path.join("artifacts");
	for directory in [&left, &right, &artifacts] {
		fs::create_dir(directory)?;
	}
	let leaf = OsStr::from_bytes(SUBJECT);
	let left_file = left.join(leaf);
	let right_file = right.join(leaf);
	fs::write(&left_file, LEFT_BYTES)?;
	fs::write(&right_file, RIGHT_BYTES)?;
	symlink(OsStr::from_bytes(LEFT), fixture.path.join("root-alias"))?;
	fs::write(left.join("unselected"), b"left noise")?;
	fs::write(right.join("unselected"), b"right noise")?;

	let roots = SyncPreviewRoots::open(&fixture.path, [component(LEFT), component(RIGHT)])?;
	let pair = roots.observe(component(SUBJECT))?;
	for (entry, expected) in pair.entries().into_iter().zip([LEFT_BYTES, RIGHT_BYTES]) {
		let SyncPreviewEntry::Present(view) = entry else {
			return Err("fixture subject must be present on both sides".into());
		};
		let mut observed = vec![0; expected.len()];
		assert_eq!(view.length(), u64::try_from(expected.len())?);
		view.read_exact_at(0, &mut observed)?;
		assert_eq!(observed, expected);
	}

	let (subject, [left_fact, right_fact]) = pair.recheck_history_location()?;
	assert_eq!(subject.as_bytes(), SUBJECT);
	assert_eq!(left_fact.root_name.as_bytes(), LEFT);
	assert_eq!(right_fact.root_name.as_bytes(), RIGHT);
	for (fact, path) in [(left_fact, &left), (right_fact, &right)] {
		assert_eq!(
			observed_identity(fact.root),
			identity(&open_directory(path)?.metadata()?)
		);
	}
	assert_ne!(left_fact.root, right_fact.root);
	let parent_identity = identity(&fixture.directory.metadata()?);

	let boot = format_boot(left_fact.boot);
	let mut boot_line = boot.as_bytes().to_vec();
	boot_line.push(b'\n');
	assert_eq!(
		bounded_proc(proc, c"sys/kernel/random/boot_id", 37)?,
		boot_line
	);
	let namespace_dir = open_at(thread, c"ns", DIRECTORY_FLAGS, BELOW_PROC | NO_LINKS)?;
	// Only the two fixed kernel namespace links may be followed under this held directory.
	let observe_namespace = |name: &CStr| {
		rustix::fs::openat(
			&namespace_dir,
			name,
			OFlags::RDONLY | OFlags::CLOEXEC,
			Mode::empty(),
		)
		.map(File::from)
	};
	let held_mount_namespace = observe_namespace(c"mnt")?;
	let held_user_namespace = observe_namespace(c"user")?;
	for namespace in [&held_mount_namespace, &held_user_namespace] {
		assert_eq!(rustix::fs::fstatfs(namespace)?.f_type, NSFS_MAGIC);
	}
	let mount_namespace = identity(&held_mount_namespace.metadata()?);
	let user_namespace = identity(&held_user_namespace.metadata()?);
	assert_ne!(mount_namespace, user_namespace);
	let mount = whole_ext4(&fixture.directory, thread)?;
	let unique = unique_mount(&fixture.directory)?;
	assert_eq!(roots.selection().mount_id, mount);
	for fact in [left_fact, right_fact] {
		assert_eq!(fact.boot, left_fact.boot);
		assert_eq!(observed_identity(fact.parent), parent_identity);
		assert_ne!(observed_identity(fact.root), parent_identity);
		assert_eq!(observed_identity(fact.mount_namespace), mount_namespace);
		assert_eq!(observed_identity(fact.user_namespace), user_namespace);
		assert_eq!(fact.unique_mount.get(), unique);
	}
	assert_eq!(unique_mount(&open_directory(&left)?)?, unique);
	assert_eq!(unique_mount(&open_directory(&right)?)?, unique);
	assert_eq!(
		pair.recheck_history_location()?,
		(subject, [left_fact, right_fact])
	);

	assert!(matches!(
		SyncPreviewRoots::open(&fixture.path, [component(LEFT), component(LEFT)]),
		Err(SyncPreviewError::AliasedRoots)
	));
	assert!(
		SyncPreviewRoots::open(&fixture.path, [component(b"root-alias"), component(RIGHT)])
			.is_err()
	);

	member_controls(&artifacts)?;
	let retained = right.join("retained-subject");
	fs::rename(&right_file, &retained)?;
	fs::hard_link(&left_file, &right_file)?;
	assert!(
		pair.recheck_history_location().is_err(),
		"stale subject must refuse"
	);
	assert!(matches!(
		roots.observe(component(SUBJECT)),
		Err(SyncPreviewError::AliasedFiles)
	));
	assert_eq!(fs::read(&retained)?, RIGHT_BYTES);
	fs::remove_file(&right_file)?;
	fs::rename(&retained, &right_file)?;

	let current = roots.observe(component(SUBJECT))?;
	current.recheck_history_location()?;
	let spare = fixture.path.join("swap-temporary");
	fs::rename(&left, &spare)?;
	fs::rename(&right, &left)?;
	fs::rename(&spare, &right)?;
	assert!(matches!(
		current.recheck_history_location(),
		Err(SyncPreviewError::Changed)
	));
	let swapped = SyncPreviewRoots::open(&fixture.path, [component(LEFT), component(RIGHT)])?;
	let swapped_pair = swapped.observe(component(SUBJECT))?;
	let (_, [swapped_left, swapped_right]) = swapped_pair.recheck_history_location()?;
	assert_eq!(swapped_left.root, right_fact.root);
	assert_eq!(swapped_right.root, left_fact.root);
	assert_eq!(fs::read(left_file)?, RIGHT_BYTES);
	assert_eq!(fs::read(right_file)?, LEFT_BYTES);
	assert_eq!(fs::read(left.join("unselected"))?, b"right noise");
	assert_eq!(fs::read(right.join("unselected"))?, b"left noise");
	Ok(LiveFacts {
		boot,
		mount_namespace,
		user_namespace,
		mount,
		unique_mount: unique,
		parent: parent_identity,
		roots: [
			observed_identity(left_fact.root),
			observed_identity(right_fact.root),
		],
	})
}

fn member_controls(path: &Path) -> TestResult {
	let member = path.join(OsStr::from_bytes(MEMBER));
	let retained = path.join("retained-member");
	let other = path.join("unselected-member");
	fs::write(&member, ARTIFACT)?;
	fs::write(&other, b"noise")?;
	symlink(OsStr::from_bytes(MEMBER), path.join("member-alias"))?;
	let root = ReadRoot::from_directory(open_directory(path)?)?;
	let directory = SyncHistoryDirectory::new(&root, 5);
	assert_eq!(
		directory
			.open_member(component(b"missing"))
			.unwrap_err()
			.kind(),
		io::ErrorKind::NotFound
	);
	assert!(directory.open_member(component(b"member-alias")).is_err());
	assert!(
		SyncHistoryDirectory::new(&root, 4)
			.open_member(component(MEMBER))
			.is_err()
	);
	let mut reader = directory.open_member(component(MEMBER))?;
	let mut bytes = [0; ARTIFACT.len()];
	reader.read_exact(&mut bytes)?;
	assert_eq!(&bytes, ARTIFACT);
	assert_eq!(
		reader.read(&mut [0; 1])?,
		0,
		"exact EOF under the original name"
	);

	let mut stale = directory.open_member(component(MEMBER))?;
	stale.read_exact(&mut bytes)?;
	fs::rename(&member, &retained)?;
	fs::write(&member, ARTIFACT)?;
	assert!(
		stale.read(&mut [0; 1]).is_err(),
		"equal bytes at a changed name are insufficient"
	);
	assert_ne!(
		identity(&fs::metadata(&member)?),
		identity(&fs::metadata(&retained)?)
	);
	assert_eq!(fs::read(&retained)?, ARTIFACT);
	assert_eq!(fs::read(&other)?, b"noise");
	Ok(())
}

fn unique_mount(directory: &File) -> TestResult<u64> {
	let observed = rustix::fs::statx(directory, c"", AtFlags::EMPTY_PATH, STATX_MNT_ID_UNIQUE)?;
	if observed.stx_mask & STATX_MNT_ID_UNIQUE.bits() == 0 || observed.stx_mnt_id == 0 {
		return Err("kernel did not supply an exact unique mount identity".into());
	}
	Ok(observed.stx_mnt_id)
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("fixed fixture component is valid")
}

fn identity(metadata: &Metadata) -> Identity {
	(metadata.dev(), metadata.ino())
}

fn observed_identity(native: FileIdentity) -> Identity {
	(native.device(), native.inode())
}

fn format_boot(boot: [u8; 16]) -> String {
	use std::fmt::Write as _;

	let mut text = String::with_capacity(36);
	for (index, byte) in boot.into_iter().enumerate() {
		if matches!(index, 4 | 6 | 8 | 10) {
			text.push('-');
		}
		write!(text, "{byte:02x}").expect("format fixed boot ID");
	}
	text
}

struct Fixture {
	parent: File,
	directory: File,
	path: PathBuf,
	name: String,
	finished: bool,
}

impl Fixture {
	fn create(parent_path: &Path, thread: &File) -> TestResult<Self> {
		let parent = open_directory(parent_path)?;
		let metadata = parent.metadata()?;
		if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
			return Err("fixture parent must be owned and mode 0700".into());
		}
		whole_ext4(&parent, thread)?;
		unique_mount(&parent)?;
		let name = format!(".exacopy-sync-history-ext4-{}", std::process::id());
		rustix::fs::mkdirat(&parent, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
		let directory = rustix::fs::openat2(
			&parent,
			name.as_str(),
			DIRECTORY_FLAGS,
			Mode::empty(),
			NO_LINKS | ResolveFlags::BENEATH | ResolveFlags::NO_XDEV,
		)
		.map(File::from)
		.map_err(|error| {
			io::Error::other(format!(
				"cannot pin newly created fixture {name}; retained for cleanup review: {error}"
			))
		})?;
		let fixture = Self {
			parent,
			directory,
			path: parent_path.join(&name),
			name,
			finished: false,
		};
		fixture.check_custody()?;
		Ok(fixture)
	}

	fn check_custody(&self) -> TestResult {
		let held_metadata = self.directory.metadata()?;
		let stamp = identity(&held_metadata);
		let named =
			rustix::fs::statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
		let path_metadata = fs::symlink_metadata(&self.path)?;
		if !path_metadata.is_dir()
			|| identity(&path_metadata) != stamp
			|| (named.st_dev, named.st_ino) != stamp
			|| held_metadata.uid() != geteuid().as_raw()
			|| held_metadata.mode() & 0o7777 != 0o700
		{
			return Err("fixture name or custody changed; retain directory".into());
		}
		Ok(())
	}

	fn cleanup(&self) -> TestResult {
		self.check_custody()?;
		fs::remove_dir_all(&self.path)?;
		match rustix::fs::statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
			Err(rustix::io::Errno::NOENT) => Ok(()),
			_ => Err("fixture cleanup could not establish absence".into()),
		}
	}

	fn finish(mut self) -> TestResult {
		self.finished = true;
		self.cleanup()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		if !self.finished
			&& let Err(error) = self.cleanup()
		{
			eprintln!("owned sync history fixture retained: {error}");
		}
	}
}
