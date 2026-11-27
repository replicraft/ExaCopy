use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};

use exacopy_journal::JournalJobId;
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_FILE_NAME, WindowsBootstrapBytes,
	WindowsBootstrapFileIdentity, WindowsBootstrapRoles, job_directory_name,
};
use exacopy_platform::windows::{
	WindowsBootstrapRoleKind, WindowsStageIdentity, observe_windows_bootstrap_role_identity,
};

const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Clone, Copy)]
pub(super) struct SelectedRoot {
	pub(super) guid: [u8; 36],
	pub(super) serial: u64,
	pub(super) file_id: [u8; 16],
}

impl SelectedRoot {
	pub(super) fn into_identity(self) -> WindowsBootstrapFileIdentity {
		WindowsBootstrapFileIdentity::new(self.guid, self.serial, self.file_id)
			.expect("valid independently retained root identity")
	}
}

pub(super) struct SelectedFixture {
	pub(super) root: PathBuf,
	pub(super) drive: u8,
	pub(super) root_observation: SelectedRoot,
	pub(super) roles: WindowsBootstrapRoles,
}

pub(super) fn read_selection() -> SelectedFixture {
	let root = PathBuf::from(
		std::env::var_os("EXACOPY_WINDOWS_BOOTSTRAP_ROOT").expect("owned fixture launcher root"),
	);
	let mut units = root.as_os_str().encode_wide();
	let drive = u8::try_from(units.next().expect("fixture drive")).expect("ASCII fixture drive");
	assert!(drive.is_ascii_alphabetic() && units.next() == Some(u16::from(b':')));
	assert_eq!(units.next(), Some(u16::from(b'\\')), "absolute drive root");
	let material =
		std::env::var("EXACOPY_WINDOWS_BOOTSTRAP_ROLE_IDS").expect("original five role identities");
	const ROLE_BYTES: usize = 36 + 1 + 16 + 1 + 32;
	assert_eq!(
		material.len(),
		5 * ROLE_BYTES + 4,
		"bounded five-role selection"
	);
	let identities = material.split(';').map(parse_identity).collect::<Vec<_>>();
	let [root_observation, job, owner, journal, segment] = identities.as_slice() else {
		panic!("exactly five original role identities are required")
	};
	let roles = WindowsBootstrapRoles::new(
		root_observation.into_identity(),
		job.into_identity(),
		owner.into_identity(),
		journal.into_identity(),
		segment.into_identity(),
	)
	.expect("distinct selected original roles");
	SelectedFixture {
		root,
		drive: drive.to_ascii_uppercase(),
		root_observation: *root_observation,
		roles,
	}
}

fn parse_identity(material: &str) -> SelectedRoot {
	let mut fields = material.split('/');
	let guid = fields
		.next()
		.expect("volume GUID")
		.as_bytes()
		.try_into()
		.expect("36-byte canonical GUID");
	let serial_hex = fields.next().expect("volume serial");
	assert_eq!(serial_hex.len(), 16);
	let serial = u64::from_str_radix(serial_hex, 16).expect("full unsigned volume serial");
	let file_hex = fields.next().expect("file ID").as_bytes();
	assert_eq!(file_hex.len(), 32);
	assert!(fields.next().is_none(), "exact fixture identity fields");
	let file_id = std::array::from_fn(|index| {
		let digits =
			std::str::from_utf8(&file_hex[2 * index..2 * index + 2]).expect("ASCII file ID");
		u8::from_str_radix(digits, 16).expect("opaque file ID byte")
	});
	SelectedRoot {
		guid,
		serial,
		file_id,
	}
}

pub(super) fn identity(observed: WindowsStageIdentity) -> WindowsBootstrapFileIdentity {
	WindowsBootstrapFileIdentity::new(
		observed.volume_guid(),
		observed.volume_serial(),
		observed.file_id(),
	)
	.expect("lossless checked native identity")
}

fn observe(drive: u8, file: &File, kind: WindowsBootstrapRoleKind) -> WindowsBootstrapFileIdentity {
	identity(
		observe_windows_bootstrap_role_identity(drive, file.as_handle(), kind)
			.expect("observe exact original fixture object"),
	)
}

fn directory(path: &Path) -> File {
	OpenOptions::new()
		.read(true)
		.share_mode(FILE_SHARE_READ_WRITE)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.expect("hold original fixture directory")
}

fn open_empty_record(path: &Path) -> File {
	OpenOptions::new()
		.read(true)
		.write(true)
		.share_mode(0)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.expect("open selected original fixture record")
}

pub(super) struct Provisioned {
	pub(super) roles: WindowsBootstrapRoles,
	pub(super) bytes: WindowsBootstrapBytes,
}

pub(super) fn populate(
	root: &Path,
	drive: u8,
	selected_roles: WindowsBootstrapRoles,
	job: JournalJobId,
	sign: impl FnOnce(WindowsBootstrapRoles) -> WindowsBootstrapBytes,
) -> Provisioned {
	use WindowsBootstrapRoleKind::{Directory, RegularFile};

	// Only the owned launcher can select and hold the fresh, one-principal
	// container. No signed field or arbitrary path supplied by a record is used.
	let root_handle = directory(root);
	assert_eq!(
		observe(drive, &root_handle, Directory),
		selected_roles.root()
	);
	let job_path = root.join(OsString::from_wide(&job_directory_name(job)));
	let job_handle = directory(&job_path);
	assert_eq!(
		observe(drive, &job_handle, Directory),
		selected_roles.job_directory()
	);
	let journal_path = job_path.join(OsString::from_wide(&JOURNAL_DIRECTORY_NAME));
	let journal_handle = directory(&journal_path);
	assert_eq!(
		observe(drive, &journal_handle, Directory),
		selected_roles.journal_directory()
	);
	let mut owner = open_empty_record(&job_path.join(OsString::from_wide(&OWNER_FILE_NAME)));
	let mut segment =
		open_empty_record(&journal_path.join(OsString::from_wide(&FIRST_SEGMENT_NAME)));
	let observe_roles = |owner: &File, segment: &File| {
		WindowsBootstrapRoles::new(
			observe(drive, &root_handle, Directory),
			observe(drive, &job_handle, Directory),
			observe(drive, owner, RegularFile),
			observe(drive, &journal_handle, Directory),
			observe(drive, segment, RegularFile),
		)
		.expect("independent original five roles")
	};
	let roles = observe_roles(&owner, &segment);
	assert_eq!(roles, selected_roles);
	assert_eq!(owner.metadata().expect("original owner extent").len(), 0);
	assert_eq!(
		segment.metadata().expect("original segment extent").len(),
		0
	);
	let bytes = sign(roles);

	owner
		.write_all(&bytes.owner)
		.expect("populate original owner file");
	segment
		.write_all(&bytes.first_segment)
		.expect("populate original segment");
	owner.sync_all().expect("flush fixture owner bytes");
	segment.sync_all().expect("flush fixture segment bytes");
	assert_eq!(observe_roles(&owner, &segment), roles);
	drop(owner);
	drop(segment);
	Provisioned { roles, bytes }
}
