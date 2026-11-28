use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_BYTES, FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_BYTES, OWNER_FILE_NAME,
	WindowsBootstrapBytes, WindowsBootstrapFileIdentity, WindowsBootstrapRoles, job_directory_name,
};
use exacopy_journal::{DurableJournal, JournalJobId};
use exacopy_platform::ProtectedSnapshotError;
use exacopy_platform::windows::{
	WindowsBootstrapFreshSegment, WindowsBootstrapLayout, WindowsBootstrapRoleKind,
	WindowsBootstrapRoleObservations, WindowsCaptureBootstrapScope, WindowsCaptureBootstrapSegment,
	WindowsComponent, WindowsStageIdentity, observe_windows_bootstrap_role_identity,
};

#[path = "fixture/capture_stage.rs"]
mod capture_stage;

const ERROR_SHARING_VIOLATION: i32 = 32;
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
	pub(super) copied_roles: WindowsBootstrapRoles,
}

pub(super) fn read_selection() -> SelectedFixture {
	let root = PathBuf::from(
		std::env::var_os("EXACOPY_WINDOWS_BOOTSTRAP_ROOT").expect("owned fixture launcher root"),
	);
	let mut units = root.as_os_str().encode_wide();
	let drive = u8::try_from(units.next().expect("fixture drive")).expect("ASCII fixture drive");
	assert!(drive.is_ascii_alphabetic() && units.next() == Some(u16::from(b':')));
	assert_eq!(units.next(), Some(u16::from(b'\\')), "absolute drive root");
	let (root_observation, roles) = read_roles("EXACOPY_WINDOWS_BOOTSTRAP_ROLE_IDS");
	let (_, copied_roles) = read_roles("EXACOPY_WINDOWS_BOOTSTRAP_COPY_ROLE_IDS");
	assert_eq!(roles.root(), copied_roles.root(), "one selected root");
	let original = [
		roles.job_directory(),
		roles.owner_file(),
		roles.journal_directory(),
		roles.first_segment(),
	];
	let copied = [
		copied_roles.job_directory(),
		copied_roles.owner_file(),
		copied_roles.journal_directory(),
		copied_roles.first_segment(),
	];
	assert!(
		original.iter().all(|id| !copied.contains(id)),
		"distinct job fixtures"
	);
	SelectedFixture {
		root,
		drive: drive.to_ascii_uppercase(),
		root_observation,
		roles,
		copied_roles,
	}
}

fn read_roles(variable: &str) -> (SelectedRoot, WindowsBootstrapRoles) {
	let material = std::env::var(variable).expect("launcher-selected five role identities");
	const ROLE_BYTES: usize = 36 + 1 + 16 + 1 + 32;
	assert_eq!(
		material.len(),
		5 * ROLE_BYTES + 4,
		"bounded five-role selection"
	);
	let identities = material.split(';').map(parse_identity).collect::<Vec<_>>();
	let [root, job, owner, journal, segment] = identities.as_slice() else {
		panic!("exactly five role identities are required")
	};
	let roles = WindowsBootstrapRoles::new(
		root.into_identity(),
		job.into_identity(),
		owner.into_identity(),
		journal.into_identity(),
		segment.into_identity(),
	)
	.expect("distinct selected roles");
	(*root, roles)
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

pub(super) enum SegmentPopulation {
	OriginalBootstrap,
	CopiedCounterexample,
}

pub(super) fn populate(
	root: &Path,
	drive: u8,
	selected_roles: WindowsBootstrapRoles,
	job: JournalJobId,
	population: SegmentPopulation,
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
		let sample = |file: &File, kind| {
			observe_windows_bootstrap_role_identity(drive, file.as_handle(), kind)
				.expect("observe original fixture role")
		};
		WindowsBootstrapRoleObservations {
			root: sample(&root_handle, Directory),
			job_directory: sample(&job_handle, Directory),
			owner_file: sample(owner, RegularFile),
			journal_directory: sample(&journal_handle, Directory),
			first_segment: sample(segment, RegularFile),
		}
	};
	let original = observe_roles(&owner, &segment);
	let roles = WindowsBootstrapRoles::new(
		identity(original.root),
		identity(original.job_directory),
		identity(original.owner_file),
		identity(original.journal_directory),
		identity(original.first_segment),
	)
	.expect("independent original five roles");
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
	owner.sync_all().expect("flush fixture owner bytes");
	match population {
		SegmentPopulation::OriginalBootstrap => {
			assert_eq!(observe_roles(&owner, &segment), original);
			drop(owner);
			drop(segment);
			append_original_prepared(root, drive, job, original, &bytes);
		}
		SegmentPopulation::CopiedCounterexample => {
			segment
				.write_all(&bytes.first_segment)
				.expect("populate the deliberately untrusted copied segment");
			segment.sync_all().expect("flush copied segment bytes");
			assert_eq!(observe_roles(&owner, &segment), original);
		}
	}
	Provisioned { roles, bytes }
}

fn append_original_prepared(
	root: &Path,
	drive: u8,
	job: JournalJobId,
	roles: WindowsBootstrapRoleObservations,
	bytes: &WindowsBootstrapBytes,
) {
	let encoded = &bytes.first_segment;
	let mut frames = FrameReader::new(encoded.as_slice(), ChainHead::start());
	let prepared = frames.next_frame().unwrap().unwrap();
	assert_eq!(prepared.kind(), FrameKind::JobPrepared);
	assert!(frames.next_frame().unwrap().is_none());

	let root_units: Vec<_> = root.as_os_str().encode_wide().collect();
	let job_name = job_directory_name(job);
	let layout = WindowsBootstrapLayout {
		job: WindowsComponent::new(&job_name).unwrap(),
		owner: WindowsComponent::new(&OWNER_FILE_NAME).unwrap(),
		journal: WindowsComponent::new(&JOURNAL_DIRECTORY_NAME).unwrap(),
		first_segment: WindowsComponent::new(&FIRST_SEGMENT_NAME).unwrap(),
		owner_bytes: OWNER_BYTES,
		first_segment_bytes: FIRST_SEGMENT_BYTES,
	};
	let different = WindowsBootstrapRoleObservations {
		first_segment: roles.owner_file,
		..roles
	};
	assert!(matches!(
		WindowsBootstrapFreshSegment::open_provisioned(&root_units, different, layout),
		Err(ProtectedSnapshotError::Changed)
	));
	drop(
		WindowsBootstrapFreshSegment::open_provisioned(&root_units, roles, layout)
			.expect("legacy acquisition still admits the original empty segment"),
	);
	let open_capture =
		|| WindowsCaptureBootstrapScope::open_provisioned(&root_units, roles, layout);
	let mut wrong_owner = bytes.owner;
	wrong_owner[0] ^= 1;
	assert!(matches!(
		open_capture().unwrap().append_first_segment(&wrong_owner, encoded, |_| {
			panic!("a mismatched original owner reached bootstrap append")
		}),
		Err(error) if error.kind() == io::ErrorKind::InvalidData
	));
	assert!(matches!(
		open_capture().unwrap().append_first_segment(&bytes.owner, encoded, |_| Ok(())),
		Err(error) if error.kind() == io::ErrorKind::InvalidData
	));
	assert_eq!(
		std::fs::metadata(first_segment_path(root, job))
			.unwrap()
			.len(),
		0
	);
	let original = open_capture().expect("admit the exact original empty segment for capture");
	assert!(matches!(open_capture(), Err(ProtectedSnapshotError::Busy)));
	let capture = original
		.append_first_segment(&bytes.owner, encoded, |segment| {
			append_prepared(segment, &prepared)
		})
		.expect("confirm canonical first frame on the original held segment");
	let selected_segment = first_segment_path(root, job);
	assert_segment_exclusive(&selected_segment);
	capture_stage::check(&capture, root, drive, job);
	assert_segment_exclusive(&selected_segment);
	drop(capture);
	assert_eq!(std::fs::read(selected_segment).unwrap(), encoded);
	assert!(matches!(
		WindowsBootstrapFreshSegment::open_provisioned(&root_units, roles, layout),
		Err(ProtectedSnapshotError::Changed)
	));
}

fn assert_segment_exclusive(path: &Path) {
	assert_eq!(
		OpenOptions::new()
			.read(true)
			.share_mode(FILE_SHARE_READ_WRITE)
			.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
			.open(path)
			.unwrap_err()
			.raw_os_error(),
		Some(ERROR_SHARING_VIOLATION)
	);
}

fn append_prepared(
	mut segment: WindowsCaptureBootstrapSegment<'_, '_>,
	prepared: &exacopy_journal::frame::Frame,
) -> io::Result<()> {
	assert_eq!(
		segment.seek(SeekFrom::Start(1)).unwrap_err().kind(),
		io::ErrorKind::InvalidInput
	);
	assert_eq!(
		segment
			.write(&[0; FIRST_SEGMENT_BYTES + 1])
			.unwrap_err()
			.kind(),
		io::ErrorKind::InvalidInput
	);
	let mut journal = DurableJournal::from_new_segment(segment).map_err(io::Error::other)?;
	let written = journal
		.append(FrameKind::JobPrepared, prepared.payload())
		.map_err(io::Error::other)?;
	assert_eq!(written.head(), prepared.head());
	journal
		.confirm_current_frame(&written)
		.map_err(io::Error::other)
}

pub(super) fn first_segment_path(root: &Path, job: JournalJobId) -> PathBuf {
	root.join(OsString::from_wide(&job_directory_name(job)))
		.join(OsString::from_wide(&JOURNAL_DIRECTORY_NAME))
		.join(OsString::from_wide(&FIRST_SEGMENT_NAME))
}

pub(super) fn confirm_two_link_names(
	drive: u8,
	expected: WindowsBootstrapFileIdentity,
	original: &Path,
	link: &Path,
) {
	let pin = |path| {
		OpenOptions::new()
			.read(true)
			.share_mode(FILE_SHARE_READ_WRITE)
			.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
			.open(path)
			.expect("hold one owned link name")
	};
	let original = pin(original);
	let link = pin(link);
	assert_eq!(
		observe(drive, &original, WindowsBootstrapRoleKind::RegularFile),
		expected
	);
	assert_eq!(
		observe(drive, &link, WindowsBootstrapRoleKind::RegularFile),
		expected
	);
}
