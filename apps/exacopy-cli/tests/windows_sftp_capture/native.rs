use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_BYTES, FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_BYTES, OWNER_FILE_NAME,
	WindowsBootstrapBytes, WindowsBootstrapEvidence, WindowsBootstrapFileIdentity as Identity,
	WindowsBootstrapOwner, WindowsBootstrapRoles, WindowsBootstrapSelection, inspect,
	job_directory_name, sign,
};
use exacopy_journal::{JournalJobId, OwnerProfileId, OwnerToken};
use exacopy_platform::windows::{
	WindowsBootstrapLayout, WindowsBootstrapRecords, WindowsBootstrapRoleKind,
	WindowsBootstrapRoleKind::{Directory, RegularFile},
	WindowsBootstrapRoleObservations, WindowsBootstrapRootSelection, WindowsComponent,
	WindowsStageIdentity, observe_windows_bootstrap_role_identity,
};

const NO_REPARSE: u32 = 0x0020_0000;
const DIRECTORY_OPEN: u32 = 0x0200_0000;
const SHARE_READ_WRITE: u32 = 3;
const ATTRIBUTE_ACCESS: u32 = 0x80;
pub(super) const OCCUPIED: &[u8] = b"retained occupied sibling";
pub(super) const INCUMBENT: &[u8] = b"retained existing target";

pub(super) fn identity(native: WindowsStageIdentity) -> Identity {
	Identity::new(
		native.volume_guid(),
		native.volume_serial(),
		native.file_id(),
	)
	.unwrap()
}

fn identities(roles: WindowsBootstrapRoleObservations) -> WindowsBootstrapRoles {
	WindowsBootstrapRoles::new(
		identity(roles.root),
		identity(roles.job_directory),
		identity(roles.owner_file),
		identity(roles.journal_directory),
		identity(roles.first_segment),
	)
	.unwrap()
}

fn parse_identity(encoded: &str) -> Identity {
	let mut fields = encoded.split('/');
	let guid = fields.next().unwrap().as_bytes().try_into().unwrap();
	let serial = fields.next().unwrap();
	let file = fields.next().unwrap().as_bytes();
	assert!(fields.next().is_none());
	assert_eq!(serial.len(), 16);
	assert_eq!(file.len(), 32);
	let file_id = std::array::from_fn(|i| {
		u8::from_str_radix(std::str::from_utf8(&file[i * 2..i * 2 + 2]).unwrap(), 16).unwrap()
	});
	Identity::new(guid, u64::from_str_radix(serial, 16).unwrap(), file_id).unwrap()
}

fn chosen(variable: &str) -> [Identity; 6] {
	let selection = std::env::var(variable).expect("independent launcher role selection");
	assert_eq!(selection.len(), 6 * (36 + 1 + 16 + 1 + 32) + 5);
	selection
		.split(';')
		.map(parse_identity)
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

pub(super) struct Fixture {
	pub(super) root: PathBuf,
	drive: u8,
	empty: [Identity; 6],
	occupied: [Identity; 6],
}

impl Fixture {
	pub(super) fn select() -> Self {
		let root = PathBuf::from(std::env::var_os("EXACOPY_WINDOWS_SFTP_CAPTURE_ROOT").unwrap());
		let [drive, colon, slash, ..] = root.as_os_str().encode_wide().collect::<Vec<_>>()[..]
		else {
			panic!("expected absolute owned drive path");
		};
		let drive = u8::try_from(drive).unwrap();
		assert!(drive.is_ascii_alphabetic());
		assert_eq!((colon, slash), (u16::from(b':'), u16::from(b'\\')));
		let empty = chosen("EXACOPY_WINDOWS_SFTP_CAPTURE_EMPTY_ROLES");
		let occupied = chosen("EXACOPY_WINDOWS_SFTP_CAPTURE_OCCUPIED_ROLES");
		assert_eq!(empty[0], occupied[0]);
		assert!(empty[1..].iter().all(|id| !occupied[1..].contains(id)));
		for roles in [&empty, &occupied] {
			for (index, role) in roles.iter().enumerate() {
				assert_eq!(role.volume_guid(), roles[0].volume_guid());
				assert_eq!(role.volume_serial(), roles[0].volume_serial());
				assert!(!roles[..index].contains(role));
			}
		}
		Self {
			root,
			drive: drive.to_ascii_uppercase(),
			empty,
			occupied,
		}
	}

	pub(super) fn observe(
		&self,
		handle: &File,
		kind: WindowsBootstrapRoleKind,
	) -> WindowsStageIdentity {
		observe_windows_bootstrap_role_identity(self.drive, handle.as_handle(), kind).unwrap()
	}

	pub(super) fn populate(&self, occupied: bool, key: &SigningKey) -> Job {
		let row = if occupied { 2 } else { 1 };
		let selected = if occupied { self.occupied } else { self.empty };
		let job = JournalJobId::from_bytes([
			0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, row,
		])
		.unwrap();
		let profile = OwnerProfileId::from_bytes([0x49; 16]).unwrap();
		let path = self
			.root
			.join(OsString::from_wide(&job_directory_name(job)));
		let journal = path.join(OsString::from_wide(&JOURNAL_DIRECTORY_NAME));
		let owner = path.join(OsString::from_wide(&OWNER_FILE_NAME));
		let first = journal.join(OsString::from_wide(&FIRST_SEGMENT_NAME));
		let sibling = journal.join("capture-v1.exajnl");
		let root_handle = metadata(&self.root, true);
		let job_handle = metadata(&path, true);
		let journal_handle = metadata(&journal, true);
		let mut owner_handle = OpenOptions::new()
			.read(true)
			.write(true)
			.share_mode(0)
			.custom_flags(NO_REPARSE)
			.open(&owner)
			.unwrap();
		let first_handle = reader(&first);
		let sibling_handle = reader(&sibling);
		let roles = WindowsBootstrapRoleObservations {
			root: self.observe(&root_handle, Directory),
			job_directory: self.observe(&job_handle, Directory),
			owner_file: self.observe(&owner_handle, RegularFile),
			journal_directory: self.observe(&journal_handle, Directory),
			first_segment: self.observe(&first_handle, RegularFile),
		};
		let records = identities(roles);
		let sibling_id = self.observe(&sibling_handle, RegularFile);
		assert_eq!(
			[
				records.root(),
				records.job_directory(),
				records.owner_file(),
				records.journal_directory(),
				records.first_segment(),
				identity(sibling_id)
			],
			selected
		);
		assert_eq!(owner_handle.metadata().unwrap().len(), 0);
		assert_eq!(first_handle.metadata().unwrap().len(), 0);
		assert_eq!(
			bounded_bytes(&sibling_handle, OCCUPIED.len()),
			if occupied { OCCUPIED } else { &[] }
		);
		let bytes = sign(
			&WindowsBootstrapOwner {
				profile,
				job,
				token: OwnerToken::from_bytes([0x80 + row; 16]).unwrap(),
				roles: records,
			},
			key,
		)
		.unwrap();
		owner_handle.write_all(&bytes.owner).unwrap();
		owner_handle.sync_all().unwrap();
		assert_eq!(self.observe(&owner_handle, RegularFile), roles.owner_file);
		let historical = inspect(
			&bytes.owner,
			bytes.first_segment.as_slice(),
			&WindowsBootstrapSelection {
				root: records.root(),
				job,
				profile,
				key: &key.verifying_key(),
			},
			records,
		)
		.unwrap();
		Job {
			path,
			first,
			owner,
			sibling,
			profile,
			job,
			roles,
			sibling_id,
			bytes,
			historical,
		}
	}

	pub(super) fn inspect_bootstrap(
		&self,
		job: &Job,
		key: &VerifyingKey,
	) -> WindowsBootstrapEvidence {
		let path: Vec<_> = self.root.as_os_str().encode_wide().collect();
		let root = identity(job.roles.root);
		let name = job_directory_name(job.job);
		let mut records = WindowsBootstrapRecords::open(
			&path,
			WindowsBootstrapRootSelection {
				volume_guid: *root.volume_guid(),
				volume_serial: root.volume_serial(),
				file_id: *root.file_id(),
			},
			WindowsBootstrapLayout {
				job: WindowsComponent::new(&name).unwrap(),
				owner: WindowsComponent::new(&OWNER_FILE_NAME).unwrap(),
				journal: WindowsComponent::new(&JOURNAL_DIRECTORY_NAME).unwrap(),
				first_segment: WindowsComponent::new(&FIRST_SEGMENT_NAME).unwrap(),
				owner_bytes: OWNER_BYTES,
				first_segment_bytes: FIRST_SEGMENT_BYTES,
			},
		)
		.unwrap();
		let original = identities(records.roles());
		assert_eq!(original, identities(job.roles));
		let owner = records.read_owner().unwrap();
		assert_eq!(owner.as_slice(), &job.bytes.owner);
		let mut segment = records.first_segment();
		let historical = inspect(&owner, &mut segment, &job.select(key), original).unwrap();
		segment.finish().unwrap();
		assert_eq!(historical.boundary(), job.historical.boundary());
		assert_eq!(
			historical.boundary().end_offset(),
			FIRST_SEGMENT_BYTES as u64
		);
		historical
	}

	pub(super) fn observe_record_extent(
		&self,
		path: &Path,
		expected: WindowsStageIdentity,
		length: u64,
	) {
		let file = metadata(path, false);
		assert_eq!(self.observe(&file, RegularFile), expected);
		assert_eq!(file.metadata().unwrap().len(), length);
	}

	pub(super) fn confirm_record(&self, path: &Path, expected: WindowsStageIdentity, bytes: &[u8]) {
		let file = reader(path);
		assert_eq!(self.observe(&file, RegularFile), expected);
		assert_eq!(bounded_bytes(&file, bytes.len()), bytes);
		self.observe_record_extent(path, expected, bytes.len() as u64);
	}
}

pub(super) struct Job {
	pub(super) path: PathBuf,
	pub(super) first: PathBuf,
	pub(super) owner: PathBuf,
	pub(super) sibling: PathBuf,
	profile: OwnerProfileId,
	job: JournalJobId,
	pub(super) roles: WindowsBootstrapRoleObservations,
	pub(super) sibling_id: WindowsStageIdentity,
	pub(super) bytes: WindowsBootstrapBytes,
	pub(super) historical: WindowsBootstrapEvidence,
}

impl Job {
	pub(super) fn select<'key>(&self, key: &'key VerifyingKey) -> WindowsBootstrapSelection<'key> {
		WindowsBootstrapSelection {
			root: identity(self.roles.root),
			job: self.job,
			profile: self.profile,
			key,
		}
	}
}

pub(super) fn metadata(path: &Path, directory: bool) -> File {
	OpenOptions::new()
		.access_mode(ATTRIBUTE_ACCESS)
		.share_mode(SHARE_READ_WRITE)
		.custom_flags(NO_REPARSE | if directory { DIRECTORY_OPEN } else { 0 })
		.open(path)
		.unwrap()
}

pub(super) fn reader(path: &Path) -> File {
	OpenOptions::new()
		.read(true)
		.share_mode(SHARE_READ_WRITE)
		.custom_flags(NO_REPARSE)
		.open(path)
		.unwrap()
}

pub(super) fn bounded_bytes(mut file: &File, max: usize) -> Vec<u8> {
	let mut bytes = Vec::new();
	file.take(max as u64 + 1).read_to_end(&mut bytes).unwrap();
	assert!(bytes.len() <= max);
	assert_eq!(file.read(&mut [0_u8; 1]).unwrap(), 0);
	bytes
}

pub(super) fn absent(path: &Path) {
	assert_eq!(
		std::fs::symlink_metadata(path).unwrap_err().kind(),
		std::io::ErrorKind::NotFound
	);
}
