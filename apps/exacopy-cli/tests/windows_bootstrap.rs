//! Explicitly provisioned Windows bootstrap fixture with no CLI activation.
#![cfg(target_os = "windows")]

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::frame::{ChainHead, FrameReader};
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_BYTES, FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_BYTES, OWNER_FILE_NAME,
	WindowsBootstrapBytes, WindowsBootstrapInspectionError, WindowsBootstrapOwner,
	WindowsBootstrapOwnerError, WindowsBootstrapPrefix, WindowsBootstrapRoles,
	WindowsBootstrapSelection, inspect, job_directory_name, sign,
};
use exacopy_journal::{JournalJobId, OwnerError, OwnerProfileId, OwnerToken};
use exacopy_platform::ProtectedSnapshotError;
use exacopy_platform::windows::{
	WindowsBootstrapLayout, WindowsBootstrapRecords, WindowsBootstrapRootSelection,
	WindowsComponent,
};

#[path = "windows_bootstrap/fixture.rs"]
mod fixture;

use fixture::{Provisioned, SelectedFixture, SelectedRoot, identity, read_selection};

const JOB: [u8; 16] = [
	0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
];

// Public test material from RFC 8032 section 7.1, tests 1 and 2.
const FIXTURE_SEED: [u8; 32] = [
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const FIXTURE_KEY: [u8; 32] = [
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const FOREIGN_KEY: [u8; 32] = [
	0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
	0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

fn component(units: &[u16]) -> WindowsComponent<'_> {
	WindowsComponent::new(units).expect("fixed bootstrap component")
}

fn layout(job_name: &[u16]) -> WindowsBootstrapLayout<'_> {
	WindowsBootstrapLayout {
		job: component(job_name),
		owner: component(&OWNER_FILE_NAME),
		journal: component(&JOURNAL_DIRECTORY_NAME),
		first_segment: component(&FIRST_SEGMENT_NAME),
		owner_bytes: OWNER_BYTES,
		first_segment_bytes: FIRST_SEGMENT_BYTES,
	}
}

fn root_selection(selected: SelectedRoot) -> WindowsBootstrapRootSelection {
	WindowsBootstrapRootSelection {
		volume_guid: selected.guid,
		volume_serial: selected.serial,
		file_id: selected.file_id,
	}
}

fn observed_roles(records: &WindowsBootstrapRecords<'_>) -> WindowsBootstrapRoles {
	let observed = records.roles();
	WindowsBootstrapRoles::new(
		identity(observed.root),
		identity(observed.job_directory),
		identity(observed.owner_file),
		identity(observed.journal_directory),
		identity(observed.first_segment),
	)
	.expect("distinct same-volume held roles")
}

fn inspect_fixture(
	root: &Path,
	selected_root: SelectedRoot,
	expected: &WindowsBootstrapSelection<'_>,
	provisioned: &Provisioned,
) -> WindowsBootstrapPrefix {
	let job_name = job_directory_name(expected.job);
	let layout = layout(&job_name);
	let root_units: Vec<_> = root.as_os_str().encode_wide().collect();
	let root_selection = root_selection(selected_root);
	let foreign_serial = WindowsBootstrapRootSelection {
		volume_serial: selected_root.serial ^ (1 << 63),
		..root_selection
	};
	assert!(matches!(
		WindowsBootstrapRecords::open(&root_units, foreign_serial, layout),
		Err(ProtectedSnapshotError::Changed)
	));
	let mut records = WindowsBootstrapRecords::open(&root_units, root_selection, layout)
		.expect("admit all five held roles");
	let roles = observed_roles(&records);
	assert_eq!(roles, provisioned.roles);

	let owner_bytes = records
		.read_owner()
		.expect("read exact held owner through EOF");
	assert_eq!(owner_bytes.as_slice(), provisioned.bytes.owner.as_slice());

	// A wrong independently selected key must refuse even with valid held bytes.
	let foreign_key =
		VerifyingKey::from_bytes(&FOREIGN_KEY).expect("separately selected wrong key");
	let wrong_key = WindowsBootstrapSelection {
		key: &foreign_key,
		..*expected
	};
	assert!(matches!(
		inspect(&owner_bytes, std::io::empty(), &wrong_key, roles),
		Err(WindowsBootstrapInspectionError::Owner(
			WindowsBootstrapOwnerError::Owner(OwnerError::UntrustedKey)
		))
	));

	let mut segment = records.first_segment();
	let historical = inspect(&owner_bytes, &mut segment, expected, roles)
		.expect("authenticate exact held owner and sole prepared frame");
	segment
		.finish()
		.expect("confirm terminal physical EOF and final held custody");

	let original = FrameReader::new(
		provisioned.bytes.first_segment.as_slice(),
		ChainHead::start(),
	)
	.next_frame()
	.expect("read original fixture frame")
	.expect("fixture has its prepared frame");
	let boundary = historical.boundary();
	assert_eq!(boundary.head(), original.head());
	assert_eq!(boundary.head().sequence(), 1);
	assert_eq!(boundary.end_offset(), FIRST_SEGMENT_BYTES as u64);
	boundary
}

fn print_boundary(boundary: WindowsBootstrapPrefix) {
	let mut digest = String::with_capacity(64);
	for byte in boundary.head().digest() {
		write!(digest, "{byte:02x}").expect("hex format to String");
	}
	println!(
		r#"{{"extent":{},"historical_head":"{digest}","sequence":{}}}"#,
		boundary.end_offset(),
		boundary.head().sequence(),
	);
}

#[test]
#[ignore = "requires the externally owned fixed-NTFS bootstrap fixture"]
fn admits_only_the_selected_held_bootstrap_history() {
	let fixture = read_selection();
	let signer = SigningKey::from_bytes(&FIXTURE_SEED);
	let verifier = VerifyingKey::from_bytes(&FIXTURE_KEY).expect("independently selected test key");
	let profile = OwnerProfileId::from_bytes([0x49; 16]).expect("fixture profile");
	let job = JournalJobId::from_bytes(JOB).expect("fixture UUIDv7");
	let token = OwnerToken::from_bytes([0x82; 16]).expect("independent synthetic fixture token");
	let selection = WindowsBootstrapSelection {
		profile,
		job,
		key: &verifier,
		root: fixture.roles.root(),
	};

	let provisioned =
		fixture::populate(&fixture.root, fixture.drive, fixture.roles, job, |roles| {
			sign(
				&WindowsBootstrapOwner {
					profile,
					job,
					token,
					roles,
				},
				&signer,
			)
			.expect("sign the original five native identities")
		});
	verify_counterexamples(&fixture, &selection, &provisioned.bytes);
	let historical = inspect_fixture(
		&fixture.root,
		fixture.root_observation,
		&selection,
		&provisioned,
	);
	println!(
		r#"{{"copied_job":"refused","hardlink":"refused","named_stream":"refused","suffix":"refused"}}"#
	);
	print_boundary(historical);
}

fn verify_counterexamples(
	fixture: &SelectedFixture,
	original: &WindowsBootstrapSelection<'_>,
	bytes: &WindowsBootstrapBytes,
) {
	let mut copied_job = JOB;
	copied_job[15] = 2;
	let copied_job = JournalJobId::from_bytes(copied_job).expect("different selected UUIDv7");
	let copied_selection = WindowsBootstrapSelection {
		job: copied_job,
		..*original
	};
	let copied = fixture::populate(
		&fixture.root,
		fixture.drive,
		fixture.copied_roles,
		copied_selection.job,
		|_| WindowsBootstrapBytes {
			owner: bytes.owner,
			first_segment: bytes.first_segment,
		},
	);
	let job = job_directory_name(copied_selection.job);
	let layout = layout(&job);
	let root: Vec<_> = fixture.root.as_os_str().encode_wide().collect();
	let selected_root = root_selection(fixture.root_observation);
	let mut records = WindowsBootstrapRecords::open(&root, selected_root, layout)
		.expect("admit separate private job and the copied record extents");
	let roles = observed_roles(&records);
	assert_eq!(roles, copied.roles);
	let owner = records
		.read_owner()
		.expect("read the complete copied owner");
	assert_eq!(owner.as_slice(), bytes.owner.as_slice());

	let mut copy = [0; FIRST_SEGMENT_BYTES];
	let mut segment = records.first_segment();
	segment
		.read_exact(&mut copy)
		.expect("read the complete copied segment");
	assert_eq!(segment.read(&mut [0]).expect("probe copied segment EOF"), 0);
	segment.finish().expect("confirm copied record custody");
	assert_eq!(copy, bytes.first_segment);
	assert!(matches!(
		inspect(&owner, records.first_segment(), &copied_selection, roles),
		Err(WindowsBootstrapInspectionError::Owner(
			WindowsBootstrapOwnerError::Job
		))
	));
	drop(records);

	let segment = fixture::first_segment_path(&fixture.root, copied_selection.job);
	let alias = segment.with_file_name("owned-negative-hardlink");
	fs::hard_link(&segment, &alias).expect("add one hardlink to the owned copied segment");
	fixture::confirm_two_link_names(
		fixture.drive,
		copied.roles.first_segment(),
		&segment,
		&alias,
	);
	assert_eq!(
		WindowsBootstrapRecords::open(&root, selected_root, layout).err(),
		Some(ProtectedSnapshotError::Unprotected),
		"refuse the owned second name before data open"
	);
	assert_eq!(
		fs::read(&segment).unwrap().as_slice(),
		bytes.first_segment.as_slice()
	);
	assert_eq!(
		fs::read(&alias).unwrap().as_slice(),
		bytes.first_segment.as_slice()
	);
	fs::remove_file(&alias).expect("remove only the owned hardlink");

	let ads = segment.with_file_name("00000000000000000001.exajnl:owned-negative");
	let mut stream = File::create_new(&ads).expect("create only the owned named stream");
	let named_bytes = b"synthetic stream";
	stream.write_all(named_bytes).unwrap();
	stream.sync_all().unwrap();
	drop(stream);
	assert_eq!(
		WindowsBootstrapRecords::open(&root, selected_root, layout).err(),
		Some(ProtectedSnapshotError::Unprotected),
		"refuse the owned named stream before data open"
	);
	assert_eq!(
		fs::read(&segment).unwrap().as_slice(),
		bytes.first_segment.as_slice()
	);
	assert_eq!(fs::read(&ads).unwrap().as_slice(), named_bytes);
	fs::remove_file(&ads).expect("remove only the owned named stream");

	let records = WindowsBootstrapRecords::open(&root, selected_root, layout)
		.expect("re-admit both copied records once aliases are gone");
	assert_eq!(observed_roles(&records), copied.roles);
	drop(records);

	let suffix = [0xA7];
	let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
	file.write_all(&suffix).unwrap();
	file.sync_all().unwrap();
	drop(file);
	assert_eq!(
		WindowsBootstrapRecords::open(&root, selected_root, layout).err(),
		Some(ProtectedSnapshotError::Changed),
		"refuse the actual extra segment extent before data open"
	);
	let retained = fs::read(segment).expect("read preserved copied segment and suffix");
	assert_eq!(retained.len(), FIRST_SEGMENT_BYTES + suffix.len());
	assert_eq!(
		&retained[..FIRST_SEGMENT_BYTES],
		bytes.first_segment.as_slice()
	);
	assert_eq!(&retained[FIRST_SEGMENT_BYTES..], suffix.as_slice());
}
