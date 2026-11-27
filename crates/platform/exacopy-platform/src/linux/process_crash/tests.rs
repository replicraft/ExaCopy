use std::fs::File;

use rustix::fs::makedev;

use super::mount::{Mount, is_fixture_mount};
use super::{
	DestinationRoot, ProcessCrashEligibility, ProcessCrashProfileError, ProcessCrashProfileId,
	ReadRoot, observe_process_crash_environment, parse_boot_id,
};
use crate::linux::mount_observation::MountObservations;
use crate::scratch::Scratch;

const MOUNTINFO: &str =
	"32 1 253:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,discard,errors=remount-ro,commit=30\n";

#[test]
fn admits_only_the_exact_mounted_ext4_profile() {
	let mount = Mount {
		id: 32,
		unique_id: 10_044,
		device: makedev(253, 1),
	};
	assert!(accepts_mount(MOUNTINFO.as_bytes(), mount));
	for (from, to) in [
		("32 1", "31 1"),
		("253:1", "253:2"),
		("/ /", "/nested /"),
		("/ /", "/ /nested"),
		("shared:1", "master:1"),
		("rw,relatime", "ro,relatime"),
		("ext4", "ext3"),
		("/dev/vda1", "/dev/vdb1"),
		("commit=30", "commit=5"),
	] {
		assert!(!accepts_mount(
			MOUNTINFO.replacen(from, to, 1).as_bytes(),
			mount
		));
	}
	assert!(!accepts_mount(MOUNTINFO.repeat(2).as_bytes(), mount));
}

fn accepts_mount(bytes: &[u8], mount: Mount) -> bool {
	MountObservations::parse(bytes).ok().is_some_and(|table| {
		table
			.record(mount.id)
			.is_some_and(|record| is_fixture_mount(&record, mount))
	})
}

#[test]
fn requires_an_exact_nonnil_kernel_boot_identifier() {
	let input = b"00112233-4455-4677-8899-aabbccddeeff\n";
	assert_eq!(
		parse_boot_id(input),
		Some([
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
			0xee, 0xff
		])
	);
	assert_eq!(parse_boot_id(&input[..input.len() - 1]), None);
	assert_eq!(
		parse_boot_id(b"00000000-0000-0000-0000-000000000000\n"),
		None
	);
	assert_eq!(
		parse_boot_id(b"00112233_4455-4677-8899-aabbccddeeff\n"),
		None
	);
}

#[test]
#[ignore = "requires the exact ARM64 Ubuntu ext4 process-crash qualification fixture"]
fn qualified_fixture_checks_held_mount_and_expected_environment_before_use() {
	let scratch = Scratch::new();
	let destination_scratch = Scratch::new();
	let source = ReadRoot::from_directory(scratch.open()).expect("hold source root");
	let destination =
		DestinationRoot::from_directory(destination_scratch.open()).expect("hold destination root");
	// This derives the expectation only in the native fixture. Production must
	// get the expectation from separately reviewed and provisioned evidence.
	let expected = observe_process_crash_environment(&source, &destination)
		.expect("observe qualified ext4 setup");
	let admitted = ProcessCrashEligibility::admit(expected, &source, &destination)
		.expect("match native evidence");
	assert_eq!(
		admitted.profile_id(),
		ProcessCrashProfileId::Arm64UbuntuExt4FixtureV1
	);
	admitted.recheck().expect("re-observe held roots");
	let mut changed = expected;
	changed.unique_mount ^= 1;
	assert!(matches!(
		ProcessCrashEligibility::admit(changed, &source, &destination),
		Err(ProcessCrashProfileError::EnvironmentChanged)
	));
	changed = expected;
	changed.boot_id[0] ^= 1;
	assert!(matches!(
		ProcessCrashEligibility::admit(changed, &source, &destination),
		Err(ProcessCrashProfileError::EnvironmentChanged)
	));
	changed = expected;
	changed.mount_namespace ^= 1;
	assert!(matches!(
		ProcessCrashEligibility::admit(changed, &source, &destination),
		Err(ProcessCrashProfileError::EnvironmentChanged)
	));
	let proc_source = ReadRoot::from_directory(File::open("/proc").expect("open proc fixture"))
		.expect("hold unsupported source root");
	assert!(matches!(
		observe_process_crash_environment(&proc_source, &destination),
		Err(ProcessCrashProfileError::UnsupportedMount)
	));
}

#[path = "../../../tests/unit/process_crash_facts.rs"]
mod facts;
