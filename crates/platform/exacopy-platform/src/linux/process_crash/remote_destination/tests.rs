use super::*;
use crate::scratch::Scratch;

mod campaign;

const MOUNT_ROW: &str = "13 1 8:1 / /selected\\040mount rw,nosuid - ext4 /dev/loop1 rw,user_xattr";

#[test]
fn unavailable_or_denied_uname_returns_the_kernel_error() {
	for errno in [nix::errno::Errno::EPERM, nix::errno::Errno::ENOSYS] {
		let result = read_kernel(|| Err(errno));
		assert!(
			matches!(result, Err(RemoteDestinationEligibilityError::KernelIo(error))
			if error.raw_os_error() == Some(errno as i32))
		);
	}
}

#[test]
fn destination_observer_joins_exact_writable_ext4_row_to_the_held_mount() {
	let fixture = mount::Mount {
		id: 13,
		unique_id: 35,
		device: fs::makedev(8, 1),
	};
	let rows = MountObservations::parse(format!("{MOUNT_ROW}\n").as_bytes()).unwrap();
	assert_eq!(
		remote_mount_row(&rows, fixture).unwrap(),
		MOUNT_ROW.as_bytes()
	);
	for (from, to) in [
		("13 1", "14 1"),
		("8:1", "8:2"),
		(" / /selected", " /subtree /selected"),
		("ext4", "ext3"),
		("rw,nosuid", "ro,nosuid"),
		("rw,nosuid", "rw,ro,nosuid"),
		("rw,user_xattr", "ro,user_xattr"),
	] {
		let data = format!("{}\n", MOUNT_ROW.replacen(from, to, 1));
		let rows = MountObservations::parse(data.as_bytes()).unwrap();
		assert!(matches!(
			remote_mount_row(&rows, fixture),
			Err(RemoteDestinationEligibilityError::UnsupportedMount)
		));
	}
	let data = format!(
		"{MOUNT_ROW},{}\n",
		"a".repeat(MAX_REMOTE_MOUNT_RECORD_BYTES)
	);
	let rows = MountObservations::parse(data.as_bytes()).unwrap();
	assert!(matches!(
		remote_mount_row(&rows, fixture),
		Err(RemoteDestinationEligibilityError::UnsupportedObservation)
	));
}

#[test]
fn destination_observer_accepts_ext4_with_namespace_handle_mounts_present() {
	const ROUTE_ROW: &str = "17 13 0:4 net:[4026533115] /run/netns/route rw - nsfs nsfs rw";
	const PEER_ROW: &str = "18 13 0:4 net:[4026533116] /run/netns/peer rw - nsfs nsfs rw";
	let data = format!("{MOUNT_ROW}\n{ROUTE_ROW}\n{PEER_ROW}\n");
	let rows = MountObservations::parse(data.as_bytes()).unwrap();
	let ext4 = mount::Mount {
		id: 13,
		unique_id: 35,
		device: fs::makedev(8, 1),
	};
	assert_eq!(remote_mount_row(&rows, ext4).unwrap(), MOUNT_ROW.as_bytes());
	assert_eq!(rows.record_bytes(17), Some(ROUTE_ROW.as_bytes()));
	assert_eq!(rows.record_bytes(18), Some(PEER_ROW.as_bytes()));

	let nsfs = mount::Mount {
		id: 17,
		unique_id: 36,
		device: fs::makedev(0, 4),
	};
	assert!(matches!(
		remote_mount_row(&rows, nsfs),
		Err(RemoteDestinationEligibilityError::UnsupportedMount)
	));

	let data = format!("{}\n", ROUTE_ROW.replace("net:[4026533115]", "/"));
	let absolute = MountObservations::parse(data.as_bytes()).unwrap();
	assert!(matches!(
		remote_mount_row(&absolute, nsfs),
		Err(RemoteDestinationEligibilityError::UnsupportedMount)
	));
}

#[test]
fn missing_projection_refuses_before_any_mount_observation() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held fixture directory");
	assert!(matches!(
		RemoteDestinationEligibility::admit(&root, None),
		Err(RemoteDestinationEligibilityError::Unqualified)
	));
}

#[test]
#[ignore = "requires a disposable native ext4 directory in this boot and mount namespace"]
fn exact_held_destination_and_independently_provisioned_fixture_projection_are_required() {
	let fixture = std::env::var_os("EXACOPY_REMOTE_QUALIFICATION_ROOT")
		.expect("select a disposable native ext4 fixture");
	let root = DestinationRoot::from_directory(std::fs::File::open(&fixture).unwrap()).unwrap();

	// This test validates native comparison only. Its self-observed projection is synthetic.
	let facts = observe_remote_destination(&root).unwrap();
	let admitted = RemoteDestinationQualification::new(facts.clone(), [0xa5; 32]).unwrap();
	let eligibility = RemoteDestinationEligibility::admit(&root, Some(&admitted)).unwrap();
	assert_eq!(eligibility.qualification_digest(), [0xa5; 32]);
	eligibility.recheck_for(&root).unwrap();
	let reopened = DestinationRoot::from_directory(std::fs::File::open(fixture).unwrap()).unwrap();
	assert!(matches!(
		eligibility.recheck_for(&reopened),
		Err(RemoteDestinationEligibilityError::DifferentRoot)
	));

	let expected = facts.ids();
	for changed in [
		RemoteDestinationIds {
			root: JobFileIdentity {
				inode: different(expected.root.inode),
				..expected.root
			},
			..expected
		},
		RemoteDestinationIds {
			effective_uid: expected.effective_uid ^ 1,
			..expected
		},
		RemoteDestinationIds {
			effective_gid: expected.effective_gid ^ 1,
			..expected
		},
		RemoteDestinationIds {
			boot_id: [0x67; 16],
			..expected
		},
		RemoteDestinationIds {
			mount_namespace: different(expected.mount_namespace),
			..expected
		},
		RemoteDestinationIds {
			mount_id: different(expected.mount_id),
			..expected
		},
		RemoteDestinationIds {
			unique_mount: different(expected.unique_mount),
			..expected
		},
	] {
		let changed = RemoteDestinationFacts::new(
			changed,
			facts.architecture(),
			facts.kernel_release(),
			facts.kernel_build(),
			facts.mount_record(),
		)
		.unwrap();
		let changed = RemoteDestinationQualification::new(changed, [0xa5; 32]).unwrap();
		assert!(matches!(
			RemoteDestinationEligibility::admit(&root, Some(&changed)),
			Err(RemoteDestinationEligibilityError::EnvironmentChanged)
		));
	}
}

fn different(value: u64) -> u64 {
	if value == 1 { 2 } else { 1 }
}
