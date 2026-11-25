//! Independent structure and exact-byte controls for destination qualification facts.

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::{
	MAX_REMOTE_KERNEL_FIELD_BYTES, MAX_REMOTE_MOUNT_RECORD_BYTES, RemoteDestinationFacts,
	RemoteDestinationIds, RemoteDestinationQualification, RemoteKernelArchitecture,
};

const IDS: RemoteDestinationIds = RemoteDestinationIds {
	root: JobFileIdentity {
		device: 31,
		inode: 41,
	},
	effective_uid: 1000,
	effective_gid: 1001,
	boot_id: [0xaa; 16],
	mount_namespace: 9,
	mount_id: 13,
	unique_mount: 15,
};

const RELEASE: &[u8] = b"6.8.12-release";
const BUILD: &[u8] = b"#1 SMP fixture";
const ROW: &[u8] = b"13 1 8:1 / /destination\\040scope rw,nosuid - ext4 /dev/loop1 rw,user_xattr";

fn facts(
	ids: RemoteDestinationIds,
	release: &[u8],
	build: &[u8],
	row: &[u8],
) -> Option<RemoteDestinationFacts> {
	RemoteDestinationFacts::new(ids, RemoteKernelArchitecture::X86_64, release, build, row)
}

#[test]
fn projection_retains_exact_bytes_and_record_digest() {
	let native = facts(IDS, RELEASE, BUILD, ROW).unwrap();
	assert_eq!(native.ids(), IDS);
	assert_eq!(native.architecture(), RemoteKernelArchitecture::X86_64);
	assert_eq!(native.kernel_release(), RELEASE);
	assert_eq!(native.kernel_build(), BUILD);
	assert_eq!(native.mount_record(), ROW);
	assert!(RemoteDestinationQualification::new(native.clone(), [0; 32]).is_none());
	let qualification = RemoteDestinationQualification::new(native.clone(), [0x17; 32]).unwrap();
	assert_eq!(qualification.digest(), [0x17; 32]);
	assert_eq!(qualification.facts(), &native);
	assert!(!format!("{native:?}").contains("destination"));
}

#[test]
fn refuses_reserved_native_ids_and_non_bounded_exact_fields() {
	for changed in [
		RemoteDestinationIds {
			root: JobFileIdentity {
				device: 31,
				inode: 0,
			},
			..IDS
		},
		RemoteDestinationIds {
			boot_id: [0; 16],
			..IDS
		},
		RemoteDestinationIds {
			mount_namespace: 0,
			..IDS
		},
		RemoteDestinationIds { mount_id: 0, ..IDS },
		RemoteDestinationIds {
			unique_mount: 0,
			..IDS
		},
	] {
		assert!(facts(changed, RELEASE, BUILD, ROW).is_none());
	}
	for invalid in [
		b"".as_slice(),
		b"embedded\0null",
		b"extra\nline",
		b"trailing\r",
	] {
		assert!(facts(IDS, invalid, BUILD, ROW).is_none());
		assert!(facts(IDS, RELEASE, invalid, ROW).is_none());
		assert!(facts(IDS, RELEASE, BUILD, invalid).is_none());
	}
	let kernel = [b'A'; MAX_REMOTE_KERNEL_FIELD_BYTES];
	let row = [b'A'; MAX_REMOTE_MOUNT_RECORD_BYTES];
	assert!(facts(IDS, &kernel, &kernel, &row).is_some());
	assert!(
		facts(
			IDS,
			&[b'A'; MAX_REMOTE_KERNEL_FIELD_BYTES + 1],
			&kernel,
			&row
		)
		.is_none()
	);
	assert!(
		facts(
			IDS,
			&kernel,
			&kernel,
			&[b'A'; MAX_REMOTE_MOUNT_RECORD_BYTES + 1]
		)
		.is_none()
	);
}
