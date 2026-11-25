use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES};
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS, MAX_REMOTE_PATH_BYTES,
};

use super::*;

#[test]
fn checkpoint_geometry_matches_wide_unsigned_arithmetic_at_boundaries() {
	for offset in [
		0,
		1,
		MAX_FILE_LENGTH - MAX_REMOTE_CHECKPOINT_BYTES,
		MAX_FILE_LENGTH - 1,
		MAX_FILE_LENGTH,
		MAX_FILE_LENGTH + 1,
		u64::MAX,
	] {
		for length in [
			0,
			1,
			MAX_REMOTE_CHECKPOINT_BYTES,
			MAX_REMOTE_CHECKPOINT_BYTES + 1,
			u64::MAX,
		] {
			for ordinal in [
				0,
				1,
				2,
				MAX_REMOTE_CHECKPOINTS,
				MAX_REMOTE_CHECKPOINTS + 1,
				u16::MAX,
			] {
				let expected_valid = (1..=4096).contains(&ordinal)
					&& (1..=67_108_864).contains(&length)
					&& ((ordinal == 1) == (offset == 0))
					&& u128::from(offset) + u128::from(length) < (1_u128 << 63);
				let prepared = head(3, 0xa3);
				let result = RemoteDownloadRecord::new(
					context(),
					Some(prepared),
					Body::RangeCheckpoint {
						prepared,
						epochs: epochs(2, 10),
						ordinal,
						offset,
						length,
						digest: StreamDigest::from_bytes([7; 32]),
					},
				);
				assert_eq!(
					result.is_ok(),
					expected_valid,
					"{ordinal} range {offset} + {length}"
				);
				if let Ok(record) = result {
					let bytes = record.encode().unwrap();
					assert_eq!(RemoteDownloadRecord::decode(&bytes), Ok(record));
				}
			}
		}
	}
}

#[test]
fn fresh_epochs_follow_checked_run_successor_and_strict_source_increase() {
	let source = RemoteSourceObservation::new(StreamLength::new(0).unwrap(), MODE, 0).unwrap();
	for (previous, next, accepted) in [
		(None, epochs(1, 7), true),
		(None, epochs(2, 7), false),
		(Some(epochs(1, 7)), epochs(2, 8), true),
		(Some(epochs(1, 7)), epochs(3, 8), false),
		(Some(epochs(1, 7)), epochs(2, 7), false),
		(Some(epochs(1, 7)), epochs(2, 6), false),
		(
			Some(epochs(u64::MAX - 1, u64::MAX - 1)),
			epochs(u64::MAX, u64::MAX),
			true,
		),
		(
			Some(epochs(u64::MAX, u64::MAX - 1)),
			epochs(1, u64::MAX),
			false,
		),
	] {
		let result = RemoteDownloadRecord::new(
			context(),
			Some(head(1, 4)),
			Body::StageAllocated {
				previous,
				next,
				name: UnixComponent::new(&[b'x'; MAX_UNIX_COMPONENT_BYTES]).unwrap(),
				nonce: NONCE,
				source,
			},
		);
		assert_eq!(result.is_ok(), accepted, "{previous:?} to {next:?}");
		if let Ok(record) = result {
			let bytes = record.encode().unwrap();
			assert!(bytes.len() <= MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES);
			assert_eq!(RemoteDownloadRecord::decode(&bytes), Ok(record));
		}
	}

	for invalid in [0o040644, 0o120777, u32::MAX] {
		assert_eq!(
			RemoteSourceObservation::new(StreamLength::new(0).unwrap(), invalid, 0),
			Err(Error::Binding),
		);
	}
}

#[test]
fn name_and_route_admission_is_component_scoped_and_port_exact() {
	for path in [
		b"".as_slice(),
		b"/file",
		b"inbox//file",
		b"inbox/.",
		b"inbox/..",
		b"a/\0",
		b"dir/",
	] {
		assert_eq!(
			RemoteDownloadSource::new(
				authority("transfer.example", "reader"),
				[1; 32],
				RemoteDownloadRoute::Direct,
				path,
			),
			Err(Error::Scope),
			"{path:?}",
		);
	}
	for inner in [
		"0.0.0.0:22",
		"255.255.255.255:22",
		"239.4.5.6:22",
		"10.15.17.19:23",
		"[::ffff:192.0.2.5]:22",
	] {
		assert_eq!(
			RemoteDownloadSource::new(
				authority("transfer.example", "reader"),
				[1; 32],
				wireguard(inner),
				b"a"
			),
			Err(Error::Scope),
			"{inner}",
		);
	}
}

#[test]
fn maximum_owner_projection_fits_its_bound_and_refuses_long_paths() {
	let mut path = vec![b'x'; MAX_REMOTE_PATH_BYTES];
	for index in (254..MAX_REMOTE_PATH_BYTES).step_by(255) {
		path[index] = b'/';
	}
	let host = format!(
		"{}.{}.{}.{}.",
		"a".repeat(63),
		"b".repeat(63),
		"c".repeat(63),
		"d".repeat(61)
	);
	let account = "e".repeat(256);
	let authority = authority(&host, &account);
	let route = wireguard("[2001:db8::2]:22");
	let selected = RemoteDownloadSource::new(authority.clone(), [1; 32], route, &path).unwrap();
	let mut declared = manifest(selected);
	declared.scope.maximum_extent = StreamLength::new(MAX_FILE_LENGTH).unwrap();
	declared.scope.destination = RemoteDownloadDestination::new(
		root(),
		LinuxFileIdentity::new(7, u64::MAX),
		UnixComponent::new(&[0xff; MAX_UNIX_COMPONENT_BYTES]).unwrap(),
	);
	let owner = RemoteDownloadOwnerRecord::sign(declared, &signer()).unwrap();
	assert!(owner.as_bytes().len() <= MAX_REMOTE_DOWNLOAD_OWNER_BYTES);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(owner.as_bytes(), profile(), &signer().verifying_key()),
		Ok(owner.clone())
	);
	assert_eq!(
		OwnerRecord::decode(owner.as_bytes(), profile(), &signer().verifying_key()),
		Err(OwnerError::Length),
	);

	path.push(b'x');
	assert_eq!(
		RemoteDownloadSource::new(authority, [1; 32], route, &path),
		Err(Error::Length)
	);
}

#[test]
fn prepared_and_uncertain_records_cannot_reference_a_conflicting_or_future_head() {
	let previous = head(2, 1);
	for allocation in [head(1, 1), head(2, 2), head(3, 1)] {
		assert_eq!(
			RemoteDownloadRecord::new(
				context(),
				Some(previous),
				Body::EntryPrepared {
					allocation,
					epochs: epochs(2, 10),
					nonce: NONCE,
					stage_directory: LinuxFileIdentity::new(7, 12),
					stage: LinuxFileIdentity::new(7, 13),
				}
			),
			Err(Error::FrameBinding),
		);
	}
	for attempt in [ChainHead::start(), head(2, 2), head(3, 1)] {
		assert_eq!(
			RemoteDownloadRecord::new(
				context(),
				Some(previous),
				Body::FailureRecorded {
					attempt,
					epochs: epochs(2, 10),
					boundary: RemoteUncertainBoundary::Creation,
				}
			),
			Err(Error::FrameBinding),
		);
	}
	for stage in [LinuxFileIdentity::new(7, 12), LinuxFileIdentity::new(8, 13)] {
		assert_eq!(
			RemoteDownloadRecord::new(
				context(),
				Some(previous),
				Body::EntryPrepared {
					allocation: previous,
					epochs: epochs(2, 10),
					nonce: NONCE,
					stage_directory: LinuxFileIdentity::new(7, 12),
					stage,
				}
			),
			Err(Error::Binding),
		);
	}
}

#[test]
fn signed_scope_debug_redacts_wire_bytes_and_normalized_hosts_are_canonical() {
	let signed =
		RemoteDownloadOwnerRecord::sign(manifest(source(RemoteDownloadRoute::Direct)), &signer())
			.unwrap();
	let debug = format!("{signed:?}");
	for field in ["bytes: [", "transfer.example", "Reader", "inbox", "target-"] {
		assert!(
			!debug.contains(field),
			"debug output exposed a protected field"
		);
	}

	let wire = hex(OWNER);
	let mut body = envelope_body(&wire).to_vec();
	let host_start = body
		.windows(b"transfer.example.".len())
		.position(|window| window == b"transfer.example.")
		.unwrap();
	body[host_start] = b'T';
	let uppercase = signed_envelope(&body, DOMAIN, 4);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&uppercase, profile(), &signer().verifying_key()),
		Err(Error::NonCanonical),
	);
}
