use exacopy_endpoint::MAX_UNIX_COMPONENT_BYTES;

use super::*;

const fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

fn root(marker: u8) -> RootCapabilityId {
	RootCapabilityId::from_bytes(uuid(marker)).unwrap()
}

fn fixture() -> LocalCopyPlan<'static> {
	LocalCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(uuid(1)).unwrap(),
			epoch: JournalEpoch::new(3),
			entry: JournalEntryId::from_bytes([2; 16]),
			job_name: component(b"job"),
			stage_name: component(b"stage"),
		},
		SourcePlanBinding {
			root_id: root(4),
			root_identity: LinuxFileIdentity::new(5, 6),
			file_identity: LinuxFileIdentity::new(5, 7),
			length: 28,
			modified_at: ObservedTimestamp::new(-1, 5).unwrap(),
			changed_at: ObservedTimestamp::new(10, 45).unwrap(),
			component: component(b"src\xff"),
		},
		DestinationPlanBinding {
			root: DestinationRootBinding {
				id: root(8),
				identity: LinuxFileIdentity::new(9, 10),
			},
			component: component(b"new\xfe"),
		},
	)
	.unwrap()
}

// Literal CBOR fixture authored from the v1 field order and integer encoding.
const GOLDEN: &[u8] = &[
	0x85, 0x82, 0x01, 0x00, 0x85, 0, 0, 0, 0, 0, // record prefix and fixed policy
	0x85, 0x50, 1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1, // job UUID
	3, 0x50, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // epoch and entry
	0x43, b'j', b'o', b'b', 0x45, b's', b't', b'a', b'g', b'e', 0x87, 0x50, 4, 4, 4, 4, 4, 4, 0x70,
	4, 0x80, 4, 4, 4, 4, 4, 4, 4, // source root
	0x82, 5, 6, 0x82, 5, 7, 0x18, 28, 0x82, 0x20, 5, 0x82, 10, 0x18, 45, // file and times
	0x44, b's', b'r', b'c', 0xff, 0x83, 0x50, 8, 8, 8, 8, 8, 8, 0x70, 8, 0x80, 8, 8, 8, 8, 8, 8,
	8, // destination root
	0x82, 9, 10, 0x44, b'n', b'e', b'w', 0xfe,
];

#[test]
fn stable_wire_and_digest_with_raw_names() {
	let plan = fixture();
	assert_eq!(plan.encode(), GOLDEN);
	assert_eq!(LocalCopyPlan::decode(GOLDEN).unwrap(), plan);
	let mut preimage = b"ExaCopy/local-copy-plan/v1\0".to_vec();
	preimage.extend_from_slice(GOLDEN);
	let expected_digest = *blake3::hash(&preimage).as_bytes();
	assert_eq!(plan.digest().as_bytes(), &expected_digest);
	assert_eq!(plan.context().plan_digest, plan.digest());
	assert_eq!(plan.context().job, plan.attempt().job);
	assert_eq!(plan.context().epoch, plan.attempt().epoch);
}

#[test]
fn changing_each_bound_value_changes_the_digest() {
	let original = fixture().digest();
	for (index, replacement) in [
		(12, 7),     // Job.
		(28, 4),     // Epoch.
		(30, 3),     // Entry.
		(47, b'J'),  // Job directory.
		(51, b'S'),  // Stage file.
		(58, 12),    // Source grant.
		(75, 12),    // Source root device.
		(76, 12),    // Source root inode.
		(78, 12),    // Source file device.
		(79, 12),    // Source file inode.
		(81, 29),    // Logical length.
		(83, 0x21),  // Modification seconds.
		(84, 6),     // Modification nanoseconds.
		(86, 11),    // Change seconds.
		(88, 46),    // Change nanoseconds.
		(93, 0xfe),  // Source raw component.
		(96, 12),    // Destination grant.
		(113, 12),   // Destination root device.
		(114, 12),   // Destination root inode.
		(119, 0xff), // Destination raw component.
	] {
		let mut changed = GOLDEN.to_vec();
		changed[index] = replacement;
		let decoded = LocalCopyPlan::decode(&changed).unwrap();
		assert_ne!(decoded.digest(), original, "plan byte {index}");
	}
}

#[test]
fn checks_exact_bound_at_maximum_width() {
	let attempt = PlanAttempt {
		epoch: JournalEpoch::new(u64::MAX),
		job_name: component(&[b'j'; MAX_UNIX_COMPONENT_BYTES]),
		stage_name: component(&[b's'; MAX_UNIX_COMPONENT_BYTES]),
		..fixture().attempt()
	};
	let source = SourcePlanBinding {
		root_identity: LinuxFileIdentity::new(u64::MAX, u64::MAX - 1),
		file_identity: LinuxFileIdentity::new(u64::MAX, u64::MAX - 2),
		length: MAX_FILE_LENGTH,
		modified_at: ObservedTimestamp::new(i64::MIN, 999_999_999).unwrap(),
		changed_at: ObservedTimestamp::new(i64::MAX, 999_999_999).unwrap(),
		component: component(&[b'r'; MAX_UNIX_COMPONENT_BYTES]),
		..fixture().source()
	};
	let destination = DestinationPlanBinding {
		root: DestinationRootBinding {
			id: fixture().destination().root.id,
			identity: LinuxFileIdentity::new(u64::MAX, u64::MAX - 3),
		},
		component: component(&[b't'; MAX_UNIX_COMPONENT_BYTES]),
	};
	let plan = LocalCopyPlan::new(attempt, source, destination).unwrap();
	let mut encoded = plan.encode();
	assert_eq!(encoded.len(), MAX_LOCAL_COPY_PLAN_BYTES);
	assert_eq!(LocalCopyPlan::decode(&encoded).unwrap(), plan);
	encoded.push(0);
	assert!(matches!(
		LocalCopyPlan::decode(&encoded),
		Err(LocalCopyPlanError::PayloadTooLarge)
	));
}

#[test]
fn refuses_partial_or_noncanonical_records() {
	for prefix in 0..GOLDEN.len() {
		assert!(LocalCopyPlan::decode(&GOLDEN[..prefix]).is_err());
	}
	let mut trailing = GOLDEN.to_vec();
	trailing.push(0);
	assert!(matches!(
		LocalCopyPlan::decode(&trailing),
		Err(LocalCopyPlanError::NonCanonical)
	));

	let mut long_array_head = GOLDEN.to_vec();
	long_array_head.splice(0..1, [0x98, 5]);
	assert!(matches!(
		LocalCopyPlan::decode(&long_array_head),
		Err(LocalCopyPlanError::NonCanonical)
	));

	let mut nonminimal_version = GOLDEN.to_vec();
	nonminimal_version.splice(2..3, [0x18, 1]);
	assert!(matches!(
		LocalCopyPlan::decode(&nonminimal_version),
		Err(LocalCopyPlanError::NonCanonical)
	));

	for head in [0x86, 0x9f] {
		let mut wrong_shape = GOLDEN.to_vec();
		wrong_shape[0] = head;
		assert!(matches!(
			LocalCopyPlan::decode(&wrong_shape),
			Err(LocalCopyPlanError::InvalidShape)
		));
	}
}

#[test]
fn refuses_unknown_versions_and_each_unknown_required_policy() {
	for version_index in 2..4 {
		let mut wrong_version = GOLDEN.to_vec();
		wrong_version[version_index] = 2;
		assert!(matches!(
			LocalCopyPlan::decode(&wrong_version),
			Err(LocalCopyPlanError::UnsupportedVersion)
		));
	}
	for policy_index in 5..10 {
		let mut unknown_policy = GOLDEN.to_vec();
		unknown_policy[policy_index] = 1;
		assert!(matches!(
			LocalCopyPlan::decode(&unknown_policy),
			Err(LocalCopyPlanError::UnsupportedPolicy)
		));
	}
}

#[test]
fn refuses_oversized_absolute_and_relative_path_syntax() {
	let target_payload = GOLDEN.len() - b"new\xfe".len() - 1;
	let oversize = vec![b'x'; MAX_UNIX_COMPONENT_BYTES + 1];
	for (bad_name, expected) in [
		(&b""[..], NameError::Empty),
		(b".", NameError::Reserved),
		(b"..", NameError::Reserved),
		(b"/root", NameError::Separator),
		(b"a/b", NameError::Separator),
		(b"foo\0", NameError::Nul),
		(&oversize, NameError::TooLong),
	] {
		let mut malformed_name = GOLDEN[..target_payload].to_vec();
		if bad_name.len() < 24 {
			malformed_name.push(0x40 + u8::try_from(bad_name.len()).unwrap());
		} else {
			malformed_name.push(0x59);
			malformed_name.extend_from_slice(&u16::try_from(bad_name.len()).unwrap().to_be_bytes());
		}
		malformed_name.extend_from_slice(bad_name);
		assert!(matches!(
			LocalCopyPlan::decode(&malformed_name),
			Err(LocalCopyPlanError::InvalidComponent(error)) if error == expected
		));
	}
}

#[test]
fn refuses_invalid_identifiers_and_timestamp_on_wire() {
	let mut bad_job = GOLDEN.to_vec();
	bad_job[18] = 0x40;
	assert!(matches!(
		LocalCopyPlan::decode(&bad_job),
		Err(LocalCopyPlanError::InvalidJobId)
	));

	let mut bad_entry = GOLDEN.to_vec();
	bad_entry[29] = 0x4f;
	assert!(matches!(
		LocalCopyPlan::decode(&bad_entry),
		Err(LocalCopyPlanError::InvalidEntryId)
	));

	let mut bad_root = GOLDEN.to_vec();
	bad_root[66] = 0x00;
	assert!(matches!(
		LocalCopyPlan::decode(&bad_root),
		Err(LocalCopyPlanError::InvalidRootId)
	));

	let mut bad_time = GOLDEN.to_vec();
	bad_time.splice(84..85, [0x1a, 0x3b, 0x9a, 0xca, 0x00]); // One billion nanoseconds.
	assert!(matches!(
		LocalCopyPlan::decode(&bad_time),
		Err(LocalCopyPlanError::InvalidSourceTimestamp)
	));
}

#[test]
fn refuses_impossible_identity_and_namespace_observations() {
	let plan = fixture();
	let (attempt, source, destination) = (plan.attempt(), plan.source(), plan.destination());
	for source in [
		SourcePlanBinding {
			file_identity: source.root_identity,
			..source
		},
		SourcePlanBinding {
			file_identity: destination.root.identity,
			..source
		},
		SourcePlanBinding {
			root_id: destination.root.id,
			..source
		},
	] {
		assert!(matches!(
			LocalCopyPlan::new(attempt, source, destination),
			Err(LocalCopyPlanError::ConflictingIdentities)
		));
	}

	let same_root = SourcePlanBinding {
		root_identity: destination.root.identity,
		..source
	};
	for source in [
		SourcePlanBinding {
			component: attempt.job_name,
			..same_root
		},
		SourcePlanBinding {
			component: destination.component,
			..same_root
		},
	] {
		assert!(matches!(
			LocalCopyPlan::new(attempt, source, destination),
			Err(LocalCopyPlanError::ConflictingNames)
		));
	}
	assert!(LocalCopyPlan::new(attempt, same_root, destination).is_ok());

	let job_is_target = DestinationPlanBinding {
		component: attempt.job_name,
		..destination
	};
	assert!(matches!(
		LocalCopyPlan::new(attempt, source, job_is_target),
		Err(LocalCopyPlanError::ConflictingNames)
	));
	let huge_source = SourcePlanBinding {
		length: MAX_FILE_LENGTH + 1,
		..source
	};
	assert!(matches!(
		LocalCopyPlan::new(attempt, huge_source, destination),
		Err(LocalCopyPlanError::SourceTooLong)
	));
}
