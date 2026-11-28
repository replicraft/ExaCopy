//! Independent approval wire vectors through the production encoding and verification path.

use std::path::Path;

use ed25519_dalek::Signature;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	ApplyQualificationDigest, JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId,
	PlanDigest,
};
use exacopy_transfer::linux::PlanAttempt;

use super::super::{ApprovalEnrollment, LocalApplyQualificationEnrollment, check_time};
use super::{
	ApprovalFields, ApprovalOperation, Error, GRANT_DOMAIN, HostFields, PARENT_DOMAIN, SigningKey,
	UnixTimestamp, VerifyingKey, approval_keys_match, approve_fields, encode_host,
	role_projections,
};

const FIXTURES: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/verification/managed_approval_wire/vectors.hex",
));

fn vector(name: &str) -> Vec<u8> {
	let text = FIXTURES
		.lines()
		.find_map(|line| {
			let (label, digits) = line.split_once(' ').unwrap();
			(label == name).then_some(digits)
		})
		.unwrap();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn fixed<const N: usize>(name: &str) -> [u8; N] {
	vector(name).try_into().unwrap()
}

fn public(name: &str) -> VerifyingKey {
	VerifyingKey::from_bytes(&fixed(name)).unwrap()
}

fn source_time(seconds: i64, nanos: u32) -> UnixTimestamp {
	UnixTimestamp::new(seconds, nanos).unwrap()
}

fn window() -> [UnixTimestamp; 2] {
	[source_time(-20, 789), source_time(30, 101)]
}

fn octets<const N: usize>(start: u8) -> [u8; N] {
	let mut value = start;
	std::array::from_fn(|_| {
		let byte = value;
		value = value.wrapping_add(7);
		byte
	})
}

fn selected_host() -> HostFields {
	let mut ids: [[u8; 16]; 15] =
		std::array::from_fn(|index| octets(0x10 + u8::try_from(index).unwrap() * 11));
	for index in [2, 3, 5, 12] {
		ids[index][6] = (ids[index][6] & 0x0f) | 0x70;
		ids[index][8] = (ids[index][8] & 0x3f) | 0x80;
	}
	let mut digests = std::array::from_fn(|index| octets(0x40 + u8::try_from(index).unwrap() * 7));
	digests[0] = fixed("owner_key");
	digests[1] = fixed("approver_key");
	digests[2] = fixed("attestor_key");
	digests[11] = fixed("slot_role");
	digests[12] = fixed("segment_role");
	let [start, end] = window();
	HostFields {
		ids,
		digests,
		counters: [
			0x0102_0304_0506_0708,
			0x1112_1314_1516_1718,
			0x2122_2324_2526_2728,
			1,
			0xf1f2_f3f4_f5f6_f7f8,
			1,
			432,
		],
		times: [source_time(-60, 123), source_time(50, 456), start, end],
		direction: 1,
		reason: 0,
	}
}

fn selected_approval(approver: &VerifyingKey) -> ApprovalFields<'_> {
	let host = selected_host();
	ApprovalFields {
		host: fixed("host_pin"),
		review: host.digests[8],
		child: host.digests[9],
		private_plan: host.digests[10],
		content: octets(0xd9),
		metadata: octets(0xe5),
		qualification: host.digests[14],
		action: host.ids[4],
		stream_length: 0x0102_0304,
		buffer_budget: 0x0001_2034,
		window: window(),
		direction: host.direction,
		predecessor: host.digests[7],
		p063_pair: octets(0x83),
		pair: host.ids[2],
		activation: host.ids[11],
		approver,
	}
}

fn admit<'a>(
	grant: &'a [u8],
	parent: &'a [u8],
	activation: &'a [u8],
	activation_digest: [u8; 32],
) -> ApprovalOperation<'a> {
	ApprovalOperation::Verify {
		grant,
		parent,
		activation,
		activation_digest,
	}
}

#[test]
fn host_grant_parent_and_activation_match_independent_vectors() {
	let (host, host_pin) = encode_host(selected_host());
	assert_eq!(host, vector("host"));
	assert_eq!(host_pin, fixed("host_pin"));

	let approver = public("approver_key");
	let preview = approve_fields(selected_approval(&approver), ApprovalOperation::Preview).unwrap();
	assert_eq!(preview.grant, vector("grant"));
	assert_eq!(preview.parent, vector("parent"));
	assert_eq!(preview.body_digest, fixed("body_pin"));
	assert!(preview.activation.is_none());
	assert_eq!(
		blake3::derive_key(GRANT_DOMAIN, &preview.grant),
		fixed("grant_pin")
	);
	assert_eq!(
		blake3::derive_key(PARENT_DOMAIN, &preview.parent),
		fixed("parent_pin")
	);

	let signer = SigningKey::from_bytes(&fixed("approver_seed"));
	let signed = approve_fields(
		selected_approval(&approver),
		ApprovalOperation::Sign {
			confirmed_body: fixed("body_pin"),
			signer: &signer,
		},
	)
	.unwrap();
	let (envelope, digest) = signed.activation.unwrap();
	assert_eq!(&envelope[..196], vector("body").as_slice());
	assert_eq!(envelope, vector("envelope"));
	assert_eq!(digest, fixed("envelope_pin"));
	let verified = approve_fields(
		selected_approval(&approver),
		admit(
			&vector("grant"),
			&vector("parent"),
			&vector("envelope"),
			fixed("envelope_pin"),
		),
	)
	.unwrap();
	assert_eq!(verified.activation, Some((envelope, digest)));
}

#[test]
fn approval_refuses_substituted_roles_and_stale_artifacts() {
	let approver = public("approver_key");
	let grant = vector("grant");
	let parent = vector("parent");
	let envelope = vector("envelope");
	let expected = fixed("envelope_pin");
	let accepts =
		|scope: ApprovalFields<'_>, grant: &[u8], parent: &[u8], envelope: &[u8], pin: [u8; 32]| {
			approve_fields(scope, admit(grant, parent, envelope, pin))
		};
	let mut changed_host = selected_host();
	changed_host.digests.swap(11, 12);
	let (_, other_pin) = encode_host(changed_host);
	assert_ne!(other_pin, fixed("host_pin"));
	let mut scope = selected_approval(&approver);
	scope.host = other_pin;
	assert!(matches!(
		accepts(scope, &grant, &parent, &envelope, expected),
		Err(Error::Artifact)
	));
	for (one, two) in [
		(parent.as_slice(), grant.as_slice()),
		(&grant[..grant.len() - 1], parent.as_slice()),
		(grant.as_slice(), &parent[..parent.len() - 1]),
	] {
		assert!(matches!(
			accepts(selected_approval(&approver), one, two, &envelope, expected),
			Err(Error::Artifact)
		));
	}
	for candidate in ["stale_magic", "stale_major", "stale_minor", "features"] {
		let bytes = vector(candidate);
		let pin = fixed(&format!("{candidate}_pin"));
		let (body, signed) = bytes.split_at(196);
		let exact = [b"ExaCopy/linux-managed-activation/v1\0".as_slice(), body].concat();
		let signature = Signature::from_slice(signed).unwrap();
		approver.verify_strict(&exact, &signature).unwrap();
		assert_eq!(
			blake3::derive_key(
				"ExaCopy Linux managed activation signed envelope v1",
				&bytes
			),
			pin
		);
		assert!(matches!(
			accepts(selected_approval(&approver), &grant, &parent, &bytes, pin),
			Err(Error::Artifact)
		));
	}
	let mut trailing = envelope.clone();
	trailing.push(0);
	for bytes in [&envelope[..envelope.len() - 1], trailing.as_slice()] {
		assert!(matches!(
			accepts(
				selected_approval(&approver),
				&grant,
				&parent,
				bytes,
				expected
			),
			Err(Error::Artifact)
		));
	}
	for wrong in [[0; 32], fixed("body_pin"), fixed("host_pin")] {
		assert!(matches!(
			accepts(
				selected_approval(&approver),
				&grant,
				&parent,
				&envelope,
				wrong
			),
			Err(Error::Artifact)
		));
	}
}

#[test]
fn approval_refuses_wrong_signature_role_or_purpose() {
	let owner = public("owner_key");
	let approver = public("approver_key");
	let attestor = public("attestor_key");
	assert!(approval_keys_match(&owner, &owner, &approver, &attestor));
	assert!(!approval_keys_match(
		&owner, &attestor, &approver, &attestor
	));
	assert!(!approval_keys_match(&owner, &owner, &owner, &attestor));
	assert!(!approval_keys_match(&owner, &owner, &approver, &owner));
	assert!(!approval_keys_match(&owner, &owner, &approver, &approver));
	let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
	assert!(weak.is_weak());
	assert!(!approval_keys_match(&owner, &owner, &weak, &attestor));
	assert!(!approval_keys_match(&owner, &owner, &approver, &weak));

	for artifact in ["wrong_signer", "wrong_purpose"] {
		let independent_pin = fixed(&format!("{artifact}_pin"));
		assert!(matches!(
			approve_fields(
				selected_approval(&approver),
				admit(
					&vector("grant"),
					&vector("parent"),
					&vector(artifact),
					independent_pin
				),
			),
			Err(Error::Signature),
		));
	}
	let signer = SigningKey::from_bytes(&fixed("approver_seed"));
	assert!(matches!(
		approve_fields(
			selected_approval(&owner),
			ApprovalOperation::Sign {
				confirmed_body: fixed("body_pin"),
				signer: &signer
			},
		),
		Err(Error::Signature),
	));
	assert!(matches!(
		approve_fields(
			selected_approval(&approver),
			ApprovalOperation::Sign {
				confirmed_body: fixed("envelope_pin"),
				signer: &signer
			},
		),
		Err(Error::Selection),
	));
}

#[test]
fn approval_window_refuses_unavailable_or_exclusive_time() {
	let owner = public("owner_key");
	let approver = public("approver_key");
	let attestor_key = public("attestor_key");
	let host = selected_host();
	let selection = LocalApplyQualificationEnrollment {
		record_path: Path::new("/synthetic-qualification"),
		record_digest: ApplyQualificationDigest::from_bytes(host.digests[14]),
		attestor_id: host.ids[14],
		attestor_key: &attestor_key,
	};
	let enrollment = ApprovalEnrollment {
		origin_ids: [host.ids[9], host.ids[10]],
		current_selection: host.digests[6],
		predecessor: host.digests[7],
		role_projections: [host.digests[11], host.digests[12]],
		prepared: ChainHead::after(1, host.digests[13]).unwrap(),
		prepared_extent: 432,
		attempt: PlanAttempt {
			job: JournalJobId::from_bytes(host.ids[12]).unwrap(),
			entry: JournalEntryId::from_bytes(host.ids[13]),
			epoch: JournalEpoch::new(host.counters[4]),
			job_name: UnixComponent::new(b".exacopy-test").unwrap(),
			stage_name: UnixComponent::new(b"candidate").unwrap(),
		},
		private_plan: PlanDigest::from_bytes(host.digests[10]),
		ordinary_owner: (OwnerProfileId::from_bytes(host.ids[1]).unwrap(), &owner),
		approver: &approver,
		qualification: &selection,
		window: window(),
		activation: host.ids[11],
	};
	let [start, end] = window();
	for now in [start, source_time(30, 100)] {
		assert_eq!(check_time(&enrollment, &|| Some(now)).unwrap(), now);
	}
	for now in [
		None,
		Some(source_time(-20, 788)),
		Some(end),
		Some(source_time(31, 0)),
	] {
		assert!(matches!(check_time(&enrollment, &|| now), Err(Error::Time)));
	}
}

#[test]
fn approval_role_projections_match_independent_slot_and_segment_vectors() {
	for case in ["raw_name", "replacement_segment", "swapped_namespaces"] {
		let slot = vector(&format!("{case}_slot_preimage_hex"));
		let segment = vector(&format!("{case}_segment_preimage_hex"));
		let correct = [
			fixed(&format!("{case}_slot_commitment")),
			fixed(&format!("{case}_segment_commitment")),
		];
		assert_eq!(role_projections(&slot, &segment), correct, "{case}");
		assert_ne!(role_projections(&segment, &slot), correct, "{case}");
	}
}
