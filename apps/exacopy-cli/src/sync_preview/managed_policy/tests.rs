use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_plan::workflow_sync::{MAX_MEMBER_BYTES, NativeObject, WorkflowKind, WorkflowRef};

use super::{
	MANAGED_POLICY_MAX_BYTES, ManagedCooperation, ManagedHistoryMember, ManagedPolicy,
	ManagedPolicyEndpoint, ManagedPolicyError, ManagedPolicyHistory, ManagedPolicyIdentity,
	ManagedPolicyLocation, decode, encode,
};

#[test]
fn complete_envelope_matches_fixed_commitment_and_round_trips() {
	let identity = identity();
	let policy = policy();
	let (bytes, pin) = encode(&identity, &policy).unwrap();
	let header = r#"[1,"01010101010101010101010101010101",7,"#;
	let payload = concat!(
		r#""d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","#,
		r#"["02020202020202020202020202020202",[1000,1001],[1,"03030303030303030303030303030303"],"#,
		r#"["2f6d616e616765642f70616972","04040404040404040404040404040404","#,
		r#"["05050505050505050505050505050505",[0,4,1],[0,4,2],3,4,[8,1,5]],"ff","#,
		r#"[["06060606060606060606060606060606","07070707070707070707070707070707","6c656674",[8,1,6],0],"#,
		r#"["08080808080808080808080808080808","09090909090909090909090909090909","7269676874",[8,1,7],1024]]],"#,
		r#"["2f6d616e616765642f686973746f7279",[8,1,8],11,"#,
		r#"["726f6f74",6,64,"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"],"#,
		r#"[["6c",1,64,"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"],"#,
		r#"["72",1,64,"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"],"#,
		r#"["6c656166",256,64,"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"]],null]]]"#,
	);
	let commitment = format!("{header}{payload}");
	let digest = blake3::derive_key(
		"ExaCopy local managed sync policy v1",
		commitment.as_bytes(),
	);
	let digest_hex = blake3::Hash::from_bytes(digest).to_hex();
	let expected = format!(r#"{header}"{digest_hex}",{payload}"#);

	assert_eq!(pin.identity, identity);
	assert_eq!(pin.digest, digest);
	assert_eq!(bytes, expected.as_bytes());
	assert!(decode(&bytes, &pin).unwrap() == policy);
	let endpoints = policy.endpoint_facts().unwrap();
	assert_eq!(endpoints[0].name.as_bytes(), b"left");
	assert_eq!(endpoints[0].max_bytes, 0);
	assert_eq!(endpoints[1].location.mount.get(), 4);
	assert_eq!(policy.history.revision.get(), 11);
}

#[test]
fn rejects_noncanonical_syntax_without_relaxing_the_pin() {
	let (bytes, pin) = encode(&identity(), &policy()).unwrap();
	let record = String::from_utf8(bytes).unwrap();
	for altered in [
		format!(" {record}"),
		format!("{record}\n"),
		record.replacen("[1,", "[2,", 1),
		record.replacen("[1,", "[1.0,", 1),
		record.replacen("[1000,1001]", "[1000,0]", 1),
		record.replacen("d75a", "D75a", 1),
		record.replacen("d75a", r#"\u006475a"#, 1),
		record.replacen("null]]]", "null,1]]]", 1),
		record.replacen("null]]]", "]]]", 1),
	] {
		assert_ne!(altered, record);
		assert!(matches!(
			decode(altered.as_bytes(), &pin),
			Err(ManagedPolicyError::Encoding)
		));
	}
}

#[test]
fn rejects_a_different_complete_receipt_or_payload() {
	let (bytes, pin) = encode(&identity(), &policy()).unwrap();
	let mut wrong = pin;
	wrong.identity.owner_key = SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes();
	assert!(matches!(
		decode(&bytes, &wrong),
		Err(ManagedPolicyError::Selection)
	));
	wrong = pin;
	wrong.identity.owner_profile = [44; 16];
	assert!(matches!(
		decode(&bytes, &wrong),
		Err(ManagedPolicyError::Selection)
	));
	wrong = pin;
	wrong.identity.selection_id = [45; 16];
	assert!(matches!(
		decode(&bytes, &wrong),
		Err(ManagedPolicyError::Selection)
	));
	wrong = pin;
	wrong.identity.revision = nonzero(8);
	assert!(matches!(
		decode(&bytes, &wrong),
		Err(ManagedPolicyError::Selection)
	));
	wrong = pin;
	wrong.digest = [88; 32];
	assert!(matches!(
		decode(&bytes, &wrong),
		Err(ManagedPolicyError::Selection)
	));

	let changed = String::from_utf8(bytes)
		.unwrap()
		.replacen(",1024]", ",1025]", 1);
	assert!(matches!(
		decode(changed.as_bytes(), &pin),
		Err(ManagedPolicyError::Selection)
	));

	let mut swapped = policy();
	swapped.endpoints.swap(0, 1);
	let (changed, other_pin) = encode(&identity(), &swapped).unwrap();
	assert_ne!(pin.digest, other_pin.digest);
	assert!(decode(&changed, &other_pin).unwrap() == swapped);
	assert!(matches!(
		decode(&changed, &pin),
		Err(ManagedPolicyError::Selection)
	));
}

#[test]
fn preserves_member_and_path_boundaries_and_rejects_aliases() {
	let mut policy = policy();
	let path = [b"/".as_slice(), &[b'x'; 255]].concat().repeat(15);
	policy.parent_path = [path.as_slice(), b"/", &[b'\xff'; 254]].concat();
	policy.subject = vec![b'\xfe'; 255];
	policy.history.root.reference.byte_len = 2_048;
	for member in &mut policy.history.children {
		member.reference.byte_len = 2_048;
	}
	let (bytes, pin) = encode(&identity(), &policy).unwrap();
	assert!(decode(&bytes, &pin).unwrap() == policy);
	assert!(matches!(
		decode(&vec![b' '; MANAGED_POLICY_MAX_BYTES + 1], &pin),
		Err(ManagedPolicyError::Size)
	));
	assert!(matches!(
		decode(&vec![b' '; MANAGED_POLICY_MAX_BYTES], &pin),
		Err(ManagedPolicyError::Encoding)
	));

	policy.parent_path.push(b'x');
	assert!(matches!(
		encode(&identity(), &policy),
		Err(ManagedPolicyError::Scope)
	));
	policy.parent_path.pop();
	policy.history.children[0].reference.byte_len = u16::try_from(MAX_MEMBER_BYTES + 1).unwrap();
	assert!(matches!(
		encode(&identity(), &policy),
		Err(ManagedPolicyError::History)
	));
	policy.history.children[0].reference.byte_len = 2_048;
	policy.history.children[2].name = policy.history.children[0].name.clone();
	assert!(matches!(
		encode(&identity(), &policy),
		Err(ManagedPolicyError::History)
	));
	policy.history.children[2].name = b"leaf".to_vec();
	policy.history.children[2].reference.digest = policy.history.root.reference.digest;
	assert!(matches!(
		encode(&identity(), &policy),
		Err(ManagedPolicyError::History)
	));
	policy.history.children[2].reference.digest = [13; 32];
	policy.history.children.swap(1, 2);
	assert!(matches!(
		encode(&identity(), &policy),
		Err(ManagedPolicyError::History)
	));
}

fn identity() -> ManagedPolicyIdentity {
	let owner_key = SigningKey::from_bytes(&[
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
		0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
		0x7f, 0x60,
	])
	.verifying_key()
	.to_bytes();
	ManagedPolicyIdentity {
		selection_id: [1; 16],
		revision: nonzero(7),
		owner_profile: [2; 16],
		owner_key,
	}
}

fn policy() -> ManagedPolicy {
	ManagedPolicy {
		actor_uid: NonZeroU32::new(1000).unwrap(),
		actor_gid: NonZeroU32::new(1001).unwrap(),
		cooperation: ManagedCooperation {
			enrollment_id: [3; 16],
		},
		parent_path: b"/managed/pair".to_vec(),
		parent_locator: [4; 16],
		location: ManagedPolicyLocation {
			boot: [5; 16],
			mount_namespace: NativeObject {
				major: 0,
				minor: 4,
				inode: nonzero(1),
			},
			user_namespace: NativeObject {
				major: 0,
				minor: 4,
				inode: nonzero(2),
			},
			ordinary_mount: nonzero(3),
			unique_mount: nonzero(4),
			parent: object(5),
		},
		subject: vec![0xff],
		endpoints: [
			ManagedPolicyEndpoint {
				endpoint: [6; 16],
				root: [7; 16],
				name: b"left".to_vec(),
				object: object(6),
				max_bytes: 0,
			},
			ManagedPolicyEndpoint {
				endpoint: [8; 16],
				root: [9; 16],
				name: b"right".to_vec(),
				object: object(7),
				max_bytes: 1024,
			},
		],
		history: ManagedPolicyHistory {
			path: b"/managed/history".to_vec(),
			directory: object(8),
			revision: nonzero(11),
			root: member(b"root", WorkflowKind::Root, 10),
			children: [
				member(b"l", WorkflowKind::Endpoint, 11),
				member(b"r", WorkflowKind::Endpoint, 12),
				member(b"leaf", WorkflowKind::Leaf, 13),
			],
			scan: None,
		},
	}
}

fn member(name: &[u8], kind: WorkflowKind, digest_byte: u8) -> ManagedHistoryMember {
	ManagedHistoryMember {
		name: name.to_vec(),
		reference: WorkflowRef {
			digest: [digest_byte; 32],
			kind,
			byte_len: 64,
		},
	}
}

fn object(inode: u64) -> NativeObject {
	NativeObject {
		major: 8,
		minor: 1,
		inode: nonzero(inode),
	}
}

fn nonzero(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}
