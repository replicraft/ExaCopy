use super::*;

const USER: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 63, 0, 0, 0];
const EVERYONE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const READ_DATA: u32 = 1;
const DELETE_CHILD: u32 = 0x40;
const WRITE_DACL: u32 = 0x0004_0000;

fn security(owner: &[u8], protected: bool, entries: &[(u8, u8, u32, &[u8])]) -> Vec<u8> {
	let flags = SELF_RELATIVE | DACL_PRESENT | if protected { DACL_PROTECTED } else { 0 };
	let mut value = vec![1, 0];
	value.extend(flags.to_le_bytes());
	value.extend(20_u32.to_le_bytes());
	value.extend([0; 8]);
	value.extend(u32::try_from(20 + owner.len()).unwrap().to_le_bytes());
	value.extend(owner);
	let acl_size = 8 + entries.iter().map(|entry| 8 + entry.3.len()).sum::<usize>();
	value.extend([2, 0]);
	value.extend(u16::try_from(acl_size).unwrap().to_le_bytes());
	value.extend(u16::try_from(entries.len()).unwrap().to_le_bytes());
	value.extend([0, 0]);
	for &(kind, flags, mask, principal) in entries {
		value.extend([kind, flags]);
		value.extend(u16::try_from(8 + principal.len()).unwrap().to_le_bytes());
		value.extend(mask.to_le_bytes());
		value.extend(principal);
	}
	value
}

#[test]
fn private_dacl_confines_even_read_grants_and_requires_protection_and_owner() {
	for (owner, protected, trustee, allowed) in [
		(USER, true, USER, true),
		(USER, true, SYSTEM, true),
		(USER, true, ADMINISTRATORS, true),
		(USER, true, EVERYONE, false),
		(USER, false, USER, false),
		(SYSTEM, true, USER, false),
	] {
		let observed = security(owner, protected, &[(0, 0, READ_DATA, trustee)]);
		assert_eq!(approve(&observed, USER, Role::Private).is_ok(), allowed);
	}
}

#[test]
fn upper_ancestors_allow_traversal_and_sibling_creation_but_refuse_rewrites() {
	for (flags, mask, admitted) in [
		(0, READ_DATA | 2 | 4, true),
		(0, DELETE_CHILD, false),
		(0, WRITE_DACL, false),
		(INHERIT_ONLY, WRITE_DACL, true),
	] {
		let observed = security(SYSTEM, false, &[(0, flags, mask, EVERYONE)]);
		assert_eq!(
			approve(&observed, USER, Role::UpperDirectory).is_ok(),
			admitted
		);
	}
	let observed = security(EVERYONE, false, &[(0, 0, READ_DATA, USER)]);
	assert!(approve(&observed, USER, Role::UpperDirectory).is_err());
}

#[test]
fn rejects_null_truncated_overlapping_and_unrecognized_dacl_semantics() {
	let valid = security(USER, true, &[(0, 0, READ_DATA, USER)]);
	for length in 0..valid.len() {
		assert!(approve(&valid[..length], USER, Role::Private).is_err());
	}
	for descriptor_offset in [0_u32, 1, 20, u32::MAX] {
		let mut corrupt = valid.clone();
		corrupt[16..20].copy_from_slice(&descriptor_offset.to_le_bytes());
		assert!(approve(&corrupt, USER, Role::Private).is_err());
	}
	for kind in [5, 6, 9, 10] {
		let unsupported = security(USER, true, &[(kind, 0, READ_DATA, USER)]);
		assert!(approve(&unsupported, USER, Role::Private).is_err());
	}
	let empty = security(USER, true, &[]);
	assert!(approve(&empty, USER, Role::Private).is_ok());
}

#[cfg(feature = "experimental-windows-copy")]
#[test]
fn creation_descriptor_satisfies_private_acl_for_only_selected_user() {
	use crate::windows::capture_creation::CreationDescriptor;

	const OTHER: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 64, 0, 0, 0];
	let descriptor = CreationDescriptor::private_for_sid(USER).unwrap();
	let bytes = descriptor.bytes();
	assert!(approve(&bytes, USER, Role::Private).is_ok());
	assert_eq!(
		approve(&bytes, OTHER, Role::Private),
		Err(Error::Unprotected)
	);

	// Refuse a forged trustee even if the correct owner SID remains intact.
	let mut wrong_trustee = bytes.clone();
	let trailer = wrong_trustee.len() - OTHER.len();
	wrong_trustee[trailer..].copy_from_slice(OTHER);
	assert_eq!(
		approve(&wrong_trustee, USER, Role::Private),
		Err(Error::Unprotected)
	);
	for length in 0..bytes.len() {
		assert!(approve(&bytes[..length], USER, Role::Private).is_err());
	}
}
