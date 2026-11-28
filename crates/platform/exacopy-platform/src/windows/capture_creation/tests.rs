use super::CreationDescriptor;

#[test]
fn creation_descriptor_bounds_every_sid_and_native_field() {
	for count in 0_u8..=15 {
		let sid = sid_with_count(count);
		let descriptor = CreationDescriptor::private_for_sid(&sid).unwrap();
		let bytes = descriptor.bytes();

		// SECURITY_DESCRIPTOR_RELATIVE header, SID, ACL header and single
		// ACCESS_ALLOWED_ACE header precede the final trustee SID.
		let owner = 20;
		let dacl = owner + sid.len();
		let ace = dacl + 8;
		let trustee = ace + 8;
		assert!(bytes.len() <= 172);
		assert_eq!(bytes.len(), trustee + sid.len());
		assert!(bytes.len().is_multiple_of(4));
		assert_eq!(descriptor.0.as_ptr().align_offset(4), 0);
		assert_eq!(&bytes[..4], &[1, 0, 4, 144]);
		assert_eq!(&bytes[4..8], &(owner as u32).to_le_bytes());
		assert_eq!(&bytes[8..16], &[0; 8]);
		assert_eq!(&bytes[16..20], &(dacl as u32).to_le_bytes());
		assert_eq!(&bytes[owner..dacl], sid.as_slice());
		assert_eq!(&bytes[dacl..dacl + 2], &[2, 0]);
		assert_eq!(
			&bytes[dacl + 2..dacl + 4],
			&((bytes.len() - dacl) as u16).to_le_bytes()
		);
		assert_eq!(&bytes[dacl + 4..ace], &[1, 0, 0, 0]);
		assert_eq!(&bytes[ace..ace + 2], &[0, 0]);
		assert_eq!(
			&bytes[ace + 2..ace + 4],
			&((bytes.len() - ace) as u16).to_le_bytes()
		);
		assert_eq!(&bytes[ace + 4..trustee], &[255, 1, 31, 0]);
		assert_eq!(&bytes[trustee..], sid.as_slice());

		for short in 0..sid.len() {
			assert!(CreationDescriptor::private_for_sid(&sid[..short]).is_none());
		}
		let mut overlong = sid.clone();
		overlong.push(0);
		assert!(CreationDescriptor::private_for_sid(&overlong).is_none());
		let mut other_revision = sid;
		other_revision[0] = 2;
		assert!(CreationDescriptor::private_for_sid(&other_revision).is_none());
	}
	assert!(CreationDescriptor::private_for_sid(&sid_with_count(16)).is_none());
	assert!(CreationDescriptor::private_for_sid(&sid_with_count(u8::MAX)).is_none());
}

fn sid_with_count(count: u8) -> Vec<u8> {
	let mut sid = vec![1, count, 0, 0, 0, 0, 0, 5];
	for sub_authority in 1..=u32::from(count) {
		sid.extend(sub_authority.to_le_bytes());
	}
	sid
}
