use std::os::windows::io::{BorrowedHandle, OwnedHandle};

use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
use windows_sys::Win32::Security::{SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

use super::WindowsComponent;
use super::native::{Kind, Refusal, RelativeFileOpen, open_relative_entry_with_descriptor};
use super::stage::FILE_CREATED_INFORMATION;

/// A bounded SECURITY_DESCRIPTOR_RELATIVE with one explicit current-user ACE.
/// DWORD storage keeps every variable-length component aligned for NtCreateFile.
pub(super) struct CreationDescriptor(Vec<u32>);

impl CreationDescriptor {
	pub(super) fn private_for_sid(sid: &[u8]) -> Option<Self> {
		const HEADER_BYTES: u32 = 20;
		const ACL_REVISION: u8 = 2;
		const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
		let [1, sub_authorities @ 0..=15, ..] = *sid else {
			return None;
		};
		if sid.len() != 8 + usize::from(sub_authorities) * 4 {
			return None;
		}

		let sid_length = u16::try_from(sid.len()).ok()?;
		let ace_length = 8 + sid_length;
		let acl_length = 8 + ace_length;
		let dacl_offset = HEADER_BYTES + u32::from(sid_length);
		let mut bytes = Vec::with_capacity(dacl_offset as usize + usize::from(acl_length));
		bytes.extend_from_slice(&[1, 0]);
		bytes.extend_from_slice(
			&(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED).to_le_bytes(),
		);
		bytes.extend_from_slice(&HEADER_BYTES.to_le_bytes()); // Owner
		bytes.extend_from_slice(&[0; 8]); // Group and SACL are unspecified.
		bytes.extend_from_slice(&dacl_offset.to_le_bytes());
		bytes.extend_from_slice(sid);

		bytes.extend_from_slice(&[ACL_REVISION, 0]);
		bytes.extend_from_slice(&acl_length.to_le_bytes());
		bytes.extend_from_slice(&[1, 0, 0, 0]); // One ACE and reserved bytes.
		bytes.extend_from_slice(&[ACCESS_ALLOWED_ACE_TYPE, 0]);
		bytes.extend_from_slice(&ace_length.to_le_bytes());
		bytes.extend_from_slice(&FILE_ALL_ACCESS.to_le_bytes());
		bytes.extend_from_slice(sid);

		let (words, []) = bytes.as_chunks::<4>() else {
			return None;
		};
		Some(Self(
			words.iter().copied().map(u32::from_ne_bytes).collect(),
		))
	}

	#[allow(
		unsafe_code,
		reason = "the private constructor bounds and aligns the complete native descriptor"
	)]
	pub(super) fn create(
		&self,
		parent: BorrowedHandle<'_>,
		name: WindowsComponent<'_>,
		mut request: RelativeFileOpen,
		kind: Kind,
	) -> Result<OwnedHandle, Refusal> {
		request.disposition = FILE_CREATE;
		// SAFETY: Self holds a complete self-relative descriptor with checked SID
		// geometry and aligned, bounded components for the synchronous open.
		let (handle, information) = unsafe {
			open_relative_entry_with_descriptor(parent, name, request, kind, Some(&self.0))
		}?;
		if information != FILE_CREATED_INFORMATION {
			return Err(Refusal::UnexpectedOpenResult(information));
		}
		Ok(handle)
	}
}

#[cfg(test)]
mod tests;

#[cfg(test)]
impl CreationDescriptor {
	pub(super) fn bytes(&self) -> Vec<u8> {
		self.0.iter().flat_map(|word| word.to_ne_bytes()).collect()
	}
}
