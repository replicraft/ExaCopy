use std::os::windows::io::{AsHandle as _, BorrowedHandle};

use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::{
	OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_TRAVERSE, SYNCHRONIZE,
};

use super::{
	FILE_OPENED_INFORMATION, READ_ACCESS, WindowsPublicationBinding, WindowsPublicationError,
	native,
};
use crate::windows::WindowsComponent;
use crate::windows::native::{
	Kind, ObjectId, Refusal, RelativeFileOpen, observe, observe_entry, open_relative_entry,
	open_relative_file,
};

/// A sampled namespace observation under the caller's held root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowsPublicationTargetObservation {
	/// The one-component target lookup reported that its name did not exist.
	Absent,
	/// The regular target has the expected exact spelling and stage identity.
	ExactStage,
	/// A different regular object occupies the target at its exact spelling.
	Unrelated(ObjectId),
}

/// Inspects a public target through an existing parent reopened from a held fixed-NTFS root.
///
/// Inspection supports case-insensitive destination parents. The caller independently
/// authenticates the root, its ancestors, the destination parent component and all expected
/// identities. The root must be held without delete sharing and
/// the caller must exclude concurrent namespace and object changes in its controlled scope.
/// The returned value describes a sampled name and identity. It carries no file handle,
/// verification, historical publication, or durability provenance.
///
/// # Errors
/// A failed root, parent, or target check leaves the observation uncertain. Only the exact
/// native missing-name status for the target under the admitted parent maps to absence.
pub fn inspect_windows_publication_target(
	root: BorrowedHandle<'_>,
	expected_root: ObjectId,
	destination_name: WindowsComponent<'_>,
	binding: &WindowsPublicationBinding<'_>,
) -> Result<WindowsPublicationTargetObservation, WindowsPublicationError> {
	let destination_id = binding.destination_parent;
	if destination_id == expected_root
		|| destination_id == binding.stage_parent
		|| ![destination_id, binding.stage_parent, binding.stage]
			.into_iter()
			.all(|id| {
				id.volume == expected_root.volume && id.volume_serial == expected_root.volume_serial
			}) {
		return Err(WindowsPublicationError::ParentScope);
	}

	check_directory(root, None, expected_root)?;
	native::require_fixed_ntfs(root)?;
	let parent = open_relative_entry(
		root,
		destination_name,
		observation_request(
			FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		),
		Kind::Directory,
	)
	.map_err(WindowsPublicationError::native)?;
	let parent = parent.as_handle();
	check_directory(parent, Some(destination_name), destination_id)?;
	native::require_case_insensitive(parent)?;

	// Admit regular, non-recalled metadata before requesting a sharing-sensitive
	// data-read handle. No data is read through either handle.
	let name = binding.target_name;
	let metadata_pin = match open_relative_file(
		parent,
		name,
		observation_request(FILE_READ_ATTRIBUTES | SYNCHRONIZE),
	) {
		Ok(file) => Some(file),
		Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_NOT_FOUND)) => None,
		Err(cause) => return Err(WindowsPublicationError::native(cause)),
	};
	let (observation, _read_pin) = if let Some(metadata) = &metadata_pin {
		let id = target_identity(metadata.as_handle(), name)?;
		if id.volume != destination_id.volume || id.volume_serial != destination_id.volume_serial {
			return Err(WindowsPublicationError::native(Refusal::VolumeChanged));
		}
		let file = open_relative_file(parent, name, observation_request(READ_ACCESS))
			.map_err(WindowsPublicationError::native)?;
		if target_identity(file.as_handle(), name)? != id {
			return Err(WindowsPublicationError::TargetChanged);
		}
		let observation = if id == binding.stage {
			WindowsPublicationTargetObservation::ExactStage
		} else {
			WindowsPublicationTargetObservation::Unrelated(id)
		};
		(observation, Some(file))
	} else {
		(WindowsPublicationTargetObservation::Absent, None)
	};
	native::require_case_insensitive(parent)?;
	check_directory(parent, Some(destination_name), destination_id)?;
	check_directory(root, None, expected_root)?;
	Ok(observation)
}

fn target_identity(
	handle: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
) -> Result<ObjectId, WindowsPublicationError> {
	observe_entry(handle, Kind::RegularFile, Some(name)).map_err(WindowsPublicationError::native)
}

fn check_directory(
	handle: BorrowedHandle<'_>,
	name: Option<WindowsComponent<'_>>,
	expected: ObjectId,
) -> Result<(), WindowsPublicationError> {
	let id =
		observe_entry(handle, Kind::Directory, name).map_err(WindowsPublicationError::native)?;
	if id != expected {
		return Err(WindowsPublicationError::ParentChanged);
	}
	Ok(())
}

fn observation_request(access: u32) -> RelativeFileOpen {
	RelativeFileOpen {
		access,
		share: FILE_SHARE_READ,
		disposition: FILE_OPEN,
		attributes: OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
		expected_result: Some(FILE_OPENED_INFORMATION),
	}
}
