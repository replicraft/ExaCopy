use std::io;
use std::os::fd::BorrowedFd;

use apfs_mounted::metadata::{self, ApplyError, ExtendedSecurity, ObservationError};

use super::metadata::observation_io_error;

pub(super) fn has_explicit_empty_acl(fd: BorrowedFd<'_>) -> io::Result<bool> {
	Ok(descriptor_security(fd)?.is_explicit_empty_acl())
}

// Use only for an exclusively created child on the positively admitted APFS volume.
pub(super) fn has_no_stage_acl_entries(fd: BorrowedFd<'_>) -> io::Result<bool> {
	stage_security(metadata::extended_security(
		fd,
		metadata::MAX_EXTENDED_SECURITY_BYTES,
	))
}

pub(super) fn stage_security(
	security: Result<ExtendedSecurity, ObservationError>,
) -> io::Result<bool> {
	Ok(matches!(
		classify_security(security)?,
		AclObservation::Absent | AclObservation::ExplicitEmpty { .. }
	))
}

pub(super) fn has_basic_acl(fd: BorrowedFd<'_>) -> io::Result<bool> {
	basic_security(metadata::extended_security(
		fd,
		metadata::MAX_EXTENDED_SECURITY_BYTES,
	))
}

pub(super) fn basic_security(
	security: Result<ExtendedSecurity, ObservationError>,
) -> io::Result<bool> {
	Ok(classify_security(security)?.is_basic_acl())
}

#[derive(Debug, PartialEq, Eq)]
enum AclObservation {
	Absent,
	ExplicitEmpty { has_guid: bool },
	Ineligible,
}

impl AclObservation {
	fn from_security(security: ExtendedSecurity) -> Self {
		match security {
			ExtendedSecurity::NotReturned {
				empty_reference: true,
			} => Self::Absent,
			ExtendedSecurity::Present(payload) => Self::from_payload(
				payload.entry_count,
				payload.flags,
				&payload.owner_guid,
				&payload.group_guid,
			),
			_ => Self::Ineligible,
		}
	}

	fn from_payload(
		entry_count: Option<u32>,
		flags: u32,
		owner_guid: &[u8],
		group_guid: &[u8],
	) -> Self {
		if entry_count != Some(0) || flags != 0 {
			return Self::Ineligible;
		}
		let has_guid = owner_guid.iter().chain(group_guid).any(|&byte| byte != 0);
		Self::ExplicitEmpty { has_guid }
	}

	fn is_explicit_empty_acl(&self) -> bool {
		matches!(self, Self::ExplicitEmpty { .. })
	}

	fn is_basic_acl(&self) -> bool {
		matches!(self, Self::Absent | Self::ExplicitEmpty { has_guid: false })
	}
}

fn descriptor_security(fd: BorrowedFd<'_>) -> io::Result<AclObservation> {
	classify_security(metadata::extended_security(
		fd,
		metadata::MAX_EXTENDED_SECURITY_BYTES,
	))
}

fn classify_security(
	observation: Result<ExtendedSecurity, ObservationError>,
) -> io::Result<AclObservation> {
	match observation {
		Ok(security) => Ok(AclObservation::from_security(security)),
		Err(ObservationError::Malformed(_) | ObservationError::Limit { .. }) => {
			Ok(AclObservation::Ineligible)
		}
		Err(error) => Err(observation_io_error(error)),
	}
}

// The caller may only set security metadata on a freshly created directory
// whose descriptor has been bound to the exclusive creation.
pub(super) fn set_empty_acl_on_fresh_directory(fd: BorrowedFd<'_>) -> io::Result<()> {
	metadata::set_empty_acl_on_fresh_directory(fd)
		.map(|_| ())
		.map_err(|error| match error {
			ApplyError::Update(error) => error,
			ApplyError::ReadBack(error) => observation_io_error(error),
			error => io::Error::new(io::ErrorKind::InvalidData, error),
		})
}

#[cfg(test)]
pub(super) fn set_fixture_empty_acl(fd: BorrowedFd<'_>) -> io::Result<()> {
	set_empty_acl_on_fresh_directory(fd)
}

#[test]
fn unreported_security_requires_the_exact_empty_reference_observation() {
	let unsupported = AclObservation::from_security(ExtendedSecurity::NotReturned {
		empty_reference: false,
	});
	assert_eq!(unsupported, AclObservation::Ineligible);
	assert!(!unsupported.is_basic_acl());

	let absent = AclObservation::from_security(ExtendedSecurity::NotReturned {
		empty_reference: true,
	});
	assert_eq!(absent, AclObservation::Absent);
	assert!(absent.is_basic_acl());
	assert!(!absent.is_explicit_empty_acl());
}

#[test]
fn explicit_empty_acl_requires_zero_count_and_flags_and_basic_acl_requires_zero_guids() {
	let zero_guid = [0; 16];
	let mut nonzero_guid = zero_guid;
	nonzero_guid[0] = 1;

	let empty = AclObservation::from_payload(Some(0), 0, &zero_guid, &zero_guid);
	assert!(empty.is_explicit_empty_acl());
	assert!(empty.is_basic_acl());

	for (owner, group) in [(&nonzero_guid, &zero_guid), (&zero_guid, &nonzero_guid)] {
		let security_guid = AclObservation::from_payload(Some(0), 0, owner, group);
		assert!(security_guid.is_explicit_empty_acl());
		assert!(!security_guid.is_basic_acl());
	}

	for (count, flags) in [(None, 0), (Some(1), 0), (Some(0), 1)] {
		let ineligible = AclObservation::from_payload(count, flags, &zero_guid, &zero_guid);
		assert_eq!(ineligible, AclObservation::Ineligible);
		assert!(!ineligible.is_explicit_empty_acl());
		assert!(!ineligible.is_basic_acl());
	}
}
