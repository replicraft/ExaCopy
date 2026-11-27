use std::num::NonZeroU32;

use rustix::process::{getegid, geteuid, getgid, getuid};

use super::ManagedSyncError;
use crate::linux::mount_observation::ProcMounts;

pub(super) fn check(
	proc: &ProcMounts,
	uid: NonZeroU32,
	gid: NonZeroU32,
) -> Result<OwnershipSentinels, ManagedSyncError> {
	let uid = uid.get();
	let gid = gid.get();
	if getuid().as_raw() != uid
		|| geteuid().as_raw() != uid
		|| getgid().as_raw() != gid
		|| getegid().as_raw() != gid
	{
		return Err(ManagedSyncError::CredentialProfile);
	}
	let status = proc.credential_status()?;
	let maps = proc.identity_maps()?;
	if !credential_status(&status, uid, gid) || !maps.iter().all(|map| full_identity_map(map)) {
		return Err(ManagedSyncError::CredentialProfile);
	}
	let sentinels = OwnershipSentinels {
		uid: overflow_identity(&proc.root_file(c"sys/kernel/overflowuid", 16)?)?,
		gid: overflow_identity(&proc.root_file(c"sys/kernel/overflowgid", 16)?)?,
	};
	if sentinels.ambiguous(uid, gid) {
		return Err(ManagedSyncError::CredentialProfile);
	}
	Ok(sentinels)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OwnershipSentinels {
	uid: u32,
	gid: u32,
}

impl OwnershipSentinels {
	pub(super) fn ambiguous(self, uid: u32, gid: u32) -> bool {
		uid == u32::MAX || uid == self.uid || gid == u32::MAX || gid == self.gid
	}
}

fn overflow_identity(data: &[u8]) -> Result<u32, ManagedSyncError> {
	data.strip_suffix(b"\n")
		.and_then(decimal)
		.ok_or(ManagedSyncError::CredentialProfile)
}

fn field<'data>(status: &'data [u8], name: &[u8]) -> Option<&'data [u8]> {
	let mut rows = status
		.split(|&byte| byte == b'\n')
		.filter_map(|row| row.strip_prefix(name));
	let row = rows.next()?;
	rows.next().is_none().then_some(row)
}

fn columns(row: &[u8]) -> impl Iterator<Item = &[u8]> {
	row.split(|&byte| matches!(byte, b' ' | b'\t'))
		.filter(|column| !column.is_empty())
}

fn decimal(column: &[u8]) -> Option<u32> {
	if column.len() > 10
		|| !column.iter().all(u8::is_ascii_digit)
		|| (column.len() > 1 && column.first() == Some(&b'0'))
	{
		return None;
	}
	str::from_utf8(column).ok()?.parse().ok()
}

fn credential_status(status: &[u8], uid: u32, gid: u32) -> bool {
	let exact = |name: &[u8], expected| {
		field(status, name).is_some_and(|row| columns(row).map(decimal).eq([Some(expected); 4]))
	};
	status.ends_with(b"\n")
		&& exact(b"Uid:", uid)
		&& exact(b"Gid:", gid)
		&& [b"CapInh:".as_slice(), b"CapPrm:", b"CapEff:", b"CapAmb:"]
			.into_iter()
			.all(|name| {
				field(status, name)
					.is_some_and(|row| columns(row).eq([b"0000000000000000".as_slice()]))
			})
}

fn full_identity_map(data: &[u8]) -> bool {
	data.strip_suffix(b"\n")
		.is_some_and(|row| columns(row).eq([b"0".as_slice(), b"0", b"4294967295"]))
}

#[cfg(test)]
mod tests {
	use super::{OwnershipSentinels, credential_status, full_identity_map, overflow_identity};

	const STATUS: &[u8] = b"Uid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";

	#[test]
	fn refuses_ambiguity_in_each_ownership_namespace() {
		assert!(matches!(overflow_identity(b"65534\n"), Ok(65534)));
		for invalid in [
			b"65534".as_slice(),
			b"65534\n5\n",
			b" 65534\n",
			b"+65534\n",
			b"4294967296\n",
		] {
			assert!(overflow_identity(invalid).is_err());
		}
		let observed = OwnershipSentinels { uid: 42, gid: 44 };
		assert!(!observed.ambiguous(44, 42));
		assert!(observed.ambiguous(42, 42));
		assert!(observed.ambiguous(44, 44));
		assert!(observed.ambiguous(u32::MAX, 42));
		assert!(observed.ambiguous(44, u32::MAX));
	}

	#[test]
	fn demands_the_full_kernel_identity_rows() {
		assert!(full_identity_map(b"         0          0 4294967295\n"));
		for invalid in [
			b"0 0 4294967295".as_slice(),
			b"0 0 4294967294\n",
			b"0 1 4294967295\n",
			b"1 1 4294967295\n",
			b"00 0 4294967295\n",
			b"0 0 4294967295\n\n",
			b"0 0 4294967295\n1 1 1\n",
			b"0 0 4294967295 0\n",
		] {
			assert!(!full_identity_map(invalid));
		}
	}

	#[test]
	fn rejects_partial_wrong_and_extra_credential_observations() {
		assert!(credential_status(STATUS, 1000, 1001));
		assert!(!credential_status(STATUS, 1002, 1001));
		assert!(!credential_status(STATUS, 1000, 1002));
		assert!(!credential_status(&STATUS[..STATUS.len() - 1], 1000, 1001));
		let text = str::from_utf8(STATUS).unwrap();
		for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
			let bad = text.replace(
				&format!("{field}:\t0000000000000000"),
				&format!("{field}:\t0000000000000001"),
			);
			assert!(!credential_status(bad.as_bytes(), 1000, 1001));
		}
		for wrong in [
			text.replace("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1002"),
			text.replace("1001\t1001\t1001\t1001", "1001\t1001\t1001"),
			format!("{text}Uid:\t1000\t1000\t1000\t1000\n"),
			text.replace("CapInh:", "Unknown:"),
		] {
			assert!(!credential_status(wrong.as_bytes(), 1000, 1001));
		}
	}
}
