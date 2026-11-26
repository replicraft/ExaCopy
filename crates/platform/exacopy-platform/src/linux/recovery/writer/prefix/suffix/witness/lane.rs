use std::marker::PhantomData;
use std::rc::Rc;
use std::thread::{self, ThreadId};

use rustix::process::{getegid, geteuid};

use crate::linux::StageError;
use crate::linux::mount_observation::ProcMounts;

#[derive(Debug, Eq, PartialEq)]
/// Current credential and thread observation before witnessed native effects.
///
/// This capability is thread-bound. Its checks cover observable credentials;
/// the kernel enforces exact same-open-credential admission at descriptor link.
#[must_use]
pub struct WitnessCredentialLane {
	thread: ThreadId,
	user_namespace: u64,
	uid: u32,
	gid: u32,
	_thread_bound: PhantomData<Rc<()>>,
}

impl WitnessCredentialLane {
	/// Observes the current unprivileged thread's credential and namespace.
	///
	/// # Errors
	/// Refuses unavailable observations, elevated credentials or unsafe status.
	pub fn observe() -> Result<Self, StageError> {
		let thread = thread::current().id();
		let proc = ProcMounts::open().map_err(StageError::System)?;
		let user_namespace = proc.user_namespace_id().map_err(StageError::System)?;
		let uid = geteuid().as_raw();
		let gid = getegid().as_raw();
		let status = proc.credential_status().map_err(StageError::System)?;
		if uid == 0 || !stable_unprivileged(&status, uid, gid) {
			return Err(StageError::UnsafeFile);
		}
		Ok(Self {
			thread,
			user_namespace,
			uid,
			gid,
			_thread_bound: PhantomData,
		})
	}

	/// Rechecks the same thread and exact observable credentials.
	///
	/// # Errors
	/// Refuses drift or an inspection failure.
	pub fn recheck(&self) -> Result<(), StageError> {
		if &Self::observe()? != self {
			return Err(StageError::IdentityChanged);
		}
		Ok(())
	}
}

fn stable_unprivileged(status: &[u8], uid: u32, gid: u32) -> bool {
	let field = |name: &[u8]| {
		let mut matches = status
			.split(|&byte| byte == b'\n')
			.filter_map(|row| row.strip_prefix(name));
		let first = matches.next()?;
		matches.next().is_none().then_some(first)
	};
	let equal_ids = |name: &[u8], expected| {
		field(name).is_some_and(|values| {
			let mut columns = values
				.split(u8::is_ascii_whitespace)
				.filter(|value| !value.is_empty());
			let exact = (0..4).all(|_| {
				columns.next().is_some_and(|value| {
					str::from_utf8(value)
						.ok()
						.and_then(|id| id.parse::<u32>().ok())
						== Some(expected)
				})
			});
			exact && columns.next().is_none()
		})
	};
	let zero =
		|name: &[u8]| field(name).is_some_and(|value| value.trim_ascii() == b"0000000000000000");
	equal_ids(b"Uid:", uid)
		&& equal_ids(b"Gid:", gid)
		&& [b"CapEff:", b"CapPrm:", b"CapAmb:"]
			.into_iter()
			.all(|name| zero(name))
}

#[cfg(test)]
mod tests {
	use super::stable_unprivileged;

	#[test]
	fn rejects_capabilities_drift_duplicate_and_malformed_thread_status() {
		let clean = b"Uid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\n";
		assert!(stable_unprivileged(clean, 1000, 1001));
		assert!(!stable_unprivileged(clean, 1000, 1003));
		for stamp in [b"CapAmb:", b"CapPrm:", b"CapEff:"] {
			let start = clean
				.windows(stamp.len())
				.position(|row| row == stamp)
				.unwrap();
			let mut changed = clean.to_vec();
			changed[start + stamp.len() + 1] = b'1';
			assert!(!stable_unprivileged(&changed, 1000, 1001));
		}
		assert!(!stable_unprivileged(
			&[clean.as_slice(), b"Uid: 1000 1000 1000 1000\n"].concat(),
			1000,
			1001
		));
		assert!(!stable_unprivileged(&clean[..clean.len() - 3], 1000, 1001));
	}
}
