use std::io;
use std::marker::PhantomData;

use libc::c_int;

// Constants and declarations from Darwin SDK <sys/resource.h>. The pinned
// libc does not supply these declarations.
const POLICY_TYPE: c_int = 3; // IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES
const THREAD_SCOPE: c_int = 1; // IOPOL_SCOPE_THREAD
const DEFAULT: c_int = 0; // IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT
const OFF: c_int = 1; // IOPOL_MATERIALIZE_DATALESS_FILES_OFF
const ON: c_int = 2; // IOPOL_MATERIALIZE_DATALESS_FILES_ON

unsafe extern "C" {
	fn getiopolicy_np(iotype: c_int, scope: c_int) -> c_int;
	fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
}

#[derive(Debug)]
pub(super) enum PolicyError {
	Configure(io::Error),
	Restore(io::Error),
}

pub(super) fn with_materialization_disabled<T, E: From<PolicyError>>(
	operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
	let mut guard = RestorePolicy::enter().map_err(PolicyError::Configure)?;
	let result = match current() {
		Ok(OFF) => operation(),
		Ok(_) => Err(PolicyError::Configure(io::ErrorKind::Unsupported.into()).into()),
		Err(error) => Err(PolicyError::Configure(error).into()),
	};
	guard.restore().map_err(PolicyError::Restore)?;
	result
}

struct RestorePolicy {
	previous: Option<c_int>,
	// The prior policy belongs to the entering OS thread.
	thread_bound: PhantomData<*const ()>,
}

impl RestorePolicy {
	fn enter() -> io::Result<Self> {
		let previous = current()?;
		let previous = if previous == OFF {
			None
		} else {
			set(OFF)?;
			Some(previous)
		};
		Ok(Self {
			previous,
			thread_bound: PhantomData,
		})
	}

	fn restore(&mut self) -> io::Result<()> {
		if let Some(previous) = self.previous {
			set(previous)?;
			if current()? != previous {
				return Err(io::ErrorKind::Unsupported.into());
			}
			self.previous = None;
		}
		Ok(())
	}
}

impl Drop for RestorePolicy {
	fn drop(&mut self) {
		// Best effort on unwind or after an explicit restore error. The normal
		// return path reports restoration errors and suppresses the result.
		let _ = self.restore();
	}
}

fn current() -> io::Result<c_int> {
	// SAFETY: The Darwin call takes scalar constants and no pointers and
	// returns the policy of the current thread or -1 with errno.
	match unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) } {
		policy @ (DEFAULT | OFF | ON) => Ok(policy),
		-1 => Err(io::Error::last_os_error()),
		_ => Err(io::ErrorKind::Unsupported.into()),
	}
}

fn set(policy: c_int) -> io::Result<()> {
	// SAFETY: The Darwin call takes scalar values and no pointers. The only
	// inputs come from OFF or a previously validated Darwin thread policy.
	if unsafe { setiopolicy_np(POLICY_TYPE, THREAD_SCOPE, policy) } == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

#[test]
fn scoped_policy_restores_on_success_error_and_unwind() {
	use super::ManagedReadError;

	let original = current().expect("read initial policy");
	let separate_thread = || {
		std::thread::spawn(current)
			.join()
			.expect("join separate policy observer")
			.expect("read separate thread policy")
	};
	let separate_before = separate_thread();

	with_materialization_disabled(|| {
		assert_eq!(current().expect("read scoped policy"), OFF);
		assert_eq!(separate_thread(), separate_before);
		Ok::<_, ManagedReadError>(())
	})
	.expect("restore policy after successful operation");
	assert_eq!(current().expect("read restored policy"), original);

	let failed = with_materialization_disabled(|| {
		assert_eq!(current().expect("read scoped policy"), OFF);
		Err::<(), _>(ManagedReadError::UnsupportedChild)
	});
	assert!(matches!(failed, Err(ManagedReadError::UnsupportedChild)));
	assert_eq!(
		current().expect("read restored policy after rejection"),
		original
	);

	let panicked = std::panic::catch_unwind(|| {
		with_materialization_disabled::<(), ManagedReadError>(|| {
			assert_eq!(current().expect("read scoped policy"), OFF);
			panic!("synthetic reader unwind");
		})
	});
	assert!(panicked.is_err());
	assert_eq!(
		current().expect("read restored policy after unwind"),
		original
	);
}
