use apfs_mounted::dataless::{ThreadPolicy, thread_policy};

use super::*;
use crate::macos::ManagedReadError;

#[test]
fn scoped_policy_restores_on_success_error_and_unwind() {
	let original = thread_policy().expect("read initial policy");
	let separate_thread = || {
		std::thread::spawn(thread_policy)
			.join()
			.expect("join separate policy observer")
			.expect("read separate thread policy")
	};
	let separate_before = separate_thread();

	with_materialization_disabled(|| {
		assert_eq!(
			thread_policy().expect("read scoped policy"),
			ThreadPolicy::Disabled
		);
		assert_eq!(separate_thread(), separate_before);
		Ok::<(), ManagedReadError>(())
	})
	.expect("restore policy after successful operation");
	assert_eq!(thread_policy().expect("read restored policy"), original);

	let failed = with_materialization_disabled(|| {
		assert_eq!(
			thread_policy().expect("read scoped policy"),
			ThreadPolicy::Disabled
		);
		Err::<(), _>(ManagedReadError::UnsupportedChild)
	});
	assert!(matches!(failed, Err(ManagedReadError::UnsupportedChild)));
	assert_eq!(
		thread_policy().expect("read restored policy after rejection"),
		original
	);

	let panicked = std::panic::catch_unwind(|| {
		with_materialization_disabled::<(), ManagedReadError>(|| {
			assert_eq!(
				thread_policy().expect("read scoped policy"),
				ThreadPolicy::Disabled
			);
			panic!("synthetic reader unwind");
		})
	});
	assert!(panicked.is_err());
	assert_eq!(
		thread_policy().expect("read restored policy after unwind"),
		original
	);
}

fn policy_error(errno: i32) -> NativePolicyError {
	NativePolicyError::Io(io::Error::from_raw_os_error(errno))
}

#[test]
fn configuration_and_failed_rollback_both_remain_available() {
	let scope = Err(ScopeError::Configure {
		error: policy_error(libc::EIO),
		restoration: Some(policy_error(libc::EPERM)),
	});
	let Err(ManagedReadError::RestoreMaterializationPolicy(error)) =
		finish_scope::<(), ManagedReadError>(scope)
	else {
		panic!("failed policy rollback must have restore-error precedence");
	};
	let causes = error
		.get_ref()
		.and_then(|cause| cause.downcast_ref::<ScopeError<()>>())
		.expect("retain both underlying errors");
	assert!(matches!(causes,
		ScopeError::Configure {
			error: NativePolicyError::Io(error),
			restoration: Some(NativePolicyError::Io(restoration)),
		} if error.raw_os_error() == Some(libc::EIO)
			&& restoration.raw_os_error() == Some(libc::EPERM)
	));
}

#[test]
fn a_single_policy_error_retains_its_original_errno() {
	let configure = finish_scope::<(), ManagedReadError>(Err(ScopeError::Configure {
		error: policy_error(libc::EIO),
		restoration: None,
	}));
	assert!(
		matches!(configure, Err(ManagedReadError::MaterializationPolicy(error))
		if error.raw_os_error() == Some(libc::EIO))
	);
	let restore = finish_scope::<(), ManagedReadError>(Err(ScopeError::Restore {
		outcome: Ok(()),
		error: policy_error(libc::EPERM),
	}));
	assert!(
		matches!(restore, Err(ManagedReadError::RestoreMaterializationPolicy(error))
		if error.raw_os_error() == Some(libc::EPERM))
	);
}
