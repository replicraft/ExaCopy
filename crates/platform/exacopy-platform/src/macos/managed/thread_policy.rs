use std::io;

use apfs_mounted::dataless::{self, PolicyError as NativePolicyError, ScopeError};

#[derive(Debug)]
pub(super) enum PolicyError {
	Configure(io::Error),
	Restore(io::Error),
}

pub(super) fn with_materialization_disabled<T, E: From<PolicyError>>(
	operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
	finish_scope(dataless::with_materialization_disabled(operation))
}

fn finish_scope<T, E: From<PolicyError>>(
	scope: Result<Result<T, E>, ScopeError<Result<T, E>>>,
) -> Result<T, E> {
	match scope {
		Ok(outcome) => outcome,
		Err(ScopeError::Configure {
			error,
			restoration: None,
		}) => Err(PolicyError::Configure(policy_io(error)).into()),
		Err(ScopeError::Configure {
			error,
			restoration: Some(restoration),
		}) => {
			let kind = policy_kind(&restoration);
			let causes = ScopeError::<()>::Configure {
				error,
				restoration: Some(restoration),
			};
			Err(PolicyError::Restore(io::Error::new(kind, causes)).into())
		}
		Err(ScopeError::Restore { error, .. }) => {
			// Existing effectful callers keep their independent operation
			// observations and refuse success if restoration fails.
			Err(PolicyError::Restore(policy_io(error)).into())
		}
		Err(error) => Err(PolicyError::Restore(io::Error::new(
			io::ErrorKind::Unsupported,
			error.to_string(),
		))
		.into()),
	}
}

fn policy_io(error: NativePolicyError) -> io::Error {
	match error {
		NativePolicyError::Io(error) => error,
		error => io::Error::new(io::ErrorKind::Unsupported, error),
	}
}

fn policy_kind(error: &NativePolicyError) -> io::ErrorKind {
	match error {
		NativePolicyError::Io(error) => error.kind(),
		_ => io::ErrorKind::Unsupported,
	}
}

#[cfg(test)]
mod tests;
