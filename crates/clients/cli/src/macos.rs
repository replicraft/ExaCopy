use std::num::NonZeroUsize;
use std::path::{self, Path};

use exacopy_diff::{Side, macos};
use exacopy_endpoint::UnixComponent;
use exacopy_platform::macos::{ManagedReadGrant, ManagedReadRoot, ManagedRegularFile};

use crate::diff;
use crate::report::{ErrorCode, Failure, Outcome};
use crate::unix_path::split;

pub(crate) fn compare(left: &Path, right: &Path, workers: Option<NonZeroUsize>) -> Outcome {
	match compare_files(left, right, workers) {
		Ok(outcome) => outcome,
		Err(error) => Outcome::Inconclusive { error },
	}
}

fn compare_files(
	left: &Path,
	right: &Path,
	workers: Option<NonZeroUsize>,
) -> Result<Outcome, Failure> {
	let (left_root, left_name) = open_parent(left, Side::Left)?;
	let (right_root, right_name) = open_parent(right, Side::Right)?;
	let left = open_file(&left_root, left_name, Side::Left)?;
	let right = open_file(&right_root, right_name, Side::Right)?;
	diff::compare(|scratch| match workers {
		Some(workers) => macos::compare_parallel(&left, &right, scratch, workers),
		None => macos::compare(&left, &right, scratch),
	})
}

fn open_parent(path: &Path, side: Side) -> Result<(ManagedReadRoot, UnixComponent<'_>), Failure> {
	let (parent, name) = split(path).map_err(|error| Failure {
		code: ErrorCode::InvalidPath,
		message: format!("{side} input path is invalid ({error})"),
	})?;
	let parent = path::absolute(parent).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not resolve the {side} input directory ({error})"),
	})?;
	// Command dispatch reaches this path only with the explicit attestation flag.
	let grant = ManagedReadGrant::trusted_owner_authorizes_provisioned_root();
	let root = ManagedReadRoot::open_provisioned_path(&parent, grant).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not bind the {side} input directory ({error})"),
	})?;
	Ok((root, name))
}

fn open_file<'root>(
	root: &'root ManagedReadRoot,
	name: UnixComponent<'root>,
	side: Side,
) -> Result<ManagedRegularFile<'root>, Failure> {
	root.open_regular(name).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not open the {side} input file ({error})"),
	})
}
