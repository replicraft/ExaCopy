//! Public protected snapshot refusal diagnostics.

use std::error::Error;
use std::path::Path;

use exacopy_platform::{ProtectedSnapshotError, read_protected_snapshot};

#[test]
fn snapshot_refusals_explain_the_failure_without_exposing_an_underlying_cause() {
	let cases = [
		(ProtectedSnapshotError::Unsupported, "unsupported"),
		(ProtectedSnapshotError::InvalidPath, "invalid"),
		(
			ProtectedSnapshotError::Unprotected,
			"permissions or file type",
		),
		(ProtectedSnapshotError::Busy, "locked"),
		(ProtectedSnapshotError::TooLarge, "byte limit"),
		(ProtectedSnapshotError::Changed, "changed"),
		(ProtectedSnapshotError::Unavailable, "unavailable"),
	];
	for (error, reason) in cases {
		assert!(
			error.to_string().contains(reason),
			"{error:?} must identify the refusal reason with {reason:?}"
		);
		assert!(
			error.source().is_none(),
			"{error:?} exposed an underlying cause"
		);
	}
}

#[test]
fn rejected_snapshot_input_does_not_appear_in_the_diagnostic() {
	let path = Path::new("fixture-private-directory/fixture-private-leaf");
	let error = read_protected_snapshot(path).expect_err("a relative path must be refused");
	assert!(
		matches!(
			error,
			ProtectedSnapshotError::InvalidPath | ProtectedSnapshotError::Unsupported
		),
		"the snapshot input must fail admission, got {error:?}"
	);
	let diagnostic = error.to_string();
	for private_component in ["fixture-private-directory", "fixture-private-leaf"] {
		assert!(
			!diagnostic.contains(private_component),
			"the diagnostic disclosed a component of the rejected path"
		);
	}
}
