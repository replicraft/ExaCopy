use std::error::Error;
use std::io;

use rustix::io::Errno;

use super::{PlanBundleError, ReadError};

#[test]
fn checked_directory_open_refuses_unsafe_resolution() {
	for errno in [Errno::LOOP, Errno::XDEV, Errno::NOTDIR] {
		let error = PlanBundleError::bundle_open(errno);
		assert!(
			matches!(error, PlanBundleError::Unsafe(Some(_))),
			"checked directory open with {errno:?} must report unsafe resolution: {error:?}"
		);
		assert!(!error.is_existing_name(), "unsafe resolution forbids reuse");
		assert_eq!(error.to_string(), "plan bundle directory is unsafe");
		assert_native_cause(&error, errno);
	}
}

#[test]
fn ordinary_open_and_mount_failures_keep_their_io_cause() {
	let errors = [
		(PlanBundleError::bundle_open(Errno::NOENT), Errno::NOENT),
		(PlanBundleError::bundle_open(Errno::EXIST), Errno::EXIST),
		(
			PlanBundleError::mount_observation(Errno::IO.into()),
			Errno::IO,
		),
		(PlanBundleError::io(Errno::NOSPC), Errno::NOSPC),
	];
	for (error, errno) in errors {
		assert!(
			matches!(error, PlanBundleError::Io(_)),
			"I/O failure {errno:?} must retain its classification: {error:?}"
		);
		assert!(
			!error.is_existing_name(),
			"I/O error cannot authorize reuse"
		);
		assert_eq!(error.to_string(), "plan bundle filesystem operation failed");
		assert_native_cause(&error, errno);
	}
}

#[test]
fn unsupported_mount_evidence_reports_unestablished_scope() {
	const DETAIL: &str = "synthetic protected mount observation";
	let observation = io::Error::new(io::ErrorKind::Unsupported, DETAIL);
	let error = PlanBundleError::mount_observation(observation);

	assert!(
		matches!(error, PlanBundleError::Scope(Some(_))),
		"unsupported mount observation must report scope uncertainty: {error:?}"
	);
	assert!(!error.is_existing_name(), "scope uncertainty forbids reuse");
	assert_eq!(error.to_string(), "plan bundle scope is not established");
	let source = error
		.source()
		.and_then(|source| source.downcast_ref::<io::Error>())
		.expect("scope failure retains the original mount observation");
	assert_eq!(source.kind(), io::ErrorKind::Unsupported);
	assert_eq!(source.to_string(), DETAIL);
}

#[test]
fn only_an_exclusive_create_collision_permits_incumbent_verification() {
	let error = PlanBundleError::AlreadyExists(Errno::EXIST.into());

	assert!(
		error.is_existing_name(),
		"exclusive create found an incumbent"
	);
	assert_eq!(error.to_string(), "plan bundle name is occupied");
	assert_native_cause(&error, Errno::EXIST);
}

#[test]
fn bundle_policy_refusals_have_distinct_diagnostics_and_no_native_cause() {
	let cases = [
		(
			PlanBundleError::InvalidOutput,
			"invalid plan bundle output selection",
		),
		(
			PlanBundleError::Scope(None),
			"plan bundle scope is not established",
		),
		(
			PlanBundleError::Unsafe(None),
			"plan bundle directory is unsafe",
		),
		(
			PlanBundleError::Conflict,
			"plan bundle record conflicts with the selection",
		),
	];
	for (error, message) in cases {
		assert_eq!(error.to_string(), message, "wrong diagnostic for {error:?}");
		assert!(error.source().is_none(), "unexpected cause for {error:?}");
		assert!(!error.is_existing_name(), "refusal cannot authorize reuse");
	}
}

#[test]
fn failed_incumbent_read_preserves_the_typed_read_failure_and_its_cause() {
	let error = PlanBundleError::ReuseRead(ReadError::System(Errno::ACCESS.into()));

	assert!(
		!error.is_existing_name(),
		"failed read cannot authorize reuse"
	);
	assert_eq!(
		error.to_string(),
		"incumbent plan page could not be safely read"
	);
	let source = error
		.source()
		.and_then(|source| source.downcast_ref::<ReadError>())
		.expect("page reuse must expose the typed read failure");
	assert!(
		matches!(source, ReadError::System(_)),
		"expected a read syscall failure, got {source:?}"
	);
	assert_native_cause(source, Errno::ACCESS);
}

fn assert_native_cause(error: &dyn Error, errno: Errno) {
	let cause = error
		.source()
		.and_then(|source| source.downcast_ref::<io::Error>());
	assert_eq!(
		cause.and_then(io::Error::raw_os_error),
		Some(errno.raw_os_error()),
		"wrong native cause for {error:?}"
	);
}
