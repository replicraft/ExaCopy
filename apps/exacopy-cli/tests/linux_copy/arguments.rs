use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;

use super::{Fixture, OsStr, PROFILE, fs, job_directory, json};

#[test]
fn escaped_raw_paths_and_trailing_options_keep_their_original_meaning() {
	let fixture = Fixture::with_profile();
	let source = OsStr::from_bytes(b"-raw-source\xff");
	let profile = OsStr::from_bytes(b"--raw-profile\xfe");
	let target = "--format";
	let payload = b"raw arguments reach the original Linux operations";
	fs::write(fixture.path(source), payload).expect("write raw source");
	let initialized = fixture
		.command()
		.args(["profile", "init", "--"])
		.arg(profile)
		.output()
		.expect("initialize raw profile");
	assert!(initialized.status.success(), "{initialized:?}");

	let report = json(
		fixture
			.command()
			.args(["copy", "--"])
			.arg(source)
			.arg(target)
			.arg("--profile")
			.arg(profile)
			.args(["--format", "json"])
			.output()
			.expect("invoke escaped copy"),
		0,
	);
	assert_eq!(
		fs::read(fixture.path(source)).expect("preserve source"),
		payload
	);
	assert_eq!(
		fs::read(fixture.path(target)).expect("publish exact target"),
		payload
	);
	let job = job_directory(&fixture, &report);
	let inspection = fixture
		.command()
		.args(["recover", "inspect", "--"])
		.arg(job)
		.arg("--profile")
		.arg(profile)
		.args(["--format", "json"])
		.output()
		.expect("inspect with the same raw profile");
	assert!(inspection.status.success(), "{inspection:?}");
	let report: serde_json::Value =
		serde_json::from_slice(&inspection.stdout).expect("read recovery report");
	assert_eq!(report["schema"], "exacopy.local_recovery_inspection");
}

#[test]
fn incomplete_or_duplicate_copy_grants_create_no_job_and_preserve_existing_objects() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"source").expect("write source");
	fs::write(fixture.path("incumbent"), b"prior contents").expect("write incumbent");
	let incumbent = fs::metadata(fixture.path("incumbent")).expect("stat incumbent");
	for target in ["absent", "incumbent"] {
		for options in [
			&["--profile"][..],
			&["--profile", "--format", "json"],
			&["--profile", PROFILE, "--profile", PROFILE],
		] {
			let output = fixture
				.command()
				.args(["copy", "source", target])
				.args(options)
				.output()
				.expect("invoke copy with malformed grant");
			assert_eq!(output.status.code(), Some(2), "{target} {options:?}");
			assert!(output.stdout.is_empty());
			assert!(!output.stderr.is_empty());
			assert!(fixture.jobs().is_empty());
			assert_eq!(
				fixture
					.path("absent")
					.symlink_metadata()
					.expect_err("absent target")
					.kind(),
				ErrorKind::NotFound
			);
			let current = fs::metadata(fixture.path("incumbent")).expect("stat retained incumbent");
			assert_eq!(current.ino(), incumbent.ino());
			assert_eq!(
				fs::read(fixture.path("incumbent")).expect("read incumbent"),
				b"prior contents"
			);
			assert_eq!(
				fs::read(fixture.path("source")).expect("read source"),
				b"source"
			);
		}
	}
}

#[test]
fn incomplete_source_grants_preserve_an_existing_recovery_journal() {
	let fixture = Fixture::with_profile();
	let payload = b"retained copy evidence";
	fs::write(fixture.path("source"), payload).expect("write source");
	let report = json(
		fixture
			.copy("source", "target")
			.output()
			.expect("publish fixture copy"),
		0,
	);
	let job = job_directory(&fixture, &report);
	let journal = job.join("journal/00000000000000000001.exajnl");
	let original = fs::read(&journal).expect("read committed journal");
	for action in ["retry", "resume"] {
		for options in [
			&["--profile", PROFILE, "--source-root"][..],
			&[
				"--source-root",
				".",
				"--source-root",
				".",
				"--profile",
				PROFILE,
			],
		] {
			let output = fixture
				.command()
				.args(["recover", action])
				.arg(&job)
				.args(options)
				.output()
				.expect("invoke recovery with malformed grant");
			assert_eq!(output.status.code(), Some(2), "{action} {options:?}");
			assert!(output.stdout.is_empty());
			assert_eq!(
				fs::read(&journal).expect("retain exact journal bytes"),
				original
			);
			assert_eq!(
				fs::read(fixture.path("source")).expect("retain source"),
				payload
			);
			assert_eq!(
				fs::read(fixture.path("target")).expect("retain target"),
				payload
			);
		}
	}
}
