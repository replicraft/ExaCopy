//! Process tests for the single-file Linux copy and local profile routes.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{OwnerProfileId, OwnerRecord, ReceiptCommitted};
use exacopy_transfer::linux::{CopyReceipt, LocalCopyPlan};
use serde_json::Value;
use uuid::{Builder, Uuid};

const PROFILE: &str = "profile";
const SEED: &str = "profile/owner.seed";

#[test]
fn publishes_raw_name_and_retains_authenticated_job_and_matching_receipt() {
	let fixture = Fixture::with_profile();
	let source = OsStr::from_bytes(b"-raw\xff\nsource");
	let target = OsStr::from_bytes(b"raw\xfe\ntarget");
	let contents = b"verified synthetic contents\0\xff";
	fs::write(fixture.path(source), contents).expect("write synthetic source");
	fs::set_permissions(fixture.path(source), Permissions::from_mode(0o640))
		.expect("set source mode");
	let original = fs::metadata(fixture.path(source)).expect("stat source");

	let report = json(
		fixture.copy(source, target).output().expect("invoke copy"),
		0,
	);
	assert_eq!(report["result"], "published");
	assert_eq!(report["completed"], 1);
	assert_eq!(report["pending"], 0);
	assert_eq!(report["publication"], "published");
	assert_eq!(report["verification"], "hash_readback");
	assert_eq!(report["consistency"], "live_observed");
	assert_eq!(report["durability"], "unconfirmed");
	assert_eq!(report["preservation"], "preserve");
	assert_eq!(report["redundancy"], "independent_writes");
	assert_eq!(report["metadata"], "complete_for_policy");
	assert_eq!(
		report["receipt"]["blake3"],
		blake3::hash(contents).to_hex().as_str()
	);

	let copied = fs::metadata(fixture.path(target)).expect("stat target");
	assert_ne!(original.ino(), copied.ino());
	assert_eq!(copied.permissions().mode() & 0o777, 0o640);
	assert_eq!(
		fs::read(fixture.path(source)).expect("read source"),
		contents
	);
	assert_eq!(
		fs::read(fixture.path(target)).expect("read target"),
		contents
	);

	let receipt = &report["receipt"];
	let job_id =
		Uuid::parse_str(receipt["job_id"].as_str().expect("job ID")).expect("parse job UUID");
	assert_eq!(job_id.get_version_num(), 7);
	let job = job_directory(&fixture, &report);
	assert_eq!(
		job.file_name().expect("job name"),
		format!(".exacopy-{job_id}").as_str()
	);
	assert_eq!(fs::metadata(&job).expect("stat job").mode() & 0o777, 0o700);

	let bytes = fs::read(job.join("receipts/receipt.cbor")).expect("read receipt");
	let artifact = CopyReceipt::decode(&bytes).expect("decode genuine receipt");
	assert_eq!(artifact.evidence().target.as_bytes(), target.as_bytes());
	assert_eq!(
		*artifact.evidence().context.job.as_bytes(),
		job_id.into_bytes()
	);
	assert_eq!(
		artifact.evidence().stream.length.get().to_string(),
		receipt["length"]
	);
	assert_eq!(
		blake3::Hash::from_bytes(artifact.digest())
			.to_hex()
			.as_str(),
		receipt["receipt_digest"]
	);
	let plan = fs::read(job.join("plan.cbor")).expect("read plan");
	let bound_plan = LocalCopyPlan::decode(&plan).expect("decode genuine plan");
	assert_eq!(bound_plan.context(), artifact.evidence().context);

	let owner = authenticate_owner(&fixture, &job);
	assert_eq!(owner.manifest().job, artifact.evidence().context.job);
	assert_eq!(
		owner.manifest().plan_digest,
		artifact.evidence().context.plan_digest
	);
	assert_ne!(
		owner.manifest().token.as_bytes(),
		owner.manifest().job.as_bytes()
	);
	let journal =
		File::open(job.join("journal/00000000000000000001.exajnl")).expect("open job journal");
	let mut reader = FrameReader::new(journal, ChainHead::start());
	for kind in [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
	] {
		let frame = reader
			.next_frame()
			.expect("read journal frame")
			.expect("journal frame exists");
		assert_eq!(frame.kind(), kind);
	}
	assert_eq!(reader.head(), artifact.durability_frame());
	let frame = reader
		.next_frame()
		.expect("read commitment frame")
		.expect("commitment exists");
	assert_eq!(frame.kind(), FrameKind::ReceiptCommitted);
	let committed = ReceiptCommitted::decode(frame.payload()).expect("read receipt commitment");
	assert_eq!(*committed.digest().as_bytes(), artifact.digest());
	assert_eq!(committed.durability(), artifact.durability_frame());
	assert!(reader.next_frame().expect("read journal EOF").is_none());
	assert!(!job.join("stage/data").exists());
	assert!(!job.join("owner.seed").exists());

	let report = json(
		fixture.copy(source, "second").output().expect("copy again"),
		0,
	);
	let second = authenticate_owner(&fixture, &job_directory(&fixture, &report));
	assert_ne!(owner.manifest().job, second.manifest().job);
	assert_ne!(owner.manifest().token, second.manifest().token);
	assert_eq!(owner.manifest().profile, second.manifest().profile);
}

#[test]
fn refuses_incumbents_symlinks_and_source_aliases_without_starting_a_job() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"source").expect("write source");
	fs::write(fixture.path("incumbent"), b"incumbent").expect("write incumbent");
	fs::hard_link(fixture.path("source"), fixture.path("hardlink")).expect("hard link source");
	symlink("absent", fixture.path("symlink")).expect("create target symlink");

	for target in ["incumbent", "hardlink", "source", "symlink"] {
		let report = json(
			fixture
				.copy("source", target)
				.output()
				.expect("invoke conflict"),
			3,
		);
		assert_eq!(report["error"]["code"], "E_CONFLICT");
		assert_eq!(report["publication"], "not_published");
		assert!(report["error"].get("job_id").is_none());
	}
	assert_eq!(
		fs::read(fixture.path("source")).expect("read source"),
		b"source"
	);
	assert_eq!(
		fs::read(fixture.path("incumbent")).expect("read incumbent"),
		b"incumbent"
	);
	assert_eq!(
		fs::read_link(fixture.path("symlink")).expect("read symlink"),
		Path::new("absent")
	);
	assert!(fixture.jobs().is_empty());
}

#[test]
fn rejects_malformed_and_unsafe_profiles_and_preserves_the_key() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"source").expect("write source");
	let key = fixture.path(SEED);
	let seed = fs::read(&key).expect("read synthetic key");
	assert_eq!(seed.len(), 32);
	assert_eq!(fs::metadata(&key).expect("stat key").mode() & 0o777, 0o600);
	assert_eq!(
		fs::metadata(fixture.path(PROFILE))
			.expect("stat profile")
			.mode()
			& 0o777,
		0o700
	);
	let reinit = fixture
		.command()
		.args(["profile", "init", PROFILE])
		.output()
		.expect("reject reinit");
	assert_eq!(reinit.status.code(), Some(3));
	assert_eq!(fs::read(&key).expect("read original seed"), seed);

	let rejected = |profile: &str| {
		let output = fixture
			.command()
			.args([
				"copy",
				"source",
				"target",
				"--profile",
				profile,
				"--format",
				"json",
			])
			.output()
			.expect("invoke untrusted profile");
		assert_eq!(json(output, 8)["error"]["code"], "E_PROFILE_AUTHORIZATION");
	};

	symlink(PROFILE, fixture.path("profile-link")).expect("symlink profile");
	rejected("profile-link");
	rejected("profile/../missing");
	fs::set_permissions(fixture.path(PROFILE), Permissions::from_mode(0o755))
		.expect("expose directory");
	rejected(PROFILE);
	fs::set_permissions(fixture.path(PROFILE), Permissions::from_mode(0o700))
		.expect("restore directory mode");
	fs::set_permissions(&key, Permissions::from_mode(0o644)).expect("expose key");
	rejected(PROFILE);
	fs::set_permissions(&key, Permissions::from_mode(0o600)).expect("restore seed mode");
	let alias = fixture.path("seed-alias");
	fs::hard_link(&key, &alias).expect("hard link seed");
	rejected(PROFILE);
	fs::remove_file(alias).expect("remove synthetic alias");
	let secret_source = fixture
		.copy(SEED, "target")
		.output()
		.expect("refuse signing seed as source");
	assert_eq!(
		json(secret_source, 8)["error"]["code"],
		"E_PROFILE_AUTHORIZATION"
	);
	fs::rename(&key, fixture.path("saved-seed")).expect("temporarily move seed");
	symlink("../saved-seed", &key).expect("symlink seed");
	rejected(PROFILE);
	fs::remove_file(&key).expect("remove synthetic symlink");
	fs::rename(fixture.path("saved-seed"), &key).expect("restore seed");
	fs::write(&key, [0; 33]).expect("write oversized synthetic seed");
	rejected(PROFILE);
	assert!(!fixture.path("target").exists());
	assert!(fixture.jobs().is_empty());
}

#[test]
fn concurrent_processes_cannot_replace_the_winner() {
	let fixture = Fixture::with_profile();
	for (name, contents) in [
		("left", b"left operand".as_slice()),
		("right", b"right operand"),
	] {
		fs::write(fixture.path(name), contents).expect("write source");
	}
	let spawn = |name| {
		fixture
			.copy(name, "target")
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.spawn()
			.expect("start copy")
	};
	let left = spawn("left");
	let right = spawn("right");
	let left = left.wait_with_output().expect("wait for left copy");
	let right = right.wait_with_output().expect("wait for right copy");
	let (success, conflict, expected) = if left.status.success() {
		(left, right, b"left operand".as_slice())
	} else {
		(right, left, b"right operand".as_slice())
	};
	assert_eq!(json(success, 0)["publication"], "published");
	assert_eq!(json(conflict, 3)["publication"], "not_published");
	assert_eq!(
		fs::read(fixture.path("target")).expect("read winner"),
		expected
	);
	assert_eq!(
		fs::read(fixture.path("left")).expect("read left"),
		b"left operand"
	);
	assert_eq!(
		fs::read(fixture.path("right")).expect("read right"),
		b"right operand"
	);
}

#[test]
fn failed_report_output_keeps_the_committed_copy_and_names_the_job() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"original").expect("write source");
	let full = File::options()
		.write(true)
		.open("/dev/full")
		.expect("open Linux full device");
	let result = fixture
		.copy("source", "target")
		.stdout(full)
		.output()
		.expect("invoke copy with bad output");
	assert_eq!(result.status.code(), Some(4));
	let diagnostic = String::from_utf8(result.stderr).expect("read diagnostic");
	assert!(diagnostic.contains("The copy was published"));
	assert_eq!(
		fs::read(fixture.path("target")).expect("read published target"),
		b"original"
	);
	let jobs = fixture.jobs();
	assert_eq!(jobs.len(), 1);
	assert!(jobs[0].join("receipts/receipt.cbor").is_file());
	assert!(
		diagnostic.contains(
			jobs[0]
				.file_name()
				.expect("job name")
				.to_str()
				.expect("job name UTF-8")
		)
	);
}

fn authenticate_owner(fixture: &Fixture, job: &Path) -> OwnerRecord {
	let seed = fs::read(fixture.path(SEED))
		.expect("read synthetic seed")
		.try_into()
		.expect("fixed seed length");
	let key = SigningKey::from_bytes(&seed).verifying_key();
	let mut profile = [0; 16];
	blake3::Hasher::new_derive_key("ExaCopy local CLI profile ID v1")
		.update(key.as_bytes())
		.finalize_xof()
		.fill(&mut profile);
	let id =
		OwnerProfileId::from_bytes(Builder::from_custom_bytes(profile).into_uuid().into_bytes())
			.expect("valid profile ID");
	let envelope = fs::read(job.join("owner.cbor")).expect("read owner record");
	OwnerRecord::decode(&envelope, id, &key).expect("verify owner record against selected profile")
}

fn job_directory(fixture: &Fixture, report: &Value) -> PathBuf {
	fixture.path(
		report["receipt"]["job_directory"]
			.as_str()
			.expect("reported job directory"),
	)
}

fn json(output: Output, exit: i32) -> Value {
	assert_eq!(
		output.status.code(),
		Some(exit),
		"stdout {} stderr {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout).expect("read JSON");
	assert_eq!(report["schema"], "exacopy.cli.copy");
	assert_eq!(report["schema_version"], "1.0");
	report
}

struct Fixture(PathBuf);

impl Fixture {
	fn with_profile() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		for _ in 0..128 {
			let serial = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir()
				.join(format!("exacopy-cli-copy-{}-{serial}", std::process::id()));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => {
					let fixture = Self(path);
					let output = fixture
						.command()
						.args(["profile", "init", PROFILE])
						.output()
						.expect("initialize profile");
					assert!(
						output.status.success(),
						"{}",
						String::from_utf8_lossy(&output.stderr)
					);
					return fixture;
				}
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create copy fixture: {error}"),
			}
		}
		panic!("exhausted synthetic fixture directory attempts");
	}

	fn path(&self, name: impl AsRef<Path>) -> PathBuf {
		self.0.join(name)
	}

	fn command(&self) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_exacopy"));
		command.current_dir(&self.0);
		command
	}

	fn copy(&self, source: impl AsRef<OsStr>, target: impl AsRef<OsStr>) -> Command {
		let mut command = self.command();
		command.args(["copy", "--"]).arg(source).arg(target).args([
			"--profile",
			PROFILE,
			"--format",
			"json",
		]);
		command
	}

	fn jobs(&self) -> Vec<PathBuf> {
		fs::read_dir(&self.0)
			.expect("list fixture")
			.map(|entry| entry.expect("fixture entry"))
			.filter(|entry| entry.file_name().as_bytes().starts_with(b".exacopy-"))
			.map(|entry| entry.path())
			.collect()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

#[path = "linux_copy/recovery.rs"]
mod recovery;
