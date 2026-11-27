//! Independent invocation and wire expectations for the real managed-sync CLI.

use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::managed_sync::ManagedPolicy;
use exacopy_manifest::sync_baseline::LinuxOwnerMode;
use rustix::fs::OFlags;
use serde_json::{Value, json};

use super::cli_format::{Approval, hex};
use super::cli_process::{Cli, Output};
use super::history::Artifact;
use super::rig::{Sandbox, assert_live, assert_missing, open_child, read};
use super::{SEED, TestResult, post_creation};

const SELECTED: [u8; 16] = [0xb1; 16];
const UNDELIVERED: [u8; 16] = [0xb2; 16];
pub(super) const REVISION: u64 = 13;
const SENTINEL: &[u8] = b"no acknowledgement reached this read-only descriptor";
pub(super) const ACK_BYTES: usize = 435;

pub(super) struct Inputs<'a> {
	pub(super) policy: &'a ManagedPolicy,
	pub(super) owner_profile: [u8; 16],
	pub(super) signer: &'a SigningKey,
	pub(super) live: [&'a File; 2],
	pub(super) history: &'a File,
	pub(super) artifacts: &'a [Artifact; 4],
}

pub(super) fn exercise(sandbox: &mut Sandbox, selected: Inputs<'_>) -> TestResult<String> {
	let cli = Cli::from_runner()?;
	let directory = sandbox.directory.try_clone()?;
	let profile = sandbox.mkdir(&directory, b"cli-profile")?;
	let path = sandbox.path.join("cli-profile");
	sandbox.write_new(&profile, b"owner.seed", &SEED)?;
	let held = profile.metadata()?;
	let approval = Approval::new(&path, held.dev(), held.ino(), SELECTED, &selected)?;
	let undelivered = Approval::new(&path, held.dev(), held.ino(), UNDELIVERED, &selected)?;
	let other = SigningKey::from_bytes(&[0x67; 32]).verifying_key();
	let seed = open_regular(&profile, b"owner.seed")?;
	let seed_before = read_held(&profile, b"owner.seed", &seed, &SEED)?;
	let mut args: Vec<OsString> = ["sync-managed", "profile-identity", "--profile"]
		.map(OsString::from)
		.into();
	args.push(path.clone().into_os_string());
	expect_report(
		cli.invoke(&args, b"", None)?,
		0,
		&json!({
			"owner_profile": hex(&selected.owner_profile),
			"owner_key": hex(selected.signer.verifying_key().as_bytes()),
			"device": held.dev().to_string(), "inode": held.ino().to_string(),
		}),
	)?;
	assert_eq!(
		read_held(&profile, b"owner.seed", &seed, &SEED)?,
		seed_before
	);
	assert_eq!(
		stable_metadata(&profile.metadata()?),
		stable_metadata(&held)
	);
	// The identity observation only corroborates approval independently derived above.
	let slots = [approval.slot(), undelivered.slot()];
	for name in &slots {
		assert_missing(&profile, name.as_bytes());
	}

	let mut offered = approval.clone();
	offered.owner = other;
	expect_init_refusal(
		cli.invoke(&offered.init(), &approval.envelope, None)?,
		"policy_refused",
	);
	offered = approval.clone();
	offered.selection = UNDELIVERED;
	expect_init_refusal(
		cli.invoke(&offered.init(), &approval.envelope, None)?,
		"policy_refused",
	);
	offered = approval.clone();
	offered.digest[0] ^= 1;
	expect_init_refusal(
		cli.invoke(&offered.init(), &approval.envelope, None)?,
		"policy_refused",
	);
	offered = approval.clone();
	offered.inode = directory.metadata()?.ino();
	expect_init_refusal(
		cli.invoke(&offered.init(), &approval.envelope, None)?,
		"selection_mismatch",
	);
	for name in &slots {
		assert_missing(&profile, name.as_bytes());
	}

	let ack = cli.invoke(&approval.init(), &approval.envelope, None)?;
	if ack.status.success() {
		sandbox.track_created_slot(&profile, slots[0].as_bytes())?;
	}
	assert_eq!(
		ack.status.code(),
		Some(0),
		"Init stderr {:?}",
		String::from_utf8_lossy(&ack.stderr)
	);
	assert!(ack.stderr.is_empty());
	approval.verify(&ack.stdout);
	let sealed = Slot::read(&profile, &slots[0], &approval.envelope)?;
	expect_init_refusal(
		cli.invoke(&approval.init(), &approval.envelope, None)?,
		"selection_occupied",
	);
	sealed.recheck(&profile, &slots[0])?;

	sandbox.write_new(&directory, b"delivery-sentinel", SENTINEL)?;
	let readonly = open_child(&directory, b"delivery-sentinel", OFlags::RDONLY)?;
	let delivery = cli.invoke(&undelivered.init(), &undelivered.envelope, Some(readonly))?;
	assert_eq!(delivery.status.code(), Some(2));
	assert!(delivery.stdout.is_empty());
	assert_eq!(
		delivery.stderr,
		b"exacopy: managed sync Init delivery_uncertain; selection slot retained\n"
	);
	sandbox.track_created_slot(&profile, slots[1].as_bytes())?;
	let occupied = Slot::read(&profile, &slots[1], &undelivered.envelope)?;
	expect_init_refusal(
		cli.invoke(&undelivered.init(), &undelivered.envelope, None)?,
		"selection_occupied",
	);

	sandbox.rename(&profile, b"owner.seed", b"retained-cli-seed")?;
	assert_missing(&profile, b"owner.seed");
	let preview = approval.preview();
	expect_blocked(
		cli.invoke(&undelivered.preview(), b"", None)?,
		"acknowledgement_refused",
	)?;
	let mut offered = approval.clone();
	offered.owner = other;
	expect_blocked(
		cli.invoke(&offered.preview(), &ack.stdout, None)?,
		"acknowledgement_refused",
	)?;
	expect_blocked(
		cli.invoke(&undelivered.preview(), &ack.stdout, None)?,
		"acknowledgement_refused",
	)?;
	let mut corrupt = ack.stdout.clone();
	corrupt[ACK_BYTES - 2] = if corrupt[ACK_BYTES - 2] == b'0' {
		b'1'
	} else {
		b'0'
	};
	expect_blocked(
		cli.invoke(&preview, &corrupt, None)?,
		"acknowledgement_refused",
	)?;

	let output = cli.invoke(&preview, &ack.stdout, None)?;
	let meta = LinuxOwnerMode {
		mode: 0o600,
		uid: selected.policy.actor_uid.get(),
		gid: selected.policy.actor_gid.get(),
	};
	let metadata = hex(&meta.digest()?);
	let evidence = |bytes| {
		json!({
			"state": "present", "bytes": 3, "stream_digest": hex(blake3::hash(bytes).as_bytes()),
			"required_metadata_digest": metadata,
		})
	};
	expect_report(
		output,
		0,
		&json!({
			"status": "copy_candidate", "from": "right", "target": "existing_incumbent",
			"left": evidence(b"abc"), "right": evidence(b"xyz"),
			"selection": {"id": hex(&SELECTED), "revision": REVISION.to_string()},
			"history": "authenticated_p063", "scope": "one_subject", "scope_complete": true,
			"consistency": "live_observed", "comparison": "independent_blake3_unnamed_stream",
			"required_metadata": "linux_owner_and_mode_v1", "omitted_metadata": "all_other_metadata",
			"max_file_bytes": 64 * 1024 * 1024, "baseline_advanced": false,
		}),
	)?;

	let root = &selected.policy.history.root.name;
	let retained = b"retained-cli-history";
	sandbox.rename(selected.history, root, retained)?;
	expect_blocked(
		cli.invoke(&preview, &ack.stdout, None)?,
		"selected_history_missing",
	)?;
	sandbox.rename(selected.history, retained, root)?;
	sealed.recheck(&profile, &slots[0])?;
	occupied.recheck(&profile, &slots[1])?;
	assert_eq!(read(&directory, b"delivery-sentinel")?, SENTINEL);
	assert_eq!(read(&profile, b"retained-cli-seed")?, SEED);
	assert_missing(&profile, b"owner.seed");
	post_creation::verify_history(selected.history, selected.artifacts)?;
	assert_live(selected.live, [b"abc", b"xyz"])?;
	cli.verify_digest()?;
	Ok(cli.sha256)
}

fn expect_init_refusal(output: Output, reason: &str) {
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	assert_eq!(
		output.stderr,
		format!("exacopy: managed sync Init refused ({reason})\n").as_bytes()
	);
}

fn expect_blocked(output: Output, reason: &str) -> TestResult {
	expect_report(
		output,
		2,
		&json!({
			"status": "blocked", "reason": reason, "history": "required_p063",
			"scope": "one_subject", "scope_complete": false, "baseline_advanced": false,
		}),
	)
}

fn expect_report(output: Output, code: i32, report: &Value) -> TestResult {
	assert_eq!(
		output.status.code(),
		Some(code),
		"{:?}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(output.stderr.is_empty());
	let mut expected = serde_json::to_vec(report)?;
	expected.push(b'\n');
	assert_eq!(output.stdout, expected);
	Ok(())
}

struct Slot {
	held: File,
	stamp: StableMetadata,
	bytes: Vec<u8>,
}

impl Slot {
	fn read(profile: &File, name: &str, expected: &[u8]) -> TestResult<Self> {
		let held = open_regular(profile, name.as_bytes())?;
		let stamp = read_held(profile, name.as_bytes(), &held, expected)?;
		Ok(Self {
			held,
			stamp,
			bytes: expected.to_vec(),
		})
	}

	fn recheck(&self, profile: &File, name: &str) -> TestResult {
		assert_eq!(
			read_held(profile, name.as_bytes(), &self.held, &self.bytes)?,
			self.stamp
		);
		Ok(())
	}
}

fn open_regular(parent: &File, name: &[u8]) -> TestResult<File> {
	Ok(open_child(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?)
}

fn read_held(
	parent: &File,
	name: &[u8],
	held: &File,
	expected: &[u8],
) -> TestResult<StableMetadata> {
	let meta = held.metadata()?;
	let stamp = stable_metadata(&meta);
	assert!(meta.is_file());
	assert_eq!((stamp.mode & 0o7777, stamp.links), (0o600, 1));
	assert_eq!(stamp.size, u64::try_from(expected.len())?);
	assert!(expected.len() <= 24 * 1024);
	let mut bytes = vec![0; expected.len()];
	held.read_exact_at(&mut bytes, 0)?;
	assert_eq!(held.read_at(&mut [0; 1], stamp.size)?, 0);
	assert_eq!(bytes, expected);
	assert_eq!(stable_metadata(&held.metadata()?), stamp);
	let named = open_regular(parent, name)?;
	assert_eq!(stable_metadata(&named.metadata()?), stamp);
	Ok(stamp)
}

#[derive(Debug, PartialEq, Eq)]
struct StableMetadata {
	identity: (u64, u64),
	links: u64,
	mode: u32,
	owner: (u32, u32),
	size: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}

fn stable_metadata(meta: &Metadata) -> StableMetadata {
	StableMetadata {
		identity: (meta.dev(), meta.ino()),
		links: meta.nlink(),
		mode: meta.mode(),
		owner: (meta.uid(), meta.gid()),
		size: meta.size(),
		modified: (meta.mtime(), meta.mtime_nsec()),
		changed: (meta.ctime(), meta.ctime_nsec()),
	}
}
