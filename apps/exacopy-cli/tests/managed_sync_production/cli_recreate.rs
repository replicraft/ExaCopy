use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_plan::{PlanBody, PlanEntriesPage, PlanOperation};
use rustix::fs::{FlockOperation, flock};

use super::*;

const RETAINED: &[u8] = b"retained-cli-recreate-subject";

pub(super) fn exercise(
	sandbox: &mut Sandbox,
	cli: &Cli,
	approval: &Approval,
	acknowledgement: &[u8],
	inputs: &Inputs<'_>,
) -> TestResult {
	let mut args = approval.preview();
	args[1] = "prepare-recreate".into();
	args.extend([
		"--from".into(),
		"right".into(),
		"--reviewed-conflict".into(),
		"edit-against-deletion".into(),
	]);
	let [left, right] = inputs.live;
	let (left_id, right_id) = (
		file_identity(left, super::super::SUBJECT)?,
		file_identity(right, super::super::SUBJECT)?,
	);
	refused(
		cli.invoke(&args, acknowledgement, None)?,
		"reviewed_conflict_changed",
	)?;
	let names = subject_names(sandbox)?;
	move_subject(sandbox, left, super::super::SUBJECT, RETAINED)?;
	let result = (|| {
		let names_while_absent = subject_names(sandbox)?;
		let output = cli.invoke(&args, acknowledgement, None)?;
		assert_eq!(output.status.code(), Some(0), "stderr {:?}", output.stderr);
		assert!(output.stderr.is_empty());
		let report: Value = serde_json::from_slice(&output.stdout)?;
		assert_envelope(&report, "prepared");
		assert_prepared(&report["review"], approval, inputs, right_id)?;
		let mut wrong = args.clone();
		*wrong.last_mut().unwrap() = "deletion-against-unchanged".into();
		refused(
			cli.invoke(&wrong, acknowledgement, None)?,
			"reviewed_conflict_changed",
		)?;
		let mut changed = acknowledgement.to_vec();
		changed[0] ^= 1;
		refused(
			cli.invoke(&args, &changed, None)?,
			"acknowledgement_refused",
		)?;

		let readonly = open_child(&sandbox.directory, b"delivery-sentinel", OFlags::RDONLY)?;
		let failed = cli.invoke(&args, acknowledgement, Some(readonly))?;
		assert_eq!(failed.status.code(), Some(2));
		assert!(failed.stdout.is_empty());
		assert_eq!(
			failed.stderr,
			b"exacopy: managed sync prepare-recreate output_inconclusive\n"
		);

		assert_missing(left, super::super::SUBJECT);
		assert_eq!(file_identity(left, RETAINED)?, left_id);
		assert_eq!(read(left, RETAINED)?, b"abc");
		assert_eq!(file_identity(right, super::super::SUBJECT)?, right_id);
		assert_eq!(read(right, super::super::SUBJECT)?, b"xyz");
		assert_eq!(subject_names(sandbox)?, names_while_absent);
		Ok::<_, Box<dyn std::error::Error>>(())
	})();
	if matches!(&result, Err(error) if error.is::<super::super::cli_process::UnconfirmedProcess>())
	{
		return result;
	}
	move_subject(sandbox, left, RETAINED, super::super::SUBJECT)?;
	result?;
	assert_eq!(subject_names(sandbox)?, names);
	assert_eq!(file_identity(left, super::super::SUBJECT)?, left_id);
	assert_eq!(file_identity(right, super::super::SUBJECT)?, right_id);
	assert_live(inputs.live, [b"abc", b"xyz"])
}

fn assert_envelope(report: &Value, result: &str) {
	assert_eq!(report["schema"], "exacopy.cli.managed_sync_recreate_plan");
	assert_eq!(report["schema_version"], "1.0");
	assert_eq!(report["result"], result);
	assert_eq!(report["authority"], "none");
	assert_eq!(report["approval_required"], true);
	assert_eq!(report["copy_started"], false);
	assert_eq!(report["baseline_advanced"], false);
}

fn refused(output: Output, reason: &str) -> TestResult {
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout)?;
	assert_envelope(&report, "refused");
	assert_eq!(report["reason"], reason);
	assert!(report.get("review").is_none());
	Ok(())
}

fn assert_prepared(
	review: &Value,
	approval: &Approval,
	inputs: &Inputs<'_>,
	(device, inode): (u64, u64),
) -> TestResult {
	let subject = super::super::SUBJECT;
	assert_eq!(review["selection"]["id"], hex(&approval.selection));
	assert_eq!(review["selection"]["revision"], REVISION.to_string());
	assert_eq!(review["policy_digest"], hex(&approval.digest));
	assert_eq!(
		review["predecessor_digest"],
		hex(&inputs.policy.history.root.reference.digest)
	);
	assert_eq!(review["subject_bytes_hex"], hex(subject));
	assert_eq!(review["from"], "right");
	assert_eq!(review["reviewed_conflict"], "edit-against-deletion");
	assert_eq!(
		review["source"]["observed_identity"]["device"],
		device.to_string()
	);
	assert_eq!(
		review["source"]["observed_identity"]["inode"],
		inode.to_string()
	);
	assert_eq!(review["source"]["bytes"], "3");
	let stream = *blake3::hash(b"xyz").as_bytes();
	assert_eq!(review["source"]["stream_digest"], hex(&stream));
	let metadata = LinuxOwnerMode {
		mode: 0o600,
		uid: inputs.policy.actor_uid.get(),
		gid: inputs.policy.actor_gid.get(),
	};
	assert_eq!(
		review["source"]["required_metadata_digest"],
		hex(&metadata.digest()?)
	);
	let child = &review["child_plan"];
	let digest = decode(&child["body_digest"])?;
	let body_bytes = decode(&child["body_cbor_hex"])?;
	let page_bytes = decode(&child["entry_page_cbor_hex"])?;
	let body = PlanBody::from_canonical_cbor(
		digest
			.try_into()
			.map_err(|_| "invalid child Plan digest width")?,
		&body_bytes,
	)?;
	let fields = body.fields();
	assert!(fields.approval_required);
	assert_eq!(fields.operation, PlanOperation::Copy);
	let [reference] = fields.entry_pages.as_slice() else {
		return Err("expected one entry page".into());
	};
	let entry = PlanEntriesPage::from_canonical_cbor(*reference, &page_bytes)?.entry();
	assert_eq!(entry.source.basename, subject);
	assert_eq!(entry.destination.basename, subject);
	assert_eq!(entry.stream_digest, stream);
	assert_eq!(entry.stream_length, 3);
	assert_eq!(
		entry.source.root_id.to_string(),
		review["roots"][1]["child_alias"]
	);
	assert_eq!(
		entry.destination.root_id.to_string(),
		review["roots"][0]["child_alias"]
	);
	assert_eq!(
		review["roots"][1]["managed_locator"],
		hex(&inputs.policy.endpoints[1].root)
	);
	assert_eq!(
		review["roots"][0]["managed_locator"],
		hex(&inputs.policy.endpoints[0].root)
	);
	let source = entry
		.source_identity
		.ok_or("missing held source identity")?;
	assert_eq!(source.volume_id, device.to_le_bytes());
	assert_eq!(source.object_id, inode.to_le_bytes());
	Ok(())
}

fn file_identity(root: &File, name: &[u8]) -> TestResult<(u64, u64)> {
	let meta = open_child(root, name, OFlags::RDONLY)?.metadata()?;
	Ok((meta.dev(), meta.ino()))
}

fn subject_names(sandbox: &Sandbox) -> TestResult<[Vec<OsString>; 2]> {
	let parent = sandbox.path.join("live");
	let names = |root| -> TestResult<Vec<OsString>> {
		let mut names = std::fs::read_dir(parent.join(OsStr::from_bytes(root)))?
			.map(|item| item.map(|item| item.file_name()))
			.collect::<std::io::Result<Vec<_>>>()?;
		names.sort_unstable();
		Ok(names)
	};
	let [left, right] = super::super::ROOT_NAMES;
	Ok([names(left)?, names(right)?])
}

fn move_subject(sandbox: &mut Sandbox, root: &File, from: &[u8], to: &[u8]) -> TestResult {
	let lease = open_child(
		&sandbox.directory,
		b"live",
		OFlags::RDONLY | OFlags::DIRECTORY,
	)?;
	flock(&lease, FlockOperation::NonBlockingLockExclusive)?;
	sandbox.rename(root, from, to)
}

fn decode(value: &Value) -> TestResult<Vec<u8>> {
	let hex = value.as_str().ok_or("missing lowercase hex field")?;
	let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
	if !remainder.is_empty() {
		return Err("odd hex string".into());
	}
	let mut out = Vec::with_capacity(pairs.len());
	for pair in pairs {
		out.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
	}
	assert_eq!(super::hex(&out), hex);
	Ok(out)
}
