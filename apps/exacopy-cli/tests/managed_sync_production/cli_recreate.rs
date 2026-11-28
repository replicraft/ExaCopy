use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

use ed25519_dalek::Signature;
use exacopy_plan::workflow_sync::decode_envelope;
use exacopy_plan::workflow_sync::recreate::{
	RecreateReason, RecreateSide, action_reference, decode_action, decode_parent,
	parent_signing_input,
};
use exacopy_plan::{PlanBody, PlanEntriesPage, PlanOperation, UnixTimestamp};
use rustix::fs::{FlockOperation, flock};

use super::*;

const RETAINED: &[u8] = b"retained-cli-recreate-subject";

pub(super) fn exercise(
	sandbox: &mut Sandbox,
	cli: &Cli,
	approval: &Approval,
	acknowledgement: &[u8],
	inputs: &Inputs<'_>,
	profile: &File,
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
		assert_prepared(&report["review"], approval, inputs, right_id, None)?;

		let mut expiring = args.clone();
		expiring.extend(["--expires-in-seconds".into(), "120".into()]);
		let output = cli.invoke(&expiring, acknowledgement, None)?;
		assert_eq!(output.status.code(), Some(0), "stderr {:?}", output.stderr);
		assert!(output.stderr.is_empty());
		let report: Value = serde_json::from_slice(&output.stdout)?;
		assert_envelope(&report, "prepared");
		assert_prepared(&report["review"], approval, inputs, right_id, Some(120))?;
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

		exercise_signed_export(sandbox, cli, approval, acknowledgement, inputs, profile)?;
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
	lifetime_seconds: Option<i64>,
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
	assert_eq!(
		fields.expires_at,
		lifetime_seconds.map(|seconds| {
			UnixTimestamp::new(
				fields.created_at.seconds() + seconds,
				fields.created_at.nanoseconds(),
			)
			.unwrap()
		})
	);
	if lifetime_seconds.is_some() {
		let mut unbounded = fields.clone();
		unbounded.expires_at = None;
		let unbounded = PlanBody::new(unbounded)?;
		assert!(PlanBody::from_canonical_cbor(body.digest(), unbounded.canonical_cbor()).is_err());
	}
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

fn exercise_signed_export(
	sandbox: &mut Sandbox,
	cli: &Cli,
	approval: &Approval,
	acknowledgement: &[u8],
	inputs: &Inputs<'_>,
	profile: &File,
) -> TestResult {
	const PAIR: &str = "019b8db1-d7f0-7112-8001-010203040506";
	let mut args = approval.preview();
	args[1] = "export-recreate".into();
	args.extend([
		"--from".into(),
		"right".into(),
		"--reviewed-conflict".into(),
		"edit-against-deletion".into(),
		"--expires-in-seconds".into(),
		"120".into(),
		"--pair-id".into(),
		PAIR.into(),
	]);

	// Earlier preview controls retained the original seed under a different name.
	// The signed route must pass live planning and refuse missing signing custody.
	let refusal = cli.invoke(&args, acknowledgement, None)?;
	assert_eq!(refusal.status.code(), Some(2));
	assert!(refusal.stderr.is_empty());
	let report: Value = serde_json::from_slice(&refusal.stdout)?;
	assert_export_envelope(&report, "refused");
	assert_eq!(report["reason"], "signing_custody_refused");
	assert!(report.get("bundle").is_none());
	assert!(report.get("pair_id").is_none());

	sandbox.rename(profile, b"retained-cli-seed", b"owner.seed")?;
	let output = cli.invoke_signed_export(&args, acknowledgement);
	if matches!(&output, Err(error) if error.is::<super::super::cli_process::UnconfirmedProcess>())
	{
		return output.map(|_| ());
	}
	sandbox.rename(profile, b"owner.seed", b"retained-cli-seed")?;
	let output = output?;
	assert_eq!(output.status.code(), Some(0), "stderr {:?}", output.stderr);
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout)?;
	assert_export_envelope(&report, "exported");
	assert_eq!(report["pair_id"], PAIR);
	let bundle = &report["bundle"];
	let envelope = decode(&bundle["parent_envelope_cbor_hex"])?;
	let envelope = decode_envelope(&envelope)?;
	let signing = parent_signing_input(envelope.body)?;
	assert_eq!(envelope.public_key, approval.owner.to_bytes());
	approval
		.owner
		.verify_strict(&signing, &Signature::from_bytes(&envelope.signature))?;
	assert_eq!(
		report["parent_plan_digest"],
		hex(blake3::hash(&signing).as_bytes())
	);
	let parent = decode_parent(envelope.body)?;
	assert_eq!(parent.pair_id, *uuid::Uuid::parse_str(PAIR)?.as_bytes());
	assert_eq!(parent.predecessor, inputs.artifacts[0].reference);
	assert_eq!(
		parent.endpoints,
		[inputs.artifacts[1].reference, inputs.artifacts[2].reference]
	);
	assert_ne!(parent.coverage[0], parent.coverage[1]);

	let page = decode(&bundle["action_page_cbor_hex"])?;
	assert_eq!(parent.action_page, action_reference(&page)?);
	let action = decode_action(&page)?;
	assert_eq!(action.name.as_bytes(), super::super::SUBJECT);
	assert_eq!(action.side, RecreateSide::Right);
	assert_eq!(action.reason, RecreateReason::EditAgainstDeletion);
	assert_eq!(action.stream_length, 3);
	assert_eq!(action.stream_digest, *blake3::hash(b"xyz").as_bytes());
	let child_body = decode(&bundle["child_plan_body_cbor_hex"])?;
	let child_page = decode(&bundle["child_plan_page_cbor_hex"])?;
	let child = PlanBody::from_canonical_cbor(action.child_digest, &child_body)?;
	assert!(child.fields().approval_required);
	assert_eq!(child.fields().created_at, parent.created_at);
	assert_eq!(child.fields().expires_at, Some(parent.expires_at));
	assert_eq!(child.fields().entry_pages.as_slice(), &[action.child_page]);
	let entry = PlanEntriesPage::from_canonical_cbor(action.child_page, &child_page)?.entry();
	assert_eq!(entry.source.basename, action.name.as_bytes());
	assert_eq!(entry.destination.basename, action.name.as_bytes());
	let (device, inode) = file_identity(inputs.live[1], super::super::SUBJECT)?;
	let child_source = entry
		.source_identity
		.ok_or("missing child source identity")?;
	assert_eq!(action.source.major, rustix::fs::major(device));
	assert_eq!(action.source.minor, rustix::fs::minor(device));
	assert_eq!(action.source.inode.get(), inode);
	assert_eq!(child_source.volume_id, device.to_le_bytes());
	assert_eq!(child_source.object_id, inode.to_le_bytes());
	for (name, artifact) in [
		"predecessor_root_envelope_cbor_hex",
		"left_endpoint_envelope_cbor_hex",
		"right_endpoint_envelope_cbor_hex",
		"predecessor_leaf_cbor_hex",
	]
	.into_iter()
	.zip(inputs.artifacts)
	{
		assert_eq!(decode(&bundle[name])?, artifact.bytes);
	}
	let root = exacopy_plan::workflow_sync::decode_root(
		decode_envelope(&inputs.artifacts[0].bytes)?.body,
	)?;
	assert_eq!(report["predecessor_pair_digest"], hex(&root.pair));
	Ok(())
}

fn assert_export_envelope(report: &Value, result: &str) {
	assert_eq!(report["schema"], "exacopy.cli.managed_sync_recreate_export");
	assert_eq!(report["schema_version"], "1.0");
	assert_eq!(report["result"], result);
	assert_eq!(report["authority"], "none");
	assert_eq!(report["approval_required"], true);
	for field in [
		"approval_present",
		"delegated_grant_present",
		"action_intent_present",
		"copy_started",
		"baseline_advanced",
	] {
		assert_eq!(report[field], false);
	}
}
