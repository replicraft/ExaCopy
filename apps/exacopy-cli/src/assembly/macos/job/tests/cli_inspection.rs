use std::ffi::OsString;
use std::io::Write as _;
use std::process::ExitCode;

use exacopy_journal::frame::{FrameKind, FrameWriter};

use serde_json::Value;

use super::*;

// These are the version and kind fields in the v1 frame header.
const VERSION_OFFSET: usize = 8;
const KIND_OFFSET: usize = 10;

#[test]
fn apfs_inspect_dispatch_binds_the_independent_selection_and_preserves_the_job() {
	let fixture = Fixture::new();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let private = fixture.0.join(PRIVATE);
	let (name, profile_id, root_id_bytes, native_root, journal_head) = {
		let root = fixture.root();
		let source = fixture.source(&root);
		let container = root.open_stage_directory(component(PRIVATE)).unwrap();
		let request = fixture.request(&source, &container, &signer);
		let plan = fixture.plan(&root, request);
		let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
		let destination = admit_destination(plan.destination(), request).unwrap();
		let journal_head = with_admitted_job(&plan, request, name, destination, |job| {
			job.with_admitted_entry(|entry| entry.synced().head())
				.unwrap()
		})
		.unwrap();
		(
			name,
			*request.profile.id.as_bytes(),
			*request.destination_root_id.as_bytes(),
			native_identity(root.observe_identity().unwrap()).unwrap(),
			journal_head,
		)
	};
	let key = signer.verifying_key().to_bytes();
	let job = private.join(name.to_string());
	let incumbent = fixture.0.join(TARGET);
	fs::write(&incumbent, b"independent incumbent").unwrap();
	let marked = ["owner.cbor", "plan.cbor", FIRST_SEGMENT, "stage/payload"];
	let paths: Vec<_> = marked.iter().map(|name| job.join(name)).collect();
	let before = files(&paths);
	let plan = DarwinCopyPlan::decode(
		&before[1].2,
		OwnerProfileId::from_bytes(profile_id).unwrap(),
	)
	.unwrap();
	let owner = DarwinOwnerRecord::decode(
		&before[0].2,
		OwnerProfileId::from_bytes(profile_id).unwrap(),
		&signer.verifying_key(),
	)
	.unwrap();
	assert_eq!(owner.manifest().plan_digest, plan.digest());
	assert_eq!(plan.destination().root_identity, native_root);
	let source = fixture.0.join(SOURCE);
	let outside = files(&[source.clone(), incumbent.clone()]);
	let names = inventory(&job);
	let private_names = entries(&private);
	let root_names = entries(&fixture.0);
	let selected = args(name, &private, profile_id, key, root_id_bytes);

	let report = invoke(selected.clone(), 0);
	assert_eq!(report["schema"], "exacopy.cli.apfs_recovery_inspection");
	assert_eq!(report["schema_version"], "1.1");
	assert_eq!(report["result"], "inspected");
	assert_eq!(report["historical_status"], "incomplete");
	assert_eq!(report["journal_sequence"], "2");
	assert_eq!(report["journal_offset"], before[2].2.len().to_string());
	assert_eq!(report["journal_head_digest"], hex(&journal_head.digest()));
	assert_eq!(report["journal_tail"], "clean");
	assert_eq!(report["receipt"]["status"], "missing");
	assert!(report["stage_directory"].is_object());
	assert_eq!(
		report["stage"]["identity"]["inode"],
		before[3].1.to_string()
	);
	assert_eq!(report["stage"]["length"], "0");
	assert_eq!(
		report["target"]["identity"]["inode"],
		outside[1].1.to_string()
	);
	assert_eq!(report["target"]["length"], outside[1].2.len().to_string());
	assert_eq!(files(&paths), before);

	let wrong_key = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
	for (profile, key, root, code) in [
		(profile_id, wrong_key, root_id_bytes, "E_APFS_HISTORY"),
		([7; 16], key, root_id_bytes, "E_APFS_HISTORY"),
		(
			profile_id,
			key,
			*root_id([11; 16]).as_bytes(),
			"E_APFS_BINDING",
		),
	] {
		assert_refused(invoke(args(name, &private, profile, key, root), 9), code);
		assert_eq!(files(&paths), before);
	}
	assert_refused(
		invoke(args(name, &private, profile_id, [0; 32], root_id_bytes), 2),
		"E_APFS_SELECTION",
	);

	let busy = fixture.root();
	assert_refused(invoke(selected.clone(), 9), "E_APFS_CUSTODY");
	drop(busy);

	assert_eq!(entries(&fixture.0), root_names);
	assert_eq!(entries(&private), private_names);
	let link = fixture.0.join("redirect");
	symlink(&fixture.0, &link).unwrap();
	for container in [link.join(PRIVATE), private.join("..").join(PRIVATE)] {
		assert_refused(
			invoke(args(name, &container, profile_id, key, root_id_bytes), 9),
			"E_APFS_CUSTODY",
		);
	}
	assert_eq!(inventory(&job), names);
	assert_eq!(files(&paths), before);
	assert_eq!(files(&[source.clone(), incumbent.clone()]), outside);

	let rebound = Fixture::new();
	let rebound_root = rebound.root();
	assert_ne!(
		native_identity(rebound_root.observe_identity().unwrap()).unwrap(),
		native_root
	);
	drop(rebound_root);
	let rebound_private = rebound.0.join(PRIVATE);
	let rebound_job = rebound_private.join(name.to_string());
	let job_ino = fs::symlink_metadata(&job).unwrap().ino();
	fs::rename(&job, &rebound_job).unwrap();
	assert!(!job.exists());
	assert_eq!(fs::symlink_metadata(&rebound_job).unwrap().ino(), job_ino);
	let rebound_paths: Vec<_> = marked.iter().map(|name| rebound_job.join(name)).collect();
	assert_eq!(files(&rebound_paths), before);
	assert_refused(
		invoke(
			args(name, &rebound_private, profile_id, key, root_id_bytes),
			9,
		),
		"E_APFS_BINDING",
	);
	assert_eq!(files(&rebound_paths), before);
	assert_eq!(inventory(&rebound_job), names);
	assert_eq!(files(&[source.clone(), incumbent.clone()]), outside);
	assert!(!rebound.0.join(TARGET).exists());
	fs::rename(&rebound_job, &job).unwrap();
	assert_eq!(fs::symlink_metadata(&job).unwrap().ino(), job_ino);
	assert_eq!(entries(&private), private_names);

	let segment = job.join(FIRST_SEGMENT);
	let first = before[2].2[0];
	File::options()
		.append(true)
		.open(&segment)
		.unwrap()
		.write_all(&[first])
		.unwrap();
	let torn = files(&paths);
	let observed = invoke(selected.clone(), 9);
	assert_eq!(observed["result"], "inspected");
	assert_eq!(observed["journal_tail"], "torn");
	assert_eq!(observed["torn_bytes"], "1");
	assert_eq!(observed["journal_offset"], before[2].2.len().to_string());
	assert_eq!(
		observed["journal_head_digest"],
		report["journal_head_digest"]
	);
	assert_eq!(files(&paths), torn);
	assert_eq!(inventory(&job), names);
	assert_eq!(files(&[source.clone(), incumbent.clone()]), outside);

	let mut writer = FrameWriter::new(Vec::new(), journal_head);
	writer.append(FrameKind::StageSealed, b"").unwrap();
	let suffix = writer.into_inner();
	for offset in [VERSION_OFFSET, KIND_OFFSET] {
		let mut unsupported = suffix.clone();
		// Keep the supported low byte and make the discriminator incompatible only
		// when both bytes are present.
		unsupported[offset + 1] = 0xff;
		let discriminator_end = offset + std::mem::size_of::<u16>();
		for length in [discriminator_end - 1, discriminator_end, unsupported.len()] {
			let bytes = [before[2].2.as_slice(), &unsupported[..length]].concat();
			fs::write(&segment, &bytes).unwrap();
			let retained = files(&paths);
			assert_eq!(retained[2].2, bytes);
			let inspected = invoke(selected.clone(), 9);
			if length < discriminator_end {
				assert_eq!(inspected["result"], "inspected");
				assert_eq!(inspected["journal_tail"], "torn");
				assert_eq!(inspected["torn_bytes"], length.to_string());
				for field in ["journal_sequence", "journal_offset", "journal_head_digest"] {
					assert_eq!(inspected[field], report[field]);
				}
			} else {
				assert_refused(inspected, "E_APFS_JOURNAL_UNSUPPORTED");
			}
			assert_eq!(files(&paths), retained);
			assert_eq!(inventory(&job), names);
			assert_eq!(files(&[source.clone(), incumbent.clone()]), outside);
		}
	}

	let mut damaged = suffix;
	*damaged.last_mut().unwrap() ^= 0xff;
	let bytes = [before[2].2.as_slice(), damaged.as_slice()].concat();
	fs::write(&segment, &bytes).unwrap();
	let retained = files(&paths);
	assert_eq!(retained[2].2, bytes);
	assert_refused(invoke(selected, 9), "E_APFS_HISTORY");
	assert_eq!(files(&paths), retained);
	assert_eq!(inventory(&job), names);
	assert_eq!(files(&[source, incumbent]), outside);
}

fn args(
	name: JobName,
	private: &Path,
	profile: [u8; 16],
	key: [u8; 32],
	root: [u8; 16],
) -> Vec<OsString> {
	vec![
		"recover".into(),
		"inspect-apfs".into(),
		name.to_string().into(),
		"--stage-container".into(),
		private.as_os_str().to_owned(),
		"--managed-apfs".into(),
		"--owner-profile-id".into(),
		hex(&profile).into(),
		"--owner-key".into(),
		hex(&key).into(),
		"--destination-root-id".into(),
		hex(&root).into(),
		"--format".into(),
		"json".into(),
	]
}

fn invoke(args: Vec<OsString>, expected: u8) -> Value {
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let exit = crate::command::run_with_output(args.into_iter(), &mut stdout, &mut stderr);
	assert_eq!(exit, ExitCode::from(expected), "{stderr:?}, {stdout:?}");
	assert!(stderr.is_empty());
	serde_json::from_slice(&stdout).unwrap()
}

fn assert_refused(report: Value, code: &str) {
	assert_eq!(report["result"], "refused");
	assert_eq!(report["code"], code);
	for field in [
		"journal_sequence",
		"journal_offset",
		"journal_head_digest",
		"journal_tail",
		"torn_bytes",
		"receipt",
		"stage_directory",
		"stage",
		"target",
	] {
		assert!(report.get(field).is_none(), "refusal leaked {field}");
	}
}

fn files(paths: &[PathBuf]) -> Vec<(u64, u64, Vec<u8>)> {
	paths
		.iter()
		.map(|path| {
			let stat = fs::symlink_metadata(path).unwrap();
			assert!(stat.is_file());
			(stat.dev(), stat.ino(), fs::read(path).unwrap())
		})
		.collect()
}

fn inventory(job: &Path) -> [Option<Vec<OsString>>; 4] {
	[
		job.to_path_buf(),
		job.join("journal"),
		job.join("stage"),
		job.join("receipts"),
	]
	.map(|path| entries(&path))
}

fn entries(path: &Path) -> Option<Vec<OsString>> {
	let entries = match fs::read_dir(path) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
		Err(error) => panic!("observe fixture inventory: {error}"),
	};
	let mut names: Vec<_> = entries.map(|entry| entry.unwrap().file_name()).collect();
	names.sort_unstable();
	Some(names)
}

fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write as _;

	let mut text = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(&mut text, "{byte:02x}").unwrap();
	}
	text
}
