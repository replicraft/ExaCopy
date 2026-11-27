use std::fs;

use crate::linux::StageError;
use crate::linux::job::STAGE;

use super::{JOB, PARKED, PAYLOAD, TARGET, fixture, name, private_directory, private_file};

const PART: &str = "part";
const INCUMBENT: &[u8] = b"incumbent bytes";

#[test]
fn stage_anchor_keeps_pins_after_the_writer_releases_its_lease() {
	let (fixture, root) = fixture();
	let directory = fixture.path(JOB).join(STAGE);
	private_directory(&directory);
	let stage = directory.join(PART);
	private_file(&stage, PAYLOAD);
	let job = root
		.open_recovery_job(name(JOB))
		.expect("open recovery job");
	let writer = root
		.try_recovery_write_lease(name(JOB), job.identity())
		.expect("acquire exclusive recovery lease");
	let inventory = writer
		.job()
		.inventory(name(PART), name(TARGET))
		.expect("observe private stage and absent target");
	let anchor = writer
		.pin_stopped_stage(inventory)
		.expect("pin stopped stage");
	drop(writer);

	let reader = job.try_read_lease().expect("anchor leaves job unlocked");
	let inventory = job
		.inventory(name(PART), name(TARGET))
		.expect("reopen stage under a shared lease");
	anchor
		.recheck(&inventory)
		.expect("pinned stage still matches");
	fixture.assert_debug_redacts(&anchor, &[JOB, PART, TARGET]);
	drop(reader);
	let target = fixture.path(TARGET);
	private_file(&target, INCUMBENT);
	let occupied = job
		.inventory(name(PART), name(TARGET))
		.expect("observe late incumbent alongside the original stage");
	assert!(matches!(
		anchor.recheck(&occupied),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(
		fs::read(stage).expect("read original fixture stage"),
		PAYLOAD
	);
	assert_eq!(fs::read(target).expect("read late incumbent"), INCUMBENT);
}

#[test]
fn stage_anchor_refuses_missing_stage_and_occupied_target() {
	let (fixture, root) = fixture();
	let job = root
		.open_recovery_job(name(JOB))
		.expect("open recovery job");
	let writer = root
		.try_recovery_write_lease(name(JOB), job.identity())
		.expect("acquire exclusive recovery lease");
	let observe = || writer.job().inventory(name(PART), name(TARGET));
	assert!(matches!(
		writer.pin_stopped_stage(observe().expect("observe absent directory")),
		Err(StageError::IdentityChanged)
	));

	let directory = fixture.path(JOB).join(STAGE);
	private_directory(&directory);
	assert!(matches!(
		writer.pin_stopped_stage(observe().expect("observe missing stage file")),
		Err(StageError::IdentityChanged)
	));

	let stage = directory.join(PART);
	let target = fixture.path(TARGET);
	private_file(&stage, PAYLOAD);
	private_file(&target, INCUMBENT);
	assert!(matches!(
		writer.pin_stopped_stage(observe().expect("observe both files")),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(stage).expect("read retained stage"), PAYLOAD);
	assert_eq!(
		fs::read(target).expect("read retained incumbent"),
		INCUMBENT
	);
}

#[test]
fn stage_anchor_refuses_same_bytes_at_a_rebound_stage_name() {
	let (fixture, root) = fixture();
	let directory = fixture.path(JOB).join(STAGE);
	private_directory(&directory);
	let stage = directory.join(PART);
	let parked = directory.join(PARKED);
	private_file(&stage, PAYLOAD);
	let job = root
		.open_recovery_job(name(JOB))
		.expect("open recovery job");
	let writer = root
		.try_recovery_write_lease(name(JOB), job.identity())
		.expect("acquire exclusive recovery lease");
	let original = writer
		.job()
		.inventory(name(PART), name(TARGET))
		.expect("observe original stage");
	let anchor = writer
		.pin_stopped_stage(original)
		.expect("pin stopped stage");
	drop(writer);

	fs::rename(&stage, &parked).expect("park original stage without replacement");
	private_file(&stage, PAYLOAD);
	let rebound = job
		.inventory(name(PART), name(TARGET))
		.expect("observe replacement stage");
	assert!(matches!(
		anchor.recheck(&rebound),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(parked).expect("read parked original"), PAYLOAD);
	assert_eq!(fs::read(stage).expect("read retained replacement"), PAYLOAD);
}
