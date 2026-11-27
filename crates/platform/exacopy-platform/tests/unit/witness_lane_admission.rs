use std::io;
use std::thread;

use rustix::process::{getegid, geteuid};

use super::{WitnessCredentialLane, stable_unprivileged};
use crate::linux::StageError;
use crate::linux::mount_observation::ProcMounts;

const STATUS_ROWS: [&[u8]; 5] = [
	b"Uid:\t1000\t1000\t1000\t1000\n",
	b"Gid:\t1001\t1001\t1001\t1001\n",
	b"CapEff:\t0000000000000000\n",
	b"CapPrm:\t0000000000000000\n",
	b"CapAmb:\t0000000000000000\n",
];

// Procfs renders stable identities and empty capability sets as these exact
// rows. Check the kernel's rendering independently of the lane's parser.
fn current_lane_facts(uid: u32, gid: u32) -> io::Result<(u64, bool)> {
	let proc = ProcMounts::open()?;
	let namespace = proc.user_namespace_id()?;
	let status = proc.credential_status()?;
	let uid_row = format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}");
	let gid_row = format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}");
	let admissible = uid != 0
		&& [
			uid_row.as_bytes(),
			gid_row.as_bytes(),
			b"CapEff:\t0000000000000000",
			b"CapPrm:\t0000000000000000",
			b"CapAmb:\t0000000000000000",
		]
		.into_iter()
		.all(|expected| {
			status
				.split(|&byte| byte == b'\n')
				.any(|row| row == expected)
		});
	Ok((namespace, admissible))
}

#[test]
fn native_lane_observes_and_rechecks_current_thread() {
	let uid = geteuid().as_raw();
	let gid = getegid().as_raw();
	let facts = current_lane_facts(uid, gid);
	let observation = WitnessCredentialLane::observe();
	match (facts, observation) {
		(Ok((namespace, true)), Ok(lane)) => {
			assert_eq!(lane.thread, thread::current().id(), "observed thread");
			assert_eq!(lane.user_namespace, namespace, "observed user namespace");
			assert_eq!((lane.uid, lane.gid), (uid, gid), "effective identities");
			lane.recheck()
				.expect("stable native observation should recheck");

			// Change only the saved token. Recheck still inspects the real thread.
			let stale = WitnessCredentialLane {
				user_namespace: namespace ^ 1,
				..lane
			};
			assert!(
				matches!(stale.recheck(), Err(StageError::IdentityChanged)),
				"a stale user namespace must prevent reuse of the lane"
			);
		}
		(Ok((_, false)), Err(StageError::UnsafeFile)) => {}
		(Err(expected), Err(StageError::System(actual))) => {
			assert_eq!(actual.kind(), expected.kind(), "procfs error kind");
			assert_eq!(
				actual.raw_os_error(),
				expected.raw_os_error(),
				"procfs errno"
			);
		}
		unexpected => panic!("native lane disagreed with current observations: {unexpected:?}"),
	}
}

#[test]
fn rejects_missing_fields_and_non_exact_identity_columns() {
	assert!(
		stable_unprivileged(&STATUS_ROWS.concat(), 1000, 1001),
		"complete credential status must be admissible"
	);
	for missing in 0..STATUS_ROWS.len() {
		let mut rows = STATUS_ROWS.to_vec();
		let absent = rows.remove(missing);
		assert!(
			!stable_unprivileged(&rows.concat(), 1000, 1001),
			"missing row must prevent admission: {absent:?}"
		);
	}

	for uid_row in [
		b"Uid: 1000 1000 1000\n".as_slice(),
		b"Uid: 1000 1000 1000 1000 1000\n",
		b"Uid: 1000 1000 1000 4294967296\n",
		b"Uid: 1000 1000 1000 \xff\n",
		b"Uid: 1000 1000 1000 1001\n",
	] {
		let mut rows = STATUS_ROWS;
		rows[0] = uid_row;
		assert!(
			!stable_unprivileged(&rows.concat(), 1000, 1001),
			"invalid identity row must prevent admission: {uid_row:?}"
		);
	}
}
