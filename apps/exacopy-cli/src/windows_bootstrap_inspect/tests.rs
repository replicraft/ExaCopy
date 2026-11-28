use std::io;

use serde_json::json;

use super::*;

#[test]
fn windows_bootstrap_report_projects_only_historical_evidence() {
	let mut job = [0; 16];
	job[6] = 0x70;
	job[8] = 0x80;
	job[15] = 0xab;
	let job = JournalJobId::from_bytes(job).unwrap();
	let owner = OwnerDigest::from_bytes([0x6a; 32]);
	let head = ChainHead::after(1, [0x97; 32]).unwrap();
	let observed = Outcome::historical(job, owner, head, 310);
	assert_eq!(observed.exit_code(), 0);
	assert_eq!(
		serde_json::to_value(observed).unwrap(),
		json!({
			"status": "observed",
			"job_id": "00000000-0000-7000-8000-0000000000ab",
			"owner_blake3": "6a".repeat(32),
			"historical_head_blake3": "97".repeat(32),
			"journal_sequence": "1",
			"first_segment_extent": "310",
		})
	);
	for (reason, label, exit) in [
		(Reason::Selection, "selection", 2),
		(Reason::Custody, "custody", 9),
		(Reason::History, "history", 9),
	] {
		let refused = Outcome::Refused { reason };
		assert_eq!(refused.exit_code(), exit);
		assert_eq!(
			serde_json::to_value(refused).unwrap(),
			json!({"status": "refused", "reason": label})
		);
	}
}

#[test]
fn windows_bootstrap_weak_key_refuses_with_no_reported_history() {
	use std::ffi::OsString;
	use std::process::ExitCode;

	let args = [
		"recover",
		"inspect-windows-bootstrap",
		"--root",
		r"Z:\literal-owner-selected-test-root",
		"--volume-guid",
		"01234567-89ab-cdef-0123-456789abcdef",
		"--volume-serial",
		"7",
		"--root-file-id",
		"0123456789abcdef1032547698badcfe",
		"--owner-profile-id",
		"41414141414141414141414141414141",
		"--owner-key",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"--job-id",
		"018d45be-0000-7000-8000-000000000001",
		"--managed-ntfs",
	];
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let argument_iter = || args.into_iter().map(OsString::from);
	let exit = crate::command::run_with_output(argument_iter(), &mut stdout, &mut stderr);
	assert_eq!(exit, ExitCode::from(2));
	assert!(stderr.is_empty());
	assert!(stdout.ends_with(b"\n"));
	assert_eq!(
		serde_json::from_slice::<serde_json::Value>(&stdout).unwrap(),
		json!({
			"schema": "exacopy.cli.windows_bootstrap_inspection",
			"schema_version": "1.0",
			"authority": "none",
			"status": "refused",
			"reason": "selection",
		})
	);

	for write_fails in [true, false] {
		let mut output = FailingStdout {
			written: Vec::new(),
			write_fails,
		};
		let mut stderr = Vec::new();
		let exit = crate::command::run_with_output(argument_iter(), &mut output, &mut stderr);
		assert_eq!(exit, ExitCode::from(4));
		assert_eq!(
			stderr,
			b"exacopy: could not write the Windows bootstrap inspection result\n"
		);
		if write_fails {
			assert!(output.written.is_empty());
		} else {
			assert_eq!(output.written, stdout);
		}
	}
}

struct FailingStdout {
	written: Vec<u8>,
	write_fails: bool,
}

impl io::Write for FailingStdout {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.write_fails {
			return Err(io::Error::other("private write failure detail"));
		}
		self.written.extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		if self.write_fails {
			Ok(())
		} else {
			Err(io::Error::other("private flush failure detail"))
		}
	}
}
