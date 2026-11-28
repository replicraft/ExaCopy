use std::io;

use serde::Serialize;
use uuid::Uuid;

use crate::args::JobPathDisplay;

use super::RemoteJob;

// Keep the versioned JSON locator lossless. Text disclosure is a separate choice.
#[derive(Serialize)]
pub(super) struct JobReport {
	job_id: String,
	job_directory: String,
	job_directory_bytes_hex: String,
}

impl From<RemoteJob> for JobReport {
	fn from(job: RemoteJob) -> Self {
		Self {
			job_id: Uuid::from_bytes(*job.id.as_bytes()).to_string(),
			job_directory: job.directory.to_string_lossy().into_owned(),
			job_directory_bytes_hex: encode_hex(job.directory.as_os_str().as_encoded_bytes()),
		}
	}
}

impl JobReport {
	pub(super) fn write(
		&self,
		output: &mut impl io::Write,
		path_display: JobPathDisplay,
	) -> io::Result<()> {
		match path_display {
			JobPathDisplay::Redacted => writeln!(output, "Job {} retained.", self.job_id),
			JobPathDisplay::Reveal => writeln!(
				output,
				"Job {} retained in {:?}. Directory bytes in hex: {}.",
				self.job_id, self.job_directory, self.job_directory_bytes_hex,
			),
		}
	}
}

fn encode_hex(bytes: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		result.push(char::from(HEX[usize::from(byte >> 4)]));
		result.push(char::from(HEX[usize::from(byte & 0x0f)]));
	}
	result
}
