use std::error::Error;
use std::fmt::{self, Arguments};
use std::io::{self, Write};

use serde::Serialize;

use crate::args::Format;

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum ErrorCode {
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_INPUT_PATH")]
	InvalidInput,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_MANIFEST_INVALID")]
	InvalidBaseline,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_MANIFEST_SCOPE")]
	BaselineScope,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_MANIFEST_INTEGRITY")]
	BaselineIntegrity,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_MANIFEST_STALE")]
	Stale,
	#[serde(rename = "E_MANIFEST_IO")]
	Io,
	#[serde(rename = "E_MANIFEST_UNSUPPORTED")]
	Unsupported,
}

impl ErrorCode {
	const fn exit_code(self) -> u8 {
		match self {
			#[cfg(target_os = "linux")]
			Self::InvalidInput | Self::InvalidBaseline | Self::BaselineScope => 2,
			#[cfg(target_os = "linux")]
			Self::Stale => 3,
			Self::Io => 4,
			#[cfg(target_os = "linux")]
			Self::BaselineIntegrity => 5,
			Self::Unsupported => 6,
		}
	}
}

#[derive(Serialize)]
pub(crate) struct Failure {
	code: ErrorCode,
	message: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	os_code: Option<String>,
	#[serde(skip)]
	cause: Option<Box<dyn Error + Send + Sync>>,
}

impl Failure {
	pub(crate) const fn new(code: ErrorCode, message: &'static str) -> Self {
		Self {
			code,
			message,
			os_code: None,
			cause: None,
		}
	}

	pub(crate) fn with_source(mut self, error: impl Error + Send + Sync + 'static) -> Self {
		self.os_code = native_os_code(&error).map(|code| code.to_string());
		self.cause = Some(Box::new(error));
		self
	}

	pub(crate) const fn exit_code(&self) -> u8 {
		self.code.exit_code()
	}

	pub(crate) fn write_human(&self, output: impl Write) -> io::Result<()> {
		write_line(output, format_args!("exacopy: {self}"))
	}
}

impl fmt::Debug for Failure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Failure")
			.field("code", &self.code)
			.field("message", &self.message)
			.field("os_code", &self.os_code)
			.finish_non_exhaustive()
	}
}

impl fmt::Display for Failure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.message)?;
		if let Some(code) = &self.os_code {
			write!(formatter, " (OS error {code})")?;
		}
		Ok(())
	}
}

impl Error for Failure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.cause.as_deref().map(|cause| cause as &dyn Error)
	}
}

fn native_os_code(mut error: &(dyn Error + 'static)) -> Option<i32> {
	const MAX_CAUSES: usize = 8;
	for _ in 0..MAX_CAUSES {
		if let Some(io) = error.downcast_ref::<io::Error>() {
			if let Some(code) = io.raw_os_error() {
				return Some(code);
			}
			error = io.get_ref()?;
			continue;
		}
		#[cfg(target_os = "linux")]
		if let Some(errno) = error.downcast_ref::<rustix::io::Errno>() {
			return Some(errno.raw_os_error());
		}
		error = error.source()?;
	}
	None
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg(target_os = "linux")]
pub(crate) enum Difference {
	Length { expected: String, observed: String },
	Digest { expected: String, observed: String },
}

#[derive(Serialize)]
#[cfg(target_os = "linux")]
pub(crate) struct Observation {
	consistency: &'static str,
	algorithm: &'static str,
	metadata: &'static str,
	baseline_authentication: &'static str,
	length: String,
}

#[cfg(target_os = "linux")]
impl Observation {
	pub(crate) fn new(length: u64) -> Self {
		Self {
			consistency: "live_observed",
			algorithm: "blake3-256",
			metadata: "explicitly_omitted",
			baseline_authentication: "unsigned",
			length: length.to_string(),
		}
	}
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum Outcome {
	#[cfg(target_os = "linux")]
	Verified {
		#[serde(flatten)]
		observation: Observation,
	},
	#[cfg(target_os = "linux")]
	Mismatch {
		#[serde(flatten)]
		observation: Observation,
		difference: Difference,
	},
	Inconclusive {
		error: Failure,
	},
}

#[derive(Serialize)]
struct VerifyReport<'outcome> {
	schema: &'static str,
	schema_version: &'static str,
	complete: bool,
	#[serde(flatten)]
	outcome: &'outcome Outcome,
}

impl Outcome {
	pub(crate) fn exit_code(&self) -> u8 {
		match self {
			#[cfg(target_os = "linux")]
			Self::Verified { .. } => 0,
			#[cfg(target_os = "linux")]
			Self::Mismatch { .. } => 5,
			Self::Inconclusive { error } => error.exit_code(),
		}
	}

	pub(crate) fn write(
		&self,
		format: Format,
		mut stdout: impl Write,
		stderr: impl Write,
	) -> Result<(), Failure> {
		let result = match format {
			Format::Json => {
				let report = VerifyReport {
					schema: "exacopy.cli.verify",
					schema_version: "1.0",
					complete: !matches!(self, Self::Inconclusive { .. }),
					outcome: self,
				};
				let mut bytes = serde_json::to_vec(&report).map_err(|error| {
					Failure::new(ErrorCode::Io, "could not encode the verification result")
						.with_source(error)
				})?;
				bytes.push(b'\n');
				stdout.write_all(&bytes).and_then(|()| stdout.flush())
			}
			Format::Human => self.write_human(stdout, stderr),
		};
		result.map_err(|error| {
			Failure::new(ErrorCode::Io, "could not write the verification result")
				.with_source(error)
		})
	}

	fn write_human(&self, stdout: impl Write, stderr: impl Write) -> io::Result<()> {
		#[cfg(not(target_os = "linux"))]
		let _ = stdout;

		match self {
			#[cfg(target_os = "linux")]
			Self::Verified { observation } => write_line(
				stdout,
				format_args!(
					"Verified {} bytes against the unsigned BLAKE3 baseline (live observation, metadata omitted).",
					observation.length
				),
			),
			#[cfg(target_os = "linux")]
			Self::Mismatch { difference, .. } => match difference {
				Difference::Length { expected, observed } => write_line(
					stdout,
					format_args!(
						"Length differs from the unsigned baseline (expected {expected} bytes, observed {observed} bytes)."
					),
				),
				Difference::Digest { .. } => write_line(
					stdout,
					format_args!("BLAKE3 digest differs from the unsigned baseline."),
				),
			},
			Self::Inconclusive { error } => error.write_human(stderr),
		}
	}
}

fn write_line(mut output: impl Write, message: Arguments<'_>) -> io::Result<()> {
	writeln!(output, "{message}")?;
	output.flush()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug)]
	struct PrivateCause(io::Error);

	impl fmt::Display for PrivateCause {
		fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			formatter.write_str("private-\x1b-path")
		}
	}

	impl Error for PrivateCause {
		fn source(&self) -> Option<&(dyn Error + 'static)> {
			Some(&self.0)
		}
	}

	#[test]
	fn retains_nested_io_cause_and_reports_only_its_numeric_code() {
		let source = io::Error::other(PrivateCause(io::Error::from_raw_os_error(5)));
		let failure = Failure::new(ErrorCode::Io, "could not read the input").with_source(source);
		let retained = failure
			.source()
			.and_then(|cause| cause.downcast_ref::<io::Error>())
			.and_then(|cause| cause.get_ref())
			.and_then(|cause| cause.downcast_ref::<PrivateCause>())
			.unwrap();
		assert_eq!(retained.0.raw_os_error(), Some(5));

		let json = serde_json::to_value(&failure).unwrap();
		assert_eq!(
			json,
			serde_json::json!({
				"code": "E_MANIFEST_IO",
				"message": "could not read the input",
				"os_code": "5",
			})
		);
		let mut human = Vec::new();
		failure.write_human(&mut human).unwrap();
		assert_eq!(human, b"exacopy: could not read the input (OS error 5)\n");
		assert!(!format!("{failure:?}").contains("private"));
	}

	#[derive(Debug)]
	struct FailingOutput;

	impl Write for FailingOutput {
		fn write(&mut self, _: &[u8]) -> io::Result<usize> {
			Err(io::Error::from_raw_os_error(28))
		}

		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	#[test]
	fn verify_write_failure_retains_the_original_output_errno() {
		let outcome = Outcome::Inconclusive {
			error: Failure::new(ErrorCode::Unsupported, "unsupported profile"),
		};
		let failure = outcome
			.write(Format::Json, FailingOutput, io::sink())
			.unwrap_err();

		assert_eq!(failure.exit_code(), 4);
		assert_eq!(failure.os_code.as_deref(), Some("28"));
		assert_eq!(
			failure
				.source()
				.and_then(|cause| cause.downcast_ref::<io::Error>())
				.and_then(io::Error::raw_os_error),
			Some(28)
		);
	}
}
