use std::io::{self, Write};
use std::process::ExitCode;

use serde::Serialize;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const DIFFERENT: u8 = 1;
pub(crate) const INCONCLUSIVE: u8 = 2;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LIVE_OBSERVED: &str = "live_observed";

#[derive(Serialize)]
pub(crate) struct Report {
	schema: &'static str,
	schema_version: &'static str,
	relation: &'static str,
	complete: bool,
	#[serde(flatten)]
	outcome: Outcome,
}

impl Report {
	pub(crate) fn new(outcome: Outcome) -> Self {
		Self {
			schema: "exacopy.cli.diff",
			schema_version: "1.0",
			relation: "bytes",
			complete: !matches!(&outcome, Outcome::Inconclusive { .. }),
			outcome,
		}
	}

	pub(crate) fn write_json(&self, mut output: impl Write) -> io::Result<()> {
		serde_json::to_writer(&mut output, self)?;
		writeln!(output)?;
		output.flush()
	}
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum Outcome {
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	Equal {
		consistency: &'static str,
		length: String,
	},
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	Different {
		consistency: &'static str,
		difference: DifferenceWitness,
	},
	Inconclusive {
		error: Failure,
	},
}

impl Outcome {
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	pub(crate) fn from_comparison(comparison: exacopy_diff::LiveComparison) -> Self {
		use exacopy_diff::{Difference, LiveComparison};

		let difference = match comparison {
			LiveComparison::Equal { length } => {
				return Self::Equal {
					consistency: LIVE_OBSERVED,
					length: length.to_string(),
				};
			}
			LiveComparison::Different(Difference::Length { left, right }) => {
				DifferenceWitness::Length {
					left: left.to_string(),
					right: right.to_string(),
				}
			}
			LiveComparison::Different(Difference::FirstByte { offset }) => {
				DifferenceWitness::FirstByte {
					offset: offset.to_string(),
				}
			}
		};
		Self::Different {
			consistency: LIVE_OBSERVED,
			difference,
		}
	}

	pub(crate) fn exit_code(&self) -> ExitCode {
		match self {
			#[cfg(any(target_os = "linux", target_os = "macos"))]
			Self::Equal { .. } => ExitCode::SUCCESS,
			#[cfg(any(target_os = "linux", target_os = "macos"))]
			Self::Different { .. } => ExitCode::from(DIFFERENT),
			Self::Inconclusive { .. } => ExitCode::from(INCONCLUSIVE),
		}
	}

	pub(crate) fn write_human(
		&self,
		mut stdout: impl Write,
		mut stderr: impl Write,
	) -> io::Result<()> {
		let output: &mut dyn Write = if matches!(self, Self::Inconclusive { .. }) {
			&mut stderr
		} else {
			&mut stdout
		};
		match self {
			#[cfg(any(target_os = "linux", target_os = "macos"))]
			Self::Equal {
				length,
				consistency,
			} => {
				writeln!(output, "Equal bytes ({length} bytes, {consistency}).")?;
			}
			#[cfg(any(target_os = "linux", target_os = "macos"))]
			Self::Different {
				difference,
				consistency,
			} => match difference {
				DifferenceWitness::Length { left, right } => writeln!(
					output,
					"Different lengths (left {left} bytes, right {right} bytes, {consistency})."
				)?,
				DifferenceWitness::FirstByte { offset } => writeln!(
					output,
					"First unequal byte at offset {offset} ({consistency})."
				)?,
			},
			Self::Inconclusive { error } => {
				writeln!(
					output,
					"exacopy: comparison inconclusive ({})",
					error.message
				)?;
			}
		}
		output.flush()
	}
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DifferenceWitness {
	Length { left: String, right: String },
	FirstByte { offset: String },
}

#[derive(Serialize)]
pub(crate) struct Failure {
	pub(crate) code: ErrorCode,
	pub(crate) message: String,
}

#[derive(Serialize)]
pub(crate) enum ErrorCode {
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	#[serde(rename = "E_INVALID_PATH")]
	InvalidPath,
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	#[serde(rename = "E_OPEN_INPUT")]
	OpenInput,
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	#[serde(rename = "E_COMPARE_INPUT")]
	CompareInput,
	#[cfg(any(target_os = "linux", target_os = "macos"))]
	#[serde(rename = "E_RESOURCE_LIMIT")]
	ResourceLimit,
	#[serde(rename = "E_UNSUPPORTED_PLATFORM")]
	UnsupportedPlatform,
}
