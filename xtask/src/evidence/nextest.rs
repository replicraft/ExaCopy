//! Attendance evidence from the pinned nextest reporter and exact selected test.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Take};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::finding::Findings;
use crate::verification::owned_file;

use super::record::{Record, is_uuid};

const SEPARATOR: &str = "────────────";
const MAX_LINE_BYTES: usize = 4096;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(test)]
mod tests;

pub(super) fn matches_log(
	directory: &Path,
	record: &Record,
	package: &str,
	selected: &str,
	findings: &mut Findings,
) -> bool {
	let relative = PathBuf::from(format!("{}.log", record.evidence_id));
	let path = directory.join(&relative);
	if !record.matches_rust_tool() {
		findings.add(&path, "Rust evidence requires cargo-nextest 0.9.151");
		return false;
	}
	let result = owned_file(directory, &relative)
		.and_then(File::open)
		.and_then(|source| {
			if !source.metadata()?.is_file() {
				return Err(invalid("expected an owned regular file"));
			}
			check(source, package, selected)
		});
	match result {
		Ok(actual) if record.artifact_digest.as_deref() == Some(actual.as_str()) => true,
		Ok(_) => {
			findings.add(&path, "SHA-256 digest does not match the evidence record");
			false
		}
		Err(error) => {
			findings.add(&path, error);
			false
		}
	}
}

// Parse and hash one held stream. An accepted digest covers all the original
// bytes, including Cargo diagnostics, indentation and line terminators.
fn check(source: impl Read, package: &str, selected: &str) -> io::Result<String> {
	let mut input = Transcript {
		source: BufReader::new(source.take(MAX_LOG_BYTES + 1)),
		line: Vec::new(),
		bytes: 0,
		hash: Sha256::new(),
	};
	loop {
		let line = input.required()?;
		if line == SEPARATOR {
			break;
		}
		if contradicts_run(line) {
			return Err(invalid("unexpected status before the run"));
		}
	}

	let run = input.required()?;
	let id = run
		.strip_prefix(" Nextest run ID ")
		.and_then(|run| run.strip_suffix(" with nextest profile: default"));
	if !id.is_some_and(|id| is_uuid(id) && !id.bytes().any(|byte| byte.is_ascii_uppercase())) {
		return Err(invalid("missing default-profile run ID"));
	}
	let skipped =
		starting(input.required()?).ok_or_else(|| invalid("expected one started test"))?;
	let mut line = input.required()?;
	let slow = if let Some(event) = line.strip_prefix("        SLOW ") {
		let binary = attendance(event, "> ", "(───) ", package, selected)
			.ok_or_else(|| invalid("invalid slow-test event"))?
			.to_owned();
		line = input.required()?;
		Some(binary)
	} else {
		None
	};
	let binary = line
		.strip_prefix("        PASS ")
		.and_then(|event| attendance(event, "", "(1/1) ", package, selected))
		.ok_or_else(|| invalid("expected one pass of the exact selected test"))?;
	if slow.as_deref().is_some_and(|slow| slow != binary) {
		return Err(invalid("slow and passing events select different binaries"));
	}

	if input.required()? != SEPARATOR {
		return Err(invalid("missing separator after the selected pass"));
	}
	if !summary(input.required()?, skipped, slow.is_some()) {
		return Err(invalid("inconsistent terminal summary"));
	}
	if input.next()?.is_some() {
		return Err(invalid("unexpected output after the terminal summary"));
	}
	Ok(format!("{:x}", input.hash.finalize()))
}

fn contradicts_run(line: &str) -> bool {
	let statement = line.trim_start_matches([' ', '\t']);
	let label = statement.split([' ', '\t']).next().unwrap_or_default();
	matches!(
		label.strip_suffix(':').unwrap_or(label),
		"Nextest"
			| "Starting"
			| "Summary"
			| "PASS"
			| "SLOW"
			| "FAIL"
			| "SKIP"
			| "SKIPPED"
			| "RETRY"
			| "RETRYING"
			| "TRY"
			| "FLAKY"
			| "TIMEOUT"
			| "ABORT"
			| "CANCEL"
			| "CANCELED"
			| "CANCELLED"
			| "IGNORED"
			| "LEAK"
			| "LEAKED"
	) || statement.chars().next().is_some_and(char::is_whitespace)
		|| [
			"error:",
			"error[",
			"Evidence command timed out.",
			"Could not start evidence command:",
			"Could not verify evidence inputs after execution:",
		]
		.into_iter()
		.any(|prefix| statement.starts_with(prefix))
}

fn starting(line: &str) -> Option<u64> {
	let rest = line.strip_prefix("    Starting 1 test across ")?;
	let (bins, rest) = rest.split_once(' ')?;
	let expected = match count(bins)? {
		0 => return None,
		1 => "binary",
		_ => "binaries",
	};
	let rest = rest.strip_prefix(expected)?;
	if rest.is_empty() {
		return Some(0);
	}
	let skipped = rest.strip_prefix(" (")?.strip_suffix(')')?;
	let skipped = skipped
		.strip_suffix(" tests skipped")
		.or_else(|| skipped.strip_suffix(" test skipped"))?;
	count(skipped).filter(|&count| count > 0)
}

fn attendance<'event>(
	event: &'event str,
	duration_prefix: &str,
	position: &str,
	package: &str,
	selected: &str,
) -> Option<&'event str> {
	let event = timing(event, duration_prefix)?.strip_prefix(position)?;
	let (binary, case) = event.split_once(' ')?;
	let (owner, target) = binary
		.split_once("::")
		.map_or((binary, None), |(owner, target)| (owner, Some(target)));
	(owner == package
		&& binary_token(owner)
		&& target.is_none_or(binary_token)
		&& !case.is_empty()
		&& case == selected)
		.then_some(binary)
}

fn binary_token(token: &str) -> bool {
	!token.is_empty()
		&& token
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn summary(line: &str, skipped: u64, slow: bool) -> bool {
	let Some(rest) = line
		.strip_prefix("     Summary ")
		.and_then(|line| timing(line, ""))
		.and_then(|line| line.strip_prefix("1 test run: 1 passed"))
	else {
		return false;
	};
	let rest = if slow {
		let Some(rest) = rest.strip_prefix(" (1 slow)") else {
			return false;
		};
		rest
	} else {
		rest
	};
	if skipped == 0 {
		return rest.is_empty();
	}
	rest.strip_prefix(", ")
		.and_then(|rest| rest.strip_suffix(" skipped"))
		.and_then(count)
		== Some(skipped)
}

fn timing<'line>(line: &'line str, prefix: &str) -> Option<&'line str> {
	let (duration, remainder) = line.strip_prefix('[')?.split_once("] ")?;
	let value = if prefix.is_empty() {
		duration.trim_start_matches(' ')
	} else {
		duration.strip_prefix(prefix)?
	}
	.strip_suffix('s')?;
	let (seconds, milliseconds) = value.split_once('.')?;
	if count(seconds).is_none()
		|| milliseconds.len() != 3
		|| !milliseconds.bytes().all(|byte| byte.is_ascii_digit())
	{
		return None;
	}
	Some(remainder)
}

fn count(value: &str) -> Option<u64> {
	if !(1..=10).contains(&value.len())
		|| (value.len() > 1 && value.starts_with('0'))
		|| !value.bytes().all(|byte| byte.is_ascii_digit())
	{
		return None;
	}
	value.parse().ok()
}

struct Transcript<R> {
	source: BufReader<Take<R>>,
	line: Vec<u8>,
	bytes: u64,
	hash: Sha256,
}

impl<R: Read> Transcript<R> {
	fn required(&mut self) -> io::Result<&str> {
		self.next()?.ok_or_else(|| invalid("truncated run"))
	}

	fn next(&mut self) -> io::Result<Option<&str>> {
		self.line.clear();
		loop {
			let input = self.source.fill_buf()?;
			if input.is_empty() {
				return if self.line.is_empty() {
					Ok(None)
				} else {
					Err(invalid("unterminated physical line"))
				};
			}
			let newline = input.iter().position(|&byte| byte == b'\n');
			let count = newline.map_or(input.len(), |index| index + 1);
			self.bytes += count as u64;
			if self.line.len() + count > MAX_LINE_BYTES || self.bytes > MAX_LOG_BYTES {
				return Err(invalid("log exceeds the bounded size or line width"));
			}
			self.line.extend_from_slice(&input[..count]);
			self.source.consume(count);
			if newline.is_some() {
				break;
			}
		}
		self.hash.update(&self.line);
		let text = &self.line[..self.line.len() - 1];
		let text = text.strip_suffix(b"\r").unwrap_or(text);
		let text = std::str::from_utf8(text).map_err(|_| invalid("non-UTF-8 output"))?;
		if text.chars().any(|ch| ch.is_control() && ch != '\t') {
			return Err(invalid("unexpected control character"));
		}
		Ok(Some(text))
	}
}

fn invalid(reason: &str) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!("invalid nextest transcript: {reason}"),
	)
}
