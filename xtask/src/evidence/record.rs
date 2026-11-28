use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::finding::Findings;
use crate::verification::{Gate, numbered_id};
use crate::workspace;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
	schema_version: u32,
	pub(super) evidence_id: String,
	pub(super) requirement_ids: Vec<String>,
	pub(super) obligation_ids: Vec<String>,
	pub(super) kind: Kind,
	repository: String,
	pub(super) commit: String,
	dirty: bool,
	pub(super) source_digest: String,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) generated_input_digest: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) lockfile_digest: Option<String>,
	tool: String,
	tool_version: String,
	pub(super) redacted_command: Vec<String>,
	profile: Profile,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	started_at: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	duration_ms: Option<String>,
	pub(super) seeds: Vec<String>,
	pub(super) model_bounds: Vec<String>,
	pub(super) assumptions: Vec<String>,
	pub(super) oracle: String,
	pub(super) outcome: Outcome,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	exit_status: Option<i32>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) artifact_digest: Option<String>,
	pub(super) detail: Detail,
	review: Review,
	synthetic: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
	features: Vec<String>,
	target: String,
	os: String,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	filesystem: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	hardware: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Detail {
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) theorem: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) extraction_digest: Option<String>,
	pub(super) axioms_tcb: Vec<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) state_count: Option<String>,
	pub(super) fairness: Vec<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) trace_digest: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) harness: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	pub(super) unwind_bound: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	fuzz_target: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	corpus_digest: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	budget: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	coverage_denominator: Option<String>,
	#[serde(deserialize_with = "Deserialize::deserialize")]
	mutation_denominator: Option<String>,
	qualification_conditions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
	#[serde(deserialize_with = "Deserialize::deserialize")]
	reviewer: Option<String>,
	independent: bool,
	justification: String,
}

#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
	Lean,
	Tlc,
	Kani,
	Loom,
	Shuttle,
	Miri,
	Fuzz,
	Property,
	Test,
	Coverage,
	Mutation,
	Qualification,
	Benchmark,
	Audit,
	ArtifactCheck,
}

impl Kind {
	pub(super) fn gate(self) -> Option<Gate> {
		match self {
			Self::Lean => Some(Gate::Lean),
			Self::Tlc => Some(Gate::Tlc),
			Self::Kani => Some(Gate::Kani),
			Self::Test => Some(Gate::Rust),
			_ => None,
		}
	}
}

#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
	Pass,
	Fail,
	NotRun,
	NotApplicable,
	Blocked,
}

pub(super) fn read(path: &Path, findings: &mut Findings) -> Option<Record> {
	if path.is_symlink() {
		findings.add(path, "evidence record cannot be a symlink");
		return None;
	}
	let bytes = match fs::read(path) {
		Ok(bytes) => bytes,
		Err(error) => {
			findings.add(path, error);
			return None;
		}
	};
	match serde_json::from_slice(&bytes) {
		Ok(record) => Some(record),
		Err(error) => {
			findings.add(path, error);
			None
		}
	}
}

impl Record {
	pub(super) fn matches_rust_tool(&self) -> bool {
		self.tool == "cargo-nextest"
			&& self
				.tool_version
				.split([' ', '\t'])
				.filter(|word| !word.is_empty())
				.take(2)
				.eq(["cargo-nextest", "0.9.151"])
	}

	pub(super) fn matches_features(&self, features: &[String]) -> bool {
		self.profile.features == features
	}

	pub(super) fn validate(&self, path: &Path, findings: &mut Findings) -> bool {
		let mut valid = true;
		let mut require = |condition: bool, message: &str| {
			if !condition {
				findings.add(path, message);
				valid = false;
			}
		};
		require(
			self.schema_version == 1 && is_uuid(&self.evidence_id),
			"expected schema version 1 and a UUID evidence ID",
		);
		require(
			texts(&self.requirement_ids, 4096, 128)
				&& self.requirement_ids.iter().all(|id| numbered_id(id, "R-"))
				&& texts(&self.obligation_ids, 4096, 128)
				&& self.obligation_ids.iter().all(|id| numbered_id(id, "P-")),
			"invalid requirement or obligation IDs",
		);
		require(
			workspace::is_commit(&self.commit) && is_digest(&self.source_digest),
			"invalid source revision or digest",
		);
		require(
			[
				&self.generated_input_digest,
				&self.lockfile_digest,
				&self.artifact_digest,
				&self.detail.extraction_digest,
				&self.detail.trace_digest,
				&self.detail.corpus_digest,
			]
			.into_iter()
			.all(|digest| digest.as_deref().is_none_or(is_digest)),
			"invalid SHA-256 digest",
		);
		require(
			text(&self.repository, 1024)
				&& text(&self.tool, 128)
				&& text(&self.tool_version, 128)
				&& texts(&self.redacted_command, 128, 4096)
				&& texts(&self.seeds, 4096, 128)
				&& texts(&self.model_bounds, 256, 512)
				&& texts(&self.assumptions, 256, 1024)
				&& text(&self.oracle, 4096),
			"missing or invalid tool, command, reproduction inputs, or oracle",
		);
		require(
			self.profile.valid() && self.detail.valid() && self.review.valid(),
			"invalid evidence profile, detail, or review",
		);
		if matches!(self.outcome, Outcome::Pass | Outcome::Fail) {
			require(
				self.started_at.as_deref().is_some_and(is_timestamp)
					&& self.duration_ms.as_deref().is_some_and(is_decimal)
					&& self.exit_status.is_some()
					&& self.artifact_digest.is_some()
					&& !self.redacted_command.is_empty(),
				"executed evidence needs a timestamp, duration, exit status, command and artifact digest",
			);
		}
		if self.outcome == Outcome::Pass {
			require(
				!self.dirty && !self.synthetic && self.exit_status == Some(0),
				"passing evidence must be clean, nonsynthetic, and exit successfully",
			);
			if self.kind.gate().is_some() {
				require(
					!self.obligation_ids.is_empty(),
					"gate evidence must name at least one owned obligation",
				);
			}
		}
		valid
	}
}

impl Profile {
	fn valid(&self) -> bool {
		texts(&self.features, 128, 256)
			&& text(&self.target, 128)
			&& text(&self.os, 256)
			&& self
				.filesystem
				.as_deref()
				.is_none_or(|value| text(value, 256))
			&& self
				.hardware
				.as_deref()
				.is_none_or(|value| text(value, 512))
	}
}

impl Detail {
	fn valid(&self) -> bool {
		[
			&self.state_count,
			&self.unwind_bound,
			&self.coverage_denominator,
			&self.mutation_denominator,
		]
		.into_iter()
		.all(|value| value.as_deref().is_none_or(is_decimal))
			&& [&self.theorem, &self.harness, &self.fuzz_target]
				.into_iter()
				.all(|value| value.as_deref().is_none_or(|value| text(value, 256)))
			&& [
				&self.axioms_tcb,
				&self.fairness,
				&self.qualification_conditions,
			]
			.into_iter()
			.all(|values| texts(values, 256, 512))
			&& self.budget.as_deref().is_none_or(|value| text(value, 512))
	}
}

impl Review {
	fn valid(&self) -> bool {
		self.reviewer
			.as_deref()
			.is_none_or(|value| text(value, 256))
			&& text(&self.justification, 4096)
			&& (!self.independent || self.reviewer.is_some())
	}
}

fn text(value: &str, maximum: usize) -> bool {
	!value.trim().is_empty() && value.chars().count() <= maximum
}

fn texts(values: &[String], max_items: usize, max_width: usize) -> bool {
	values.len() <= max_items && values.iter().all(|value| text(value, max_width))
}

fn is_digest(value: &str) -> bool {
	const SHA256_HEX_WIDTH: usize = 64;
	value.len() == SHA256_HEX_WIDTH
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn is_uuid(value: &str) -> bool {
	const SEGMENTS: [usize; 5] = [8, 4, 4, 4, 12];
	let parts = value.split('-').collect::<Vec<_>>();
	parts.len() == SEGMENTS.len()
		&& parts.into_iter().zip(SEGMENTS).all(|(part, size)| {
			part.len() == size && part.bytes().all(|byte| byte.is_ascii_hexdigit())
		})
}

fn is_decimal(value: &str) -> bool {
	const MAX_DECIMAL_DIGITS: usize = 20;
	value == "0"
		|| (!value.is_empty()
			&& !value.starts_with('0')
			&& value.len() <= MAX_DECIMAL_DIGITS
			&& value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_timestamp(value: &str) -> bool {
	let Some((date, time)) = value.split_once(['T', 't']) else {
		return false;
	};
	let mut date = date.split('-');
	let mut time = time.splitn(3, ':');
	field(date.next(), 4, 0, 9999)
		&& field(date.next(), 2, 1, 12)
		&& field(date.next(), 2, 1, 31)
		&& date.next().is_none()
		&& field(time.next(), 2, 0, 23)
		&& field(time.next(), 2, 0, 59)
		&& time.next().is_some_and(valid_seconds_and_zone)
}

fn valid_seconds_and_zone(value: &str) -> bool {
	let Some(zone_start) = value.find(['Z', 'z', '+', '-']) else {
		return false;
	};
	let (seconds, zone) = value.split_at(zone_start);
	let exact_seconds = match seconds.split_once('.') {
		Some((seconds, fraction))
			if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
		{
			seconds
		}
		_ => seconds,
	};
	let zone_ok = matches!(zone, "Z" | "z")
		|| zone
			.get(1..)
			.and_then(|offset| offset.split_once(':'))
			.is_some_and(|(hours, minutes)| {
				field(Some(hours), 2, 0, 23) && field(Some(minutes), 2, 0, 59)
			});
	field(Some(exact_seconds), 2, 0, 60) && zone_ok
}

fn field(value: Option<&str>, width: usize, minimum: u16, maximum: u16) -> bool {
	value.is_some_and(|text| {
		text.len() == width
			&& text.bytes().all(|byte| byte.is_ascii_digit())
			&& text
				.parse::<u16>()
				.is_ok_and(|number| (minimum..=maximum).contains(&number))
	})
}
