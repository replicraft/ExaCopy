use std::io::{self, Read};

use sha2::{Digest, Sha256};

use super::{MAX_LINE_BYTES, MAX_LOG_BYTES, check};

const RUN: &str = concat!(
	"    Finished \x60test\x60 profile target(s) in 0.06s\n",
	"────────────\n",
	" Nextest run ID 3191c34d-12fd-4f7f-8c4d-442b5d7733a4 with nextest profile: default\n",
	"    Starting 1 test across 29 binaries (337 tests skipped)\n",
	"        PASS [   0.004s] (1/1) exacopy-journal::example test_exact\n",
	"────────────\n",
	"     Summary [   0.005s] 1 test run: 1 passed, 337 skipped\n",
);

fn passes(raw: &[u8]) -> io::Result<String> {
	check(raw, "exacopy-journal", "test_exact")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
	package: String,
	test: String,
	cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
	id: String,
	accepted: bool,
	transcript: String,
}

#[test]
fn rust_gate_matches_the_shared_nextest_transcript_corpus() {
	let raw = include_str!("../../../verification/nextest-transcript-corpus.json");
	let corpus: Corpus =
		serde_json::from_str(raw).expect("shared transcript fixture is canonical JSON");
	assert!(corpus.cases.iter().any(|case| case.accepted));
	assert!(corpus.cases.iter().any(|case| !case.accepted));
	for case in corpus.cases {
		let bytes = case.transcript.as_bytes();
		let proof = check(bytes, &corpus.package, &corpus.test);
		assert_eq!(proof.is_ok(), case.accepted, "shared case {}", case.id);
		if let Ok(digest) = proof {
			assert_eq!(
				digest,
				format!("{:x}", Sha256::digest(bytes)),
				"shared case {}",
				case.id
			);
		}
	}
}

#[test]
fn rust_gate_refuses_partial_duplicate_and_bounded_stream_failures() {
	for end in 0..RUN.len() {
		assert!(
			passes(&RUN.as_bytes()[..end]).is_err(),
			"accepted a cut at {end}"
		);
	}
	for wrong in [
		"PASS test_exact arbitrary fixture output\n".to_owned(),
		RUN.repeat(2),
		format!("{RUN} \n"),
		format!("FAIL [0.000s] (1/1) exacopy-journal::example test_exact\n{RUN}"),
		format!("error: compilation failed\n{RUN}"),
		RUN.replace(
			"        PASS",
			"        PASS [0.001s] (1/1) exacopy-journal::example test_exact\n        PASS",
		),
		format!("\x1b[30m{RUN}"),
		format!("{}\n{RUN}", "x".repeat(MAX_LINE_BYTES)),
	] {
		assert!(
			passes(wrong.as_bytes()).is_err(),
			"accepted malformed attendance evidence"
		);
	}

	let line = format!("{}\n", "x".repeat(MAX_LINE_BYTES - 1));
	let limit = usize::try_from(MAX_LOG_BYTES).unwrap();
	let oversized = line.repeat(limit / MAX_LINE_BYTES) + RUN;
	assert!(passes(oversized.as_bytes()).is_err());

	let failed_eof = RUN.as_bytes().chain(FailedEof);
	let error = check(failed_eof, "exacopy-journal", "test_exact").unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
	assert_eq!(error.to_string(), "original read failure");
}

struct FailedEof;

impl Read for FailedEof {
	fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
		Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"original read failure",
		))
	}
}
