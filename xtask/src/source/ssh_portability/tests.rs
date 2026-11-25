use super::*;

#[test]
fn checks_production_source_only_and_ignores_text() {
	let source = Path::new("crates/network/ssh/src/transport.rs");
	let fixture = Path::new("crates/network/ssh/tests/openssh.rs");
	let allowed = syn::parse_file(
		r#"
		#[cfg(feature = "experimental-ssh")]
		fn transport() { let name = "std::process::Command"; }
		"#,
	)
	.unwrap();
	let blocked = syn::parse_file(
		r#"
		use std::{io, r#process as child};
		#[cfg(any(unix, target_os = "windows"))]
		fn transport() { child::Command::new("ssh").spawn(); }
		"#,
	)
	.unwrap();
	let mut findings = Findings::default();
	check(source, &allowed, &mut findings);
	check(fixture, &blocked, &mut findings);
	assert!(findings.is_empty(), "{findings}");
	check(source, &blocked, &mut findings);
	assert!(findings.to_string().contains("ambient I/O"));
	assert!(findings.to_string().contains("platform cfg"));
}
