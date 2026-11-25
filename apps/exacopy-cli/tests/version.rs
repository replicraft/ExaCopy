//! Process-level tests for the universal version command.

use std::path::Path;
use std::process::Command;

const EXACOPY: &str = env!("CARGO_BIN_EXE_exacopy");

#[test]
fn version_flags_report_build_and_running_executable() {
	let executable = Path::new(EXACOPY);
	let file_name = executable.file_name().expect("binary file name");
	let escaped_file_name = format!("{file_name:?}");
	let path_suffix = escaped_file_name
		.strip_prefix('"')
		.expect("escaped path quote");
	for flag in ["--version", "-V"] {
		let output = Command::new(executable)
			.arg(flag)
			.output()
			.expect("invoke version");
		assert_eq!(output.status.code(), Some(0), "{flag}");
		assert!(output.stderr.is_empty(), "{flag}");
		let stdout = String::from_utf8(output.stdout).expect("read version as UTF-8");
		let mut lines = stdout.lines();
		assert_eq!(
			lines.next(),
			Some(concat!("exacopy ", env!("CARGO_PKG_VERSION"))),
			"{flag}"
		);
		let path_line = lines.next().expect("version prints a path line");
		assert!(path_line.starts_with("Executable: \""), "{path_line}");
		assert!(path_line.ends_with(path_suffix), "{path_line}");
		assert_eq!(lines.next(), Some("Install origin: unknown"), "{flag}");
		assert_eq!(lines.next(), None, "{flag}");
	}
}

#[test]
fn version_is_a_standalone_root_flag() {
	let help = Command::new(EXACOPY)
		.arg("--help")
		.output()
		.expect("invoke help");
	assert_eq!(help.status.code(), Some(0));
	assert!(
		String::from_utf8(help.stdout)
			.expect("read help as UTF-8")
			.contains("-V, --version")
	);
	for args in [
		&[][..],
		&["--version", "diff"],
		&["-V", "--version"],
		&["-VV"],
		&["--", "--version"],
		&["diff", "left", "right", "--version"],
	] {
		let output = Command::new(EXACOPY)
			.args(args)
			.output()
			.expect("invoke invalid command");
		assert_eq!(output.status.code(), Some(2), "{args:?}");
		assert!(output.stdout.is_empty(), "{args:?}");
		assert!(!output.stderr.is_empty(), "{args:?}");
	}
}

#[cfg(unix)]
#[test]
fn unwritable_stdout_reports_inconclusive_status() {
	let (reader, writer) = std::io::pipe().expect("create an output pipe");
	drop(reader);
	let output = Command::new(EXACOPY)
		.arg("--version")
		.stdout(writer)
		.output()
		.expect("invoke version with a closed output pipe");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	let diagnostic = String::from_utf8(output.stderr).expect("read diagnostic as UTF-8");
	assert!(diagnostic.starts_with("exacopy: could not write version information"));
}
