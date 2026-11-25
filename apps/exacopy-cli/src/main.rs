//! Local ExaCopy command-line application.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
	exacopy_cli::run(std::env::args_os().skip(1))
}
