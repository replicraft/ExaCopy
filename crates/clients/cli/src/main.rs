//! Local ExaCopy command-line application.
#![forbid(unsafe_code)]

mod args;
mod command;
#[cfg(target_os = "linux")]
mod linux;
mod report;

fn main() -> std::process::ExitCode {
	command::run(std::env::args_os().skip(1))
}
