//! Local ExaCopy command-line application.
#![forbid(unsafe_code)]

mod args;
mod command;
#[cfg(target_os = "linux")]
mod copy;
mod copy_report;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_path;
#[cfg(target_os = "linux")]
mod profile;
#[cfg(target_os = "linux")]
mod recovery;
mod recovery_report;
mod report;

fn main() -> std::process::ExitCode {
	command::run(std::env::args_os().skip(1))
}
