//! Entry point for repository policy checks.

#![forbid(unsafe_code)]

mod command;
mod evidence;
mod finding;
mod source;
#[cfg(test)]
mod test_support;
mod verification;
mod workspace;

fn main() -> std::process::ExitCode {
	command::run(std::env::args_os().skip(1))
}
