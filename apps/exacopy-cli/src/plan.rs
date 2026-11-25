use std::io::Write;

use crate::args::PlanCommand;

#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod native;

pub(crate) fn run(command: &PlanCommand, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
	#[cfg(target_os = "linux")]
	{
		match native::export(command) {
			Ok(digest) => {
				if writeln!(stdout, "Wrote public plan {}", native::hex(&digest))
					.and_then(|()| stdout.flush())
					.is_ok()
				{
					0
				} else {
					let _ = writeln!(
						stderr,
						"exacopy: the plan was written but confirmation output failed"
					);
					4
				}
			}
			Err(error) => {
				let _ = writeln!(stderr, "exacopy: {error}");
				error.exit_code()
			}
		}
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (
			&command.source,
			&command.destination,
			&command.profile,
			&command.output,
			stdout,
		);
		let _ = writeln!(stderr, "exacopy: local planning requires Linux");
		6
	}
}
