use std::io::{self, Write};
use std::path::Path;

pub(super) fn write(output: &mut impl Write) -> io::Result<()> {
	let executable = std::env::current_exe().ok();
	render(output, executable.as_deref())
}

fn render(output: &mut impl Write, executable: Option<&Path>) -> io::Result<()> {
	writeln!(output, "exacopy {}", env!("CARGO_PKG_VERSION"))?;
	match executable {
		Some(path) => writeln!(output, "Executable: {path:?}")?,
		None => writeln!(output, "Executable: unknown")?,
	}
	writeln!(output, "Install origin: unknown")?;
	output.flush()
}

#[cfg(test)]
mod tests {
	use super::{Path, render};

	#[test]
	fn reports_unavailable_path_and_origin() {
		let mut output = Vec::new();
		render(&mut output, None).expect("write unavailable path");
		assert_eq!(
			String::from_utf8(output).expect("read version as UTF-8"),
			concat!(
				"exacopy ",
				env!("CARGO_PKG_VERSION"),
				"\nExecutable: unknown\nInstall origin: unknown\n"
			)
		);
	}

	#[test]
	fn escapes_line_breaks_and_quotes_in_observed_path() {
		let mut output = Vec::new();
		let path = Path::new("exe\nwith\r\"quote");
		render(&mut output, Some(path)).expect("write escaped path");
		let output = String::from_utf8(output).expect("read version as UTF-8");
		assert_eq!(
			output.lines().nth(1),
			Some(r#"Executable: "exe\nwith\r\"quote""#)
		);
		assert_eq!(output.lines().count(), 3);
	}
}
