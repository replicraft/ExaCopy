use std::fmt;
use std::path::Path;

#[derive(Debug, Default)]
pub(crate) struct Findings(Vec<String>);

impl Findings {
	pub(crate) fn add(&mut self, path: &Path, message: impl fmt::Display) {
		self.0.push(format!("{}: {message}", path.display()));
	}

	pub(crate) fn at_line(&mut self, path: &Path, line: usize, message: impl fmt::Display) {
		self.0.push(format!("{}:{line}: {message}", path.display()));
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl fmt::Display for Findings {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		for finding in &self.0 {
			writeln!(formatter, "{finding}")?;
		}
		Ok(())
	}
}
