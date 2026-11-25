use std::{error::Error, fmt};

use super::{WindowsComponent, WindowsNameError};

pub(super) const MAX_PATH_UNITS: usize = 32_767;
const MAX_COMPONENTS: usize = 64;
const SEPARATOR: u16 = b'\\' as u16;
const COLON: u16 = b':' as u16;

#[derive(Debug)]
pub(super) enum PathError {
	DrivePath,
	PathLimit,
	Component(WindowsNameError),
}

impl fmt::Display for PathError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::DrivePath => formatter.write_str("expected a literal absolute drive path"),
			Self::PathLimit => formatter.write_str("path exceeds the comparison bounds"),
			Self::Component(error) => write!(formatter, "invalid path component ({error})"),
		}
	}
}

impl Error for PathError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Component(error) => Some(error),
			_ => None,
		}
	}
}

pub(super) struct DrivePath<'name> {
	pub(super) letter: u8,
	pub(super) parents: Vec<WindowsComponent<'name>>,
	pub(super) leaf: WindowsComponent<'name>,
}

impl<'name> DrivePath<'name> {
	pub(super) fn parse(units: &'name [u16]) -> Result<Self, PathError> {
		if units.len() > MAX_PATH_UNITS {
			return Err(PathError::PathLimit);
		}
		let [letter, COLON, SEPARATOR, remaining @ ..] = units else {
			return Err(PathError::DrivePath);
		};
		let letter = u8::try_from(*letter).map_err(|_| PathError::DrivePath)?;
		if !letter.is_ascii_alphabetic() {
			return Err(PathError::DrivePath);
		}
		let mut components = remaining.split(|unit| *unit == SEPARATOR);
		let leaf = WindowsComponent::new(components.next_back().unwrap_or_default())
			.map_err(PathError::Component)?;
		let mut parents = Vec::new();
		for component in components {
			if parents.len() == MAX_COMPONENTS - 1 {
				return Err(PathError::PathLimit);
			}
			parents.push(WindowsComponent::new(component).map_err(PathError::Component)?);
		}
		Ok(Self {
			letter,
			parents,
			leaf,
		})
	}
}

#[cfg(test)]
mod tests;
