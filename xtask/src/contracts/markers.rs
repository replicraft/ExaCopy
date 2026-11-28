use std::fs;
use std::path::Path;

use syn::{Expr, File, Item, Lit};

use self::schema::{report_version, schema_version};
use super::{Contract, Kind, Status};

mod bindings;
mod schema;

#[cfg(test)]
mod tests;

pub(super) struct Binding {
	pub(super) id: &'static str,
	owner: &'static str,
	marker: Marker,
}

enum Marker {
	Report,
	Manifest,
	DocumentPage,
	NamedDocumentPage {
		version: &'static str,
	},
	PlanBody,
	PlanJson,
	Workflow {
		features: &'static str,
	},
	Scalar {
		version: &'static str,
		magic: Option<&'static str>,
	},
	MagicSuffix {
		magic: &'static str,
		width: usize,
	},
	Pair {
		major: &'static str,
		minor: &'static str,
		features: &'static str,
		magic: Option<&'static str>,
	},
	Array {
		version: &'static str,
		width: usize,
	},
}

pub(super) use bindings::BINDINGS;

impl Binding {
	const fn new(id: &'static str, owner: &'static str, marker: Marker) -> Self {
		Self { id, owner, marker }
	}

	pub(super) fn check(&self, root: &Path, record: &Contract) -> Result<(), String> {
		let (kind, status) = match self.marker {
			Marker::Report => (Kind::CliOutput, Status::Implemented),
			Marker::Manifest => (Kind::Manifest, Status::Implemented),
			Marker::DocumentPage | Marker::NamedDocumentPage { .. } => {
				(Kind::DocumentPage, Status::Implemented)
			}
			Marker::Workflow { .. } => (Kind::WorkflowRecord, Status::ImplementedPrivate),
			Marker::PlanBody | Marker::PlanJson => (Kind::Plan, Status::Implemented),
			_ => (Kind::TransferJournal, Status::ImplementedPrivate),
		};
		record.check_classification(kind, status, Some(Path::new(self.owner)))?;
		let source = fs::read_to_string(root.join(self.owner))
			.map_err(|error| format!("{}: {error}", self.owner))?;
		let file = syn::parse_file(&source).map_err(|error| format!("{}: {error}", self.owner))?;
		let markers = self.marker.read(&file, self.id)?;
		let actual_version = Some(markers.version.as_str());
		if record.version.as_deref() != actual_version {
			return Err(format!(
				"version differs from {} in {}",
				markers.version, self.owner
			));
		}
		if record.required_features != markers.features {
			return Err(format!(
				"required feature mask differs from {:?} in {}",
				markers.features, self.owner
			));
		}
		if record.magic != markers.magic {
			return Err(format!(
				"magic differs from {:?} in {}",
				markers.magic, self.owner
			));
		}
		Ok(())
	}
}

struct Markers {
	version: String,
	features: Option<u64>,
	magic: Option<String>,
}

impl Marker {
	const fn array(version: &'static str, width: usize) -> Self {
		Self::Array { version, width }
	}

	const fn pair(major: &'static str, minor: &'static str, features: &'static str) -> Self {
		Self::Pair {
			major,
			minor,
			features,
			magic: None,
		}
	}

	const fn pair_with_magic(
		major: &'static str,
		minor: &'static str,
		features: &'static str,
		magic: &'static str,
	) -> Self {
		Self::Pair {
			major,
			minor,
			features,
			magic: Some(magic),
		}
	}

	fn read(&self, file: &File, id: &str) -> Result<Markers, String> {
		let (version, features, magic) = match *self {
			Self::Report => (report_version(file, id)?, None, None),
			Self::Manifest => (
				schema_version(constant(file, "SCHEMA_VERSION")?)?,
				None,
				None,
			),
			Self::PlanJson => (schema_version(constant(file, "VERSION")?)?, None, None),
			Self::NamedDocumentPage { version } => {
				return Self::array(version, 2).read(file, id);
			}
			Self::DocumentPage | Self::PlanBody => {
				let Expr::Array(values) = constant(file, "VERSION")? else {
					return Err("expected a VERSION array".into());
				};
				let values = values
					.elems
					.iter()
					.map(number)
					.collect::<Result<Vec<_>, _>>()?;
				let [major, minor] = values.as_slice() else {
					return Err("expected two entries in VERSION".into());
				};
				(format!("{major}.{minor}"), None, None)
			}
			Self::Workflow { features } => {
				let mut markers = Self::array("VERSION", 2).read(file, id)?;
				markers.features = Some(number(constant(file, features)?)?);
				return Ok(markers);
			}
			Self::Scalar { version, magic } => (
				number(constant(file, version)?)?.to_string(),
				None,
				magic.map(|name| bytes(constant(file, name)?)).transpose()?,
			),
			Self::MagicSuffix { magic, width } => {
				let magic = bytes(constant(file, magic)?)?;
				let suffix = magic
					.as_bytes()
					.get(magic.len().saturating_sub(width)..)
					.filter(|suffix| {
						width > 0 && suffix.len() == width && suffix.iter().all(u8::is_ascii_digit)
					})
					.ok_or("expected a decimal version suffix in the magic")?;
				let version = std::str::from_utf8(suffix)
					.map_err(|error| error.to_string())?
					.parse::<u64>()
					.map_err(|error| error.to_string())?;
				(version.to_string(), None, Some(magic))
			}
			Self::Pair {
				major,
				minor,
				features,
				magic,
			} => (
				format!(
					"{}.{}",
					number(constant(file, major)?)?,
					number(constant(file, minor)?)?
				),
				Some(number(constant(file, features)?)?),
				magic.map(|name| bytes(constant(file, name)?)).transpose()?,
			),
			Self::Array { version, width } => {
				let Expr::Array(values) = constant(file, version)? else {
					return Err(format!("expected a {version} array"));
				};
				let values = values
					.elems
					.iter()
					.map(number)
					.collect::<Result<Vec<_>, _>>()?;
				match values.as_slice() {
					[major, minor] if width == 2 => (format!("{major}.{minor}"), None, None),
					[major, minor, features] if width == 3 => {
						(format!("{major}.{minor}"), Some(*features), None)
					}
					_ => return Err(format!("expected {width} entries in {version}")),
				}
			}
		};
		Ok(Markers {
			version,
			features,
			magic,
		})
	}
}

fn constant<'a>(file: &'a File, name: &str) -> Result<&'a Expr, String> {
	let mut matches = file.items.iter().filter_map(|item| match item {
		Item::Const(item) if item.ident == name => Some(item.expr.as_ref()),
		_ => None,
	});
	match (matches.next(), matches.next()) {
		(Some(value), None) => Ok(value),
		_ => Err(format!("expected one top-level {name} constant")),
	}
}

fn number(expression: &Expr) -> Result<u64, String> {
	if let Expr::Lit(literal) = expression
		&& let Lit::Int(value) = &literal.lit
	{
		return value.base10_parse().map_err(|error| error.to_string());
	}
	Err("expected a literal unsigned integer marker".into())
}

fn bytes(expression: &Expr) -> Result<String, String> {
	if let Expr::Lit(literal) = expression
		&& let Lit::ByteStr(value) = &literal.lit
	{
		return String::from_utf8(value.value()).map_err(|error| error.to_string());
	}
	Err("expected a literal byte string marker".into())
}
