use std::fs;
use std::path::Path;

use syn::visit::{self, Visit};
use syn::{Expr, ExprStruct, File, Item, Lit};

use super::{Contract, Kind, Status};

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
	PlanBody,
	PlanJson,
	Workflow {
		features: &'static str,
	},
	Scalar {
		version: &'static str,
		magic: Option<&'static str>,
	},
	Pair {
		major: &'static str,
		minor: &'static str,
		features: &'static str,
	},
	Array {
		version: &'static str,
		width: usize,
	},
}

pub(super) const BINDINGS: &[Binding] = &[
	Binding::new(
		"workflow-local-sync-endpoint",
		"crates/formats/exacopy-plan/src/workflow_sync/wire.rs",
		Marker::Workflow {
			features: "ENDPOINT_REQUIRED_FEATURES",
		},
	),
	Binding::new(
		"workflow-sync-genesis-root",
		"crates/formats/exacopy-plan/src/workflow_sync/wire.rs",
		Marker::Workflow {
			features: "ROOT_REQUIRED_FEATURES",
		},
	),
	Binding::new(
		"exacopy.cli.verify",
		"apps/exacopy-cli/src/manifest_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.diff",
		"apps/exacopy-cli/src/report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.copy",
		"apps/exacopy-cli/src/copy_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.local_recovery_inspection",
		"apps/exacopy-cli/src/recovery_report.rs",
		Marker::Report,
	),
	Binding::new(
		"portable-manifests",
		"crates/formats/exacopy-manifest/src/manifest/json.rs",
		Marker::Manifest,
	),
	Binding::new(
		"public-plan-entries-page",
		"crates/formats/exacopy-plan/src/plan_entries/wire.rs",
		Marker::DocumentPage,
	),
	Binding::new(
		"workflow-paired-baseline-leaf",
		"crates/formats/exacopy-manifest/src/sync_baseline/wire.rs",
		Marker::DocumentPage,
	),
	Binding::new(
		"public-plan-body",
		"crates/formats/exacopy-plan/src/plan/wire.rs",
		Marker::PlanBody,
	),
	Binding::new(
		"public-plan-json",
		"crates/formats/exacopy-plan/src/plan/json.rs",
		Marker::PlanJson,
	),
	Binding::new(
		"local-journal-frame",
		"crates/storage/exacopy-journal/src/frame.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: Some("MAGIC"),
		},
	),
	Binding::new(
		"linux-owner",
		"crates/storage/exacopy-journal/src/owner/codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-owner",
		"crates/storage/exacopy-journal/src/owner/apply_codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-copy-plan",
		"crates/engines/exacopy-transfer/src/linux/plan/wire.rs",
		Marker::array("VERSION", 2),
	),
	Binding::new(
		"linux-prepared",
		"crates/storage/exacopy-journal/src/prepared/wire.rs",
		Marker::pair("VERSION_MAJOR", "VERSION_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-publication-intent",
		"crates/storage/exacopy-journal/src/intent.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-intent",
		"crates/storage/exacopy-journal/src/intent/public_apply.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-range-page",
		"crates/storage/exacopy-journal/src/verification_records/ranges.rs",
		Marker::Scalar {
			version: "PAGE_FORMAT_VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-copy-receipt",
		"crates/engines/exacopy-transfer/src/linux/receipt.rs",
		Marker::pair("MAJOR_VERSION", "MINOR_VERSION", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-receipt",
		"crates/engines/exacopy-transfer/src/linux/receipt/public_apply.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-resolved-direct-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("RESOLVED_DIRECT_VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-absolute-path-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("ABSOLUTE_PATH_VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-records",
		"crates/storage/exacopy-journal/src/remote_download/records/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-finalization",
		"crates/storage/exacopy-journal/src/remote_download/finalization/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-capture-retirement",
		"crates/storage/exacopy-journal/src/remote_download/retirement/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-capture-continuation",
		"crates/storage/exacopy-journal/src/remote_download/continuation/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-destination-qualification",
		"crates/storage/exacopy-journal/src/remote_download/qualification/wire.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-remote-continued-checkpoint",
		"crates/storage/exacopy-journal/src/remote_download/continuation/checkpoint.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-continuation-qualification",
		"crates/storage/exacopy-journal/src/remote_download/qualification/continuation/wire.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-remote-download-receipt",
		"crates/storage/exacopy-journal/src/remote_download/finalization/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-witness-intent",
		"crates/storage/exacopy-journal/src/remote_download/witness/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-witness-receipt-ready",
		"crates/storage/exacopy-journal/src/remote_download/witness/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-stage-directory-bootstrap",
		"crates/storage/exacopy-journal/src/remote_download/bootstrap.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"darwin-managed-apfs-owner",
		"crates/storage/exacopy-journal/src/owner/darwin_codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "MANAGED_APFS_REQUIRED"),
	),
	Binding::new(
		"darwin-managed-apfs-copy-plan",
		"crates/engines/exacopy-transfer/src/macos/plan/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"darwin-managed-apfs-prepared",
		"crates/storage/exacopy-journal/src/darwin_prepared/wire.rs",
		Marker::pair("VERSION_MAJOR", "VERSION_MINOR", "MANAGED_APFS_REQUIRED"),
	),
	Binding::new(
		"darwin-managed-apfs-copy-receipt",
		"crates/engines/exacopy-transfer/src/macos/receipt/wire.rs",
		Marker::array("VERSION", 3),
	),
];

impl Binding {
	const fn new(id: &'static str, owner: &'static str, marker: Marker) -> Self {
		Self { id, owner, marker }
	}

	pub(super) fn check(&self, root: &Path, record: &Contract) -> Result<(), String> {
		let (kind, status) = match self.marker {
			Marker::Report => (Kind::CliOutput, Status::Implemented),
			Marker::Manifest => (Kind::Manifest, Status::Implemented),
			Marker::DocumentPage => (Kind::DocumentPage, Status::Implemented),
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
			Self::Pair {
				major,
				minor,
				features,
			} => (
				format!(
					"{}.{}",
					number(constant(file, major)?)?,
					number(constant(file, minor)?)?
				),
				Some(number(constant(file, features)?)?),
				None,
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

#[derive(Default)]
struct ReportInitializers<'ast>(Vec<(&'ast Expr, &'ast Expr)>);

impl<'ast> Visit<'ast> for ReportInitializers<'ast> {
	fn visit_expr_struct(&mut self, expression: &'ast ExprStruct) {
		let field = |name| {
			expression
				.fields
				.iter()
				.find_map(|field| match &field.member {
					syn::Member::Named(member) if member == name => Some(&field.expr),
					_ => None,
				})
		};
		if let (Some(schema), Some(version)) = (field("schema"), field("schema_version")) {
			self.0.push((schema, version));
		}
		visit::visit_expr_struct(self, expression);
	}
}

fn report_version(file: &File, id: &str) -> Result<String, String> {
	let mut initializers = ReportInitializers::default();
	initializers.visit_file(file);
	let [(schema, version)] = initializers.0.as_slice() else {
		return Err("expected one report initializer with schema and schema_version".into());
	};
	if string(schema).as_deref() != Some(id) {
		return Err(format!("report schema identifier differs from {id}"));
	}
	schema_version(version)
}

fn schema_version(expression: &Expr) -> Result<String, String> {
	let version = string(expression).ok_or("expected a literal schema_version string")?;
	let (major, minor) = version
		.split_once('.')
		.ok_or("expected major.minor schema_version")?;
	let major: u64 = major
		.parse()
		.map_err(|_| "expected unsigned schema major")?;
	let minor: u64 = minor
		.parse()
		.map_err(|_| "expected unsigned schema minor")?;
	if version != format!("{major}.{minor}") {
		return Err("expected canonical major.minor schema_version".into());
	}
	Ok(version)
}

fn string(expression: &Expr) -> Option<String> {
	if let Expr::Lit(literal) = expression
		&& let Lit::Str(value) = &literal.lit
	{
		return Some(value.value());
	}
	None
}
