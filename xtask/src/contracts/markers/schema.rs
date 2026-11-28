use syn::visit::{self, Visit};
use syn::{Expr, ExprStruct, File, Lit};

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

pub(super) fn report_version(file: &File, id: &str) -> Result<String, String> {
	let mut initializers = ReportInitializers::default();
	initializers.visit_file(file);
	let [(schema, version)] = initializers.0.as_slice() else {
		return Err("expected one report initializer with schema and schema_version".into());
	};
	if report_string(schema)?.as_str() != id {
		return Err(format!("report schema identifier differs from {id}"));
	}
	version_text(&report_string(version)?)
}

pub(super) fn schema_version(expression: &Expr) -> Result<String, String> {
	let version = string(expression).ok_or("expected a literal schema_version string")?;
	version_text(&version)
}

fn version_text(version: &str) -> Result<String, String> {
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
	Ok(version.to_owned())
}

fn report_string(expression: &Expr) -> Result<String, String> {
	let expression = match expression {
		Expr::MethodCall(call)
			if call.method == "into" && call.args.is_empty() && call.turbofish.is_none() =>
		{
			call.receiver.as_ref()
		}
		_ => expression,
	};
	string(expression).ok_or_else(|| "expected a literal report string".into())
}

fn string(expression: &Expr) -> Option<String> {
	if let Expr::Lit(literal) = expression
		&& let Lit::Str(value) = &literal.lit
	{
		return Some(value.value());
	}
	None
}
