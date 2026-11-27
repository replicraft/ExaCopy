use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Item, ItemMod, Lit, Meta, MetaNameValue, Token};

use super::{Case, artifact_text};
use crate::finding::Findings;

pub(super) fn check(root: &Path, manifest: &Path, case: &Case, findings: &mut Findings) {
	let Some((modules, leaf)) = selector(&case.source, &case.selector) else {
		findings.add(
			manifest,
			format_args!("invalid native test selector {}", case.selector),
		);
		return;
	};
	if !check_link(root, &modules, &case.source, findings) {
		return;
	}
	let Some(contents) = artifact_text(root, &case.source, findings) else {
		return;
	};
	if !has_test(&contents, leaf, case.ignored) {
		findings.add(
			&root.join(&case.source),
			format_args!(
				"expected native #[test] with declared ignore state for {}",
				case.selector
			),
		);
	}
}

fn selector<'a>(source: &Path, name: &'a str) -> Option<(Vec<&'a str>, &'a str)> {
	let source_text = source.to_str()?;
	if source.extension() != Some(OsStr::new("rs"))
		|| !source_text.starts_with("tests/unit/")
		|| source_text
			.split('/')
			.any(|part| matches!(part, "" | "." | "..") || part.contains(['\\', ':']))
	{
		return None;
	}
	let (scope, leaf) = name.rsplit_once("::")?;
	let modules: Vec<_> = scope.split("::").collect();
	(modules.len() >= 2
		&& modules.first() == Some(&"linux")
		&& modules
			.iter()
			.copied()
			.chain([leaf])
			.all(|part| syn::parse_str::<syn::Ident>(part).is_ok()))
	.then_some((modules, leaf))
}

fn check_link(root: &Path, modules: &[&str], source: &Path, findings: &mut Findings) -> bool {
	let mut directory = PathBuf::from("src");
	let mut parent = directory.join("lib.rs");
	let mut test_only = false;

	for (index, module) in modules.iter().enumerate() {
		let Some(contents) = artifact_text(root, &parent, findings) else {
			return false;
		};
		let linux = index == 0;
		let external = index == modules.len() - 1;
		let expected_path = external.then(|| {
			// A file module's path attribute is relative to its physical parent.
			// Require the exact route back to the package root and owned test file.
			let depth = parent.parent().map_or(0, |path| path.components().count());
			format!("{}{}", "../".repeat(depth), source.display())
		});
		let Some(gated) = module_gate(&contents, module, linux, expected_path.as_deref()) else {
			findings.add(
				&root.join(&parent),
				format_args!("missing canonical native module declaration {module}"),
			);
			return false;
		};
		test_only |= gated;
		directory.push(module);
		parent = directory.with_extension("rs");
	}

	if !test_only {
		findings.add(
			&root.join(source),
			"linked native unit test module requires cfg(test) custody",
		);
	}
	test_only
}

fn module_gate(
	contents: &str,
	name: &str,
	linux: bool,
	expected_path: Option<&str>,
) -> Option<bool> {
	let syntax = syn::parse_file(contents).ok()?;
	if !syntax
		.attrs
		.iter()
		.all(|attr| passive_annotation(&attr.meta))
	{
		return None;
	}
	let mut declarations = syntax.items.iter().filter_map(|item| match item {
		Item::Mod(declaration) if declaration.ident == name => Some(declaration),
		_ => None,
	});
	let declaration = declarations.next()?;
	if declarations.next().is_some()
		|| declaration.content.is_some()
		|| !matches_path(declaration, expected_path)
	{
		return None;
	}
	let mut conditions = declaration
		.attrs
		.iter()
		.filter(|attr| attr.path().is_ident("cfg"));
	let test = match (linux, conditions.next()) {
		(true, Some(attr)) if linux_cfg(attr) => false,
		(false, Some(attr)) if test_cfg(attr) => true,
		(false, None) => false,
		_ => return None,
	};
	conditions.next().is_none().then_some(test)
}

fn matches_path(declaration: &ItemMod, expected: Option<&str>) -> bool {
	let mut paths = declaration
		.attrs
		.iter()
		.filter(|attr| attr.path().is_ident("path"));
	let matches = match (paths.next(), expected) {
		(None, None) => true,
		(Some(attr), Some(expected)) => matches!(
			&attr.meta,
			Meta::NameValue(MetaNameValue { value: Expr::Lit(value), .. })
				if matches!(&value.lit, Lit::Str(path) if path.value() == expected)
		),
		_ => false,
	};
	matches
		&& paths.next().is_none()
		&& declaration.attrs.iter().all(|attr| {
			let path = attr.path();
			path.is_ident("cfg") || path.is_ident("path") || passive_annotation(&attr.meta)
		})
}

fn passive_annotation(meta: &Meta) -> bool {
	let path = meta.path();
	if ["allow", "deny", "doc", "expect", "forbid", "warn"]
		.iter()
		.any(|name| path.is_ident(*name))
	{
		return true;
	}
	// Conditional lint and documentation settings cannot alter test selection.
	if let Meta::List(list) = meta
		&& path.is_ident("cfg_attr")
	{
		return list
			.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
			.is_ok_and(|args| args.len() >= 2 && args.iter().skip(1).all(passive_annotation));
	}
	false
}

fn linux_cfg(attr: &Attribute) -> bool {
	attr.parse_args::<MetaNameValue>().is_ok_and(|cfg| {
		cfg.path.is_ident("target_os")
			&& matches!(&cfg.value, Expr::Lit(value) if matches!(&value.lit, Lit::Str(os) if os.value() == "linux"))
	})
}

fn test_cfg(attr: &Attribute) -> bool {
	attr.parse_args::<syn::Path>()
		.is_ok_and(|path| path.is_ident("test"))
}

fn has_test(contents: &str, leaf: &str, ignored: bool) -> bool {
	syn::parse_file(contents).is_ok_and(|syntax| {
		if !syntax
			.attrs
			.iter()
			.all(|attr| passive_annotation(&attr.meta))
		{
			return false;
		}
		let mut functions = syntax.items.iter().filter_map(|item| match item {
			Item::Fn(function) if function.sig.ident == leaf => Some(function),
			_ => None,
		});
		let Some(test) = functions.next() else {
			return false;
		};
		functions.next().is_none()
			&& !test.block.stmts.is_empty()
			&& test
				.attrs
				.iter()
				.filter(|attr| attr.path().is_ident("test") && matches!(&attr.meta, Meta::Path(_)))
				.count()
				== 1
			&& test
				.attrs
				.iter()
				.filter(|attr| attr.path().is_ident("ignore"))
				.count()
				== usize::from(ignored)
			&& test.attrs.iter().all(|attr| {
				let path = attr.path();
				if path.is_ident("test") {
					return matches!(&attr.meta, Meta::Path(_));
				}
				if path.is_ident("ignore") {
					return matches!(&attr.meta, Meta::Path(_))
						|| matches!(&attr.meta, Meta::NameValue(MetaNameValue { value: Expr::Lit(value), .. })
							if matches!(&value.lit, Lit::Str(_)));
				}
				passive_annotation(&attr.meta)
			})
	})
}

#[cfg(test)]
#[path = "../../../tests/unit/native_linked_unit.rs"]
mod tests;
