use std::path::Path;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Ident, Meta};

use crate::finding::Findings;

pub(super) fn check(path: &Path, file: &syn::File, findings: &mut Findings) {
	if path
		.ancestors()
		.any(|ancestor| ancestor.ends_with("crates/network/ssh/src"))
	{
		CallerStreamPolicy { path, findings }.visit_file(file);
	}
}

struct CallerStreamPolicy<'a> {
	path: &'a Path,
	findings: &'a mut Findings,
}

impl Visit<'_> for CallerStreamPolicy<'_> {
	fn visit_ident(&mut self, identifier: &Ident) {
		let spelling = identifier.to_string();
		if matches!(
			spelling.trim_start_matches("r#"),
			"process" | "os" | "env" | "fs" | "net" | "include" | "include_str" | "include_bytes"
		) {
			self.findings.at_line(
				self.path,
				identifier.span().start().line,
				format_args!("caller-stream SSH source cannot use process, OS, ambient I/O or include capabilities ({identifier})"),
			);
		}
	}

	fn visit_attribute(&mut self, attribute: &Attribute) {
		if platform_cfg(&attribute.meta) {
			self.findings.at_line(
				self.path,
				attribute.span().start().line,
				"caller-stream SSH source cannot depend on platform cfg",
			);
		}
		visit::visit_attribute(self, attribute);
	}
}

fn platform_cfg(meta: &Meta) -> bool {
	let path = meta.path();
	if path.get_ident().is_some_and(|identifier| {
		matches!(
			identifier.to_string().as_str(),
			"unix" | "windows" | "target_os" | "target_family" | "target_env" | "target_vendor"
		)
	}) {
		return true;
	}
	let Meta::List(list) = meta else {
		return false;
	};
	if !["cfg", "cfg_attr", "all", "any", "not"]
		.iter()
		.any(|name| path.is_ident(name))
	{
		return false;
	}
	list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
		.is_ok_and(|nested| nested.iter().any(platform_cfg))
}

#[cfg(test)]
mod tests;
