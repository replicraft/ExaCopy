use std::ffi::OsStr;
use std::path::Path;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, ItemMod, Meta, UseGlob};

use crate::finding::Findings;

pub(super) struct SourcePolicy<'a> {
	path: &'a Path,
	findings: &'a mut Findings,
	in_tests: bool,
}

impl<'a> SourcePolicy<'a> {
	pub(super) fn new(path: &'a Path, findings: &'a mut Findings) -> Self {
		let in_tests = path
			.components()
			.any(|part| part.as_os_str() == OsStr::new("tests"))
			|| path.file_name() == Some(OsStr::new("tests.rs"));
		Self {
			path,
			findings,
			in_tests,
		}
	}
}

impl<'ast> Visit<'ast> for SourcePolicy<'_> {
	fn visit_file(&mut self, file: &'ast syn::File) {
		for attr in &file.attrs {
			if suppresses_lint(&attr.meta) {
				self.findings.at_line(
					self.path,
					attr.span().start().line,
					"crate-wide lint suppression violates workspace lint policy",
				);
			}
		}
		visit::visit_file(self, file);
	}

	fn visit_item_mod(&mut self, module: &'ast ItemMod) {
		let previous = self.in_tests;
		self.in_tests |= module.attrs.iter().any(is_test_cfg);
		visit::visit_item_mod(self, module);
		self.in_tests = previous;
	}

	fn visit_item_use(&mut self, import: &'ast syn::ItemUse) {
		let previous = self.in_tests;
		self.in_tests |= import.attrs.iter().any(is_test_cfg);
		visit::visit_item_use(self, import);
		self.in_tests = previous;
	}

	fn visit_use_glob(&mut self, glob: &'ast UseGlob) {
		if !self.in_tests {
			self.findings.at_line(
				self.path,
				glob.span().start().line,
				"production glob import",
			);
		}
	}
}

fn suppresses_lint(meta: &Meta) -> bool {
	let Meta::List(list) = meta else { return false };
	if list.path.is_ident("allow") || list.path.is_ident("expect") {
		return true;
	}
	list.path.is_ident("cfg_attr")
		&& list
			.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
			.is_ok_and(|metas| metas.iter().skip(1).any(suppresses_lint))
}

fn is_test_cfg(attr: &Attribute) -> bool {
	attr.path().is_ident("cfg")
		&& attr
			.parse_args::<syn::Ident>()
			.is_ok_and(|name| name == "test")
}
