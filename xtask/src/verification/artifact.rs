use std::ffi::OsStr;
use std::path::Path;

use syn::parse::{ParseStream, Parser};
use syn::{Attribute, Item, ItemFn, LitInt, LitStr};

use crate::finding::Findings;
use crate::verification::{KaniLink, LeanLink, RustLink, TlcLink, artifact_text, kani_runner};

const PROOFS: &str = "verification/Proofs";
const GENERATED: &str = "verification/Generated";
const KANI: &str = "verification/kani";
const TLA: &str = "verification/tla";

pub(super) fn owned_location(owner: &Path, file: &Path) -> bool {
	let Ok(relative) = file.strip_prefix(owner) else {
		return false;
	};
	match file.extension().and_then(OsStr::to_str) {
		Some("lean") => relative.starts_with("Generated") || relative.starts_with("Proofs"),
		Some("tla") => relative.starts_with("tla"),
		Some("rs") => relative.starts_with("kani"),
		_ => relative.components().count() == 1,
	}
}

pub(super) fn check_symbols(root: &Path, file: &Path, symbols: &[String], findings: &mut Findings) {
	let Some(contents) = artifact_text(root, file, findings) else {
		return;
	};
	let extension = file.extension().and_then(OsStr::to_str);
	let names = match extension {
		Some("rs") => {
			let Ok(syntax) = syn::parse_file(&contents) else {
				return;
			};
			syntax
				.items
				.iter()
				.flat_map(rust_symbols)
				.collect::<Vec<_>>()
		}
		Some("tla") => contents
			.lines()
			.filter_map(|line| line.split_once("=="))
			.filter_map(|(declaration, _)| declaration.trim().split(['(', ' ']).next())
			.map(str::to_owned)
			.collect(),
		_ => {
			findings.add(
				&root.join(file),
				"source symbol links support Rust and TLA+ files",
			);
			return;
		}
	};
	for symbol in symbols {
		if !names.contains(symbol) {
			findings.add(
				&root.join(file),
				format_args!("missing obligation source symbol {symbol}"),
			);
		}
	}
}

fn rust_symbols(item: &Item) -> Vec<String> {
	let name = match item {
		Item::Const(item) => &item.ident,
		Item::Enum(item) => &item.ident,
		Item::Fn(item) => &item.sig.ident,
		Item::Mod(item) => &item.ident,
		Item::Static(item) => &item.ident,
		Item::Struct(item) => &item.ident,
		Item::Trait(item) => &item.ident,
		Item::Type(item) => &item.ident,
		Item::Impl(item) => {
			let syn::Type::Path(owner) = &*item.self_ty else {
				return Vec::new();
			};
			let Some(owner) = owner.path.segments.last() else {
				return Vec::new();
			};
			return item
				.items
				.iter()
				.filter_map(|member| match member {
					syn::ImplItem::Fn(function) => {
						Some(format!("{}::{}", owner.ident, function.sig.ident))
					}
					_ => None,
				})
				.collect();
		}
		_ => return Vec::new(),
	};
	vec![name.to_string()]
}

pub(super) fn check_rust(root: &Path, link: &RustLink, findings: &mut Findings) {
	if (link.file.starts_with("src") || link.file.starts_with("tests"))
		&& link.file.extension() == Some(OsStr::new("rs"))
	{
		check_function(
			root,
			&link.file,
			&link.test,
			|function| {
				function
					.attrs
					.iter()
					.any(|attr| attr.path().is_ident("test"))
					&& !function
						.attrs
						.iter()
						.any(|attr| attr.path().is_ident("ignore"))
			},
			"#[test]",
			true,
			findings,
		);
	} else {
		findings.add(
			&root.join(&link.file),
			"Rust test must be a Rust file under src/ or tests/",
		);
	}
}

pub(super) fn check_kani(root: &Path, link: &KaniLink, findings: &mut Findings) {
	if !location(root, &link.file, KANI, "rs", findings) {
		return;
	}
	if link.unwind_bound == 0 {
		findings.add(&root.join(&link.file), "Kani unwind bound must be positive");
	}
	let script = if let Some(runner) = &link.runner {
		match kani_runner(root, runner) {
			Ok(path) => path,
			Err(error) => {
				findings.add(&root.join(runner), error);
				return;
			}
		}
	} else {
		root.join("verification/kani/check.sh")
	};
	let default_unwind = std::fs::read_to_string(&script)
		.ok()
		.is_some_and(|contents| {
			let flags = contents
				.lines()
				.filter(|line| !line.trim_start().starts_with('#'))
				.flat_map(str::split_whitespace)
				.collect::<Vec<_>>();
			if flags.contains(&"--no-unwinding-checks") {
				findings.add(&script, "Kani script must preserve unwinding assertions");
			}
			flags.windows(2).any(|pair| {
				pair[0] == "--default-unwind" && pair[1].parse::<u32>() == Ok(link.unwind_bound)
			})
		});
	check_function(
		root,
		&link.file,
		&link.harness,
		|function| {
			let unwind = function.attrs.iter().find(|attr| kani_attr(attr, "unwind"));
			let matching_unwind = unwind.map_or(default_unwind, |attr| {
				attr.parse_args::<LitInt>()
					.ok()
					.and_then(|bound| bound.base10_parse::<u32>().ok())
					== Some(link.unwind_bound)
			});
			function.attrs.iter().any(|attr| kani_attr(attr, "proof")) && matching_unwind
		},
		"#[kani::proof] with the declared unwind bound",
		false,
		findings,
	);
	let lib = Path::new("src/lib.rs");
	let linked = artifact_text(root, lib, findings)
		.and_then(|contents| syn::parse_file(&contents).ok())
		.is_some_and(|syntax| {
			let entrypoint = Path::new(KANI).join("mod.rs");
			syntax.items.iter().any(|item| {
				let Item::Mod(module) = item else {
					return false;
				};
				let cfg_kani = module.attrs.iter().any(|attr| {
					attr.path().is_ident("cfg")
						&& attr.parse_args::<syn::Ident>().is_ok_and(|id| id == "kani")
				});
				let Some(path) = module.attrs.iter().find_map(path_attribute) else {
					return false;
				};
				let Some(path) = path.strip_prefix("../") else {
					return false;
				};
				cfg_kani
					&& module.content.is_none()
					&& (Path::new(path) == link.file
						|| (Path::new(path) == entrypoint
							&& declares_harness_module(root, &entrypoint, &link.file, findings)))
			})
		});
	if !linked {
		findings.add(
			&root.join(lib),
			"Kani harness must be explicitly linked through a cfg(kani) crate module",
		);
	}
}

fn declares_harness_module(
	root: &Path,
	entrypoint: &Path,
	file: &Path,
	findings: &mut Findings,
) -> bool {
	let Some(contents) = artifact_text(root, entrypoint, findings) else {
		return false;
	};
	syn::parse_file(&contents).is_ok_and(|syntax| {
		syntax.items.iter().any(|item| {
			let Item::Mod(module) = item else {
				return false;
			};
			let name = module
				.attrs
				.iter()
				.find_map(path_attribute)
				.unwrap_or_else(|| format!("{}.rs", module.ident));
			module.content.is_none() && Path::new(KANI).join(name) == file
		})
	})
}

fn path_attribute(attr: &Attribute) -> Option<String> {
	if !attr.path().is_ident("path") {
		return None;
	}
	let syn::Expr::Lit(value) = &attr.meta.require_name_value().ok()?.value else {
		return None;
	};
	let syn::Lit::Str(literal) = &value.lit else {
		return None;
	};
	Some(LitStr::value(literal))
}

fn kani_attr(attr: &Attribute, name: &str) -> bool {
	let mut segments = attr.path().segments.iter();
	segments.next().is_some_and(|item| item.ident == "kani")
		&& segments.next().is_some_and(|item| item.ident == name)
		&& segments.next().is_none()
}

fn check_function(
	root: &Path,
	file: &Path,
	name: &str,
	has_attribute: impl Fn(&ItemFn) -> bool,
	label: &str,
	allow_proptest: bool,
	findings: &mut Findings,
) {
	let Some(contents) = artifact_text(root, file, findings) else {
		return;
	};
	let Ok(syntax) = syn::parse_file(&contents) else {
		return;
	};
	let leaf_name = name.rsplit("::").next().unwrap_or_default();
	if !find_function(&syntax.items, leaf_name, &has_attribute, allow_proptest) {
		findings.add(
			&root.join(file),
			format_args!("expected {label} function {name}"),
		);
	}
}

fn find_function(
	items: &[Item],
	name: &str,
	has_attribute: &impl Fn(&ItemFn) -> bool,
	allow_proptest: bool,
) -> bool {
	items.iter().any(|item| match item {
		Item::Fn(function) => {
			function.sig.ident == name
				&& !function.block.stmts.is_empty()
				&& has_attribute(function)
		}
		Item::Mod(module) => module
			.content
			.as_ref()
			.is_some_and(|(_, items)| find_function(items, name, has_attribute, allow_proptest)),
		Item::Macro(item)
			if allow_proptest
				&& item
					.mac
					.path
					.segments
					.last()
					.is_some_and(|segment| segment.ident == "proptest") =>
		{
			let parser = |input: ParseStream<'_>| parse_proptest(input, name);
			parser.parse2(item.mac.tokens.clone()).unwrap_or_default()
		}
		_ => false,
	})
}

fn parse_proptest(input: ParseStream<'_>, name: &str) -> syn::Result<bool> {
	let _ = input.call(Attribute::parse_inner)?;
	let mut matching = false;
	while !input.is_empty() {
		let attrs = input.call(Attribute::parse_outer)?;
		input.parse::<syn::Token![fn]>()?;
		let ident = input.parse::<syn::Ident>()?;
		let args;
		syn::parenthesized!(args in input);
		args.parse::<proc_macro2::TokenStream>()?;
		let body = input.parse::<syn::Block>()?;
		matching |= ident == name
			&& !body.stmts.is_empty()
			&& attrs.iter().any(|attr| attr.path().is_ident("test"))
			&& attrs.iter().all(|attr| !attr.path().is_ident("ignore"));
	}
	Ok(matching)
}

pub(super) fn check_lean(root: &Path, link: &LeanLink, findings: &mut Findings) {
	for config in [
		"verification/lakefile.toml",
		"verification/lake-manifest.json",
		"verification/lean-toolchain",
	] {
		artifact_text(root, Path::new(config), findings);
	}
	for (file, directory) in [(&link.proof, PROOFS), (&link.generated, GENERATED)] {
		if !location(root, file, directory, "lean", findings) {
			continue;
		}
		let Some(contents) = artifact_text(root, file, findings) else {
			continue;
		};
		let tokens = lean_tokens(&contents);
		if tokens
			.iter()
			.any(|word| matches!(*word, "sorry" | "admit" | "axiom" | "sorryAx"))
		{
			findings.add(&root.join(file), "Lean includes a proof hole or new axiom");
		}
		if directory == PROOFS {
			let theorem = link.theorem.rsplit('.').next().unwrap_or_default();
			if !tokens
				.windows(2)
				.any(|pair| matches!(pair, ["theorem" | "lemma", name] if *name == theorem))
			{
				findings.add(
					&root.join(file),
					format_args!("missing Lean theorem {}", link.theorem),
				);
			}
		}
	}
}

fn lean_tokens(mut source: &str) -> Vec<&str> {
	let mut words = Vec::new();
	while !source.is_empty() {
		if let Some(comment) = source.strip_prefix("--") {
			source = comment.split_once('\n').map_or("", |(_, rest)| rest);
		} else if let Some(comment) = source.strip_prefix("/-") {
			source = after_lean_comment(comment);
		} else if let Some(string) = source.strip_prefix('"') {
			let mut escaped = false;
			source = string
				.char_indices()
				.find_map(|(index, ch)| {
					let end = ch == '"' && !escaped;
					escaped = ch == '\\' && !escaped;
					end.then(|| &string[index + 1..])
				})
				.unwrap_or_default();
		} else {
			let length = source
				.find(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
				.unwrap_or(source.len());
			if length > 0 {
				words.push(&source[..length]);
				source = &source[length..];
			} else if let Some(ch) = source.chars().next() {
				source = &source[ch.len_utf8()..];
			}
		}
	}
	words
}

fn after_lean_comment(mut source: &str) -> &str {
	let mut depth = 1_usize;
	while let Some(index) = source.find(['/', '-']) {
		let candidate = &source[index..];
		if let Some(remainder) = candidate.strip_prefix("/-") {
			depth += 1;
			source = remainder;
		} else if let Some(remainder) = candidate.strip_prefix("-/") {
			depth -= 1;
			if depth == 0 {
				return remainder;
			}
			source = remainder;
		} else {
			source = &candidate[1..];
		}
	}
	""
}

pub(super) fn check_tlc(root: &Path, link: &TlcLink, findings: &mut Findings) {
	let paths = [
		(&link.spec, "tla"),
		(&link.config, "cfg"),
		(&link.negative_control, "cfg"),
	];
	let [Some(spec), Some(positive), Some(negative)] = paths.map(|(file, ext)| {
		location(root, file, TLA, ext, findings)
			.then(|| artifact_text(root, file, findings))
			.flatten()
	}) else {
		return;
	};
	if !spec
		.lines()
		.any(|line| line.split_whitespace().any(|word| word == "MODULE"))
	{
		findings.add(&root.join(&link.spec), "expected a TLA+ module");
	}
	for (config, contents) in [
		(&link.config, &positive),
		(&link.negative_control, &negative),
	] {
		if !contents.lines().any(|line| {
			matches!(
				line.split_whitespace().next(),
				Some("INVARIANT" | "INVARIANTS")
			)
		}) {
			findings.add(
				&root.join(config),
				"TLC config must check a safety invariant",
			);
		}
	}
	if positive.trim() == negative.trim() {
		findings.add(
			&root.join(&link.negative_control),
			"TLC control and negative control must differ",
		);
	}
}

fn location(
	root: &Path,
	file: &Path,
	directory: &str,
	extension: &str,
	findings: &mut Findings,
) -> bool {
	if file.starts_with(directory) && file.extension() == Some(OsStr::new(extension)) {
		return true;
	}
	findings.add(
		&root.join(file),
		format_args!("expected a .{extension} file under {directory}/"),
	);
	false
}
