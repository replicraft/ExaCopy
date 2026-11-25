use std::path::Path;

use syn::spanned::Spanned;
use syn::{Expr, Item, Stmt, Visibility};

use crate::finding::Findings;

pub(super) fn check_declarations(path: &Path, file: &syn::File, findings: &mut Findings) {
	for item in &file.items {
		let is_declaration = match item {
			Item::Mod(module) => module.content.is_none(),
			Item::Use(import) => !matches!(import.vis, Visibility::Inherited),
			Item::ExternCrate(_) => true,
			_ => false,
		};
		if !is_declaration {
			findings.at_line(
				path,
				item.span().start().line,
				"lib.rs and mod.rs allow only external module declarations and explicit re-exports",
			);
		}
	}
}

pub(super) fn check_main(path: &Path, file: &syn::File, findings: &mut Findings) {
	let mut main_count = 0;
	for item in &file.items {
		match item {
			Item::Fn(function) if function.sig.ident == "main" => {
				main_count += 1;
				check_main_body(path, function, findings);
			}
			Item::Mod(module) if module.content.is_none() => (),
			Item::Use(_) | Item::ExternCrate(_) => (),
			_ => findings.at_line(
				path,
				item.span().start().line,
				"main.rs may declare modules and imports, and define only main",
			),
		}
	}
	if main_count != 1 {
		findings.add(
			path,
			"main.rs must contain one main that delegates to application code",
		);
	}
}

fn check_main_body(path: &Path, main: &syn::ItemFn, findings: &mut Findings) {
	for statement in &main.block.stmts {
		let allowed = match statement {
			Stmt::Local(local) => local.init.as_ref().is_some_and(|init| {
				init.diverge.is_none()
					&& matches!(local.pat, syn::Pat::Ident(_) | syn::Pat::Type(_))
					&& is_wiring(&init.expr)
			}),
			Stmt::Expr(expression, _) => is_wiring(expression),
			Stmt::Item(_) | Stmt::Macro(_) => false,
		};
		if !allowed {
			findings.at_line(
				path,
				statement.span().start().line,
				"main.rs may initialize and delegate using straight-line calls and assignments",
			);
		}
	}
	if !matches!(main.block.stmts.last(), Some(Stmt::Expr(expr, _)) if has_call(expr)) {
		findings.add(
			path,
			"main must end with a call that delegates or maps process exit",
		);
	}
}

fn is_wiring(expression: &Expr) -> bool {
	match expression {
		Expr::Call(call) => matches!(&*call.func, Expr::Path(_)) && call.args.iter().all(is_wiring),
		Expr::MethodCall(call) => is_wiring(&call.receiver) && call.args.iter().all(is_wiring),
		Expr::Path(_) | Expr::Lit(_) => true,
		Expr::Paren(paren) => is_wiring(&paren.expr),
		Expr::Field(field) => is_wiring(&field.base),
		Expr::Reference(reference) => is_wiring(&reference.expr),
		Expr::Try(attempt) => is_wiring(&attempt.expr),
		Expr::Await(awaited) => is_wiring(&awaited.base),
		Expr::Return(ret) => ret.expr.as_deref().is_some_and(is_wiring),
		Expr::Array(array) => array.elems.iter().all(is_wiring),
		Expr::Tuple(tuple) => tuple.elems.iter().all(is_wiring),
		Expr::Struct(structure) => {
			structure.fields.iter().all(|field| is_wiring(&field.expr))
				&& structure.rest.as_deref().is_none_or(is_wiring)
		}
		_ => false,
	}
}

fn has_call(expression: &Expr) -> bool {
	match expression {
		Expr::Call(_) | Expr::MethodCall(_) => true,
		Expr::Paren(paren) => has_call(&paren.expr),
		Expr::Try(attempt) => has_call(&attempt.expr),
		Expr::Await(awaited) => has_call(&awaited.base),
		Expr::Return(ret) => ret.expr.as_deref().is_some_and(has_call),
		_ => false,
	}
}
