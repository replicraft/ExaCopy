use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use cargo_metadata::{Dependency, DependencyKind, Package};
use serde::Deserialize;

use super::graph::Graph;
use crate::finding::Findings;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Role {
	#[default]
	Shared,
	Engine,
	Adapter,
	Application,
}

impl Role {
	pub(super) fn at(directory: &Path) -> Self {
		if directory.starts_with("crates/engines") || directory.starts_with("crates/runtime") {
			Self::Engine
		} else if ["crates/net", "crates/platform", "crates/adapters"]
			.iter()
			.any(|role| directory.starts_with(role))
		{
			Self::Adapter
		} else if directory.starts_with("apps") {
			Self::Application
		} else {
			Self::Shared
		}
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
	concrete_external: BTreeSet<String>,
}

pub(super) struct Check<'a> {
	packages: &'a BTreeMap<&'a str, &'a Package>,
	roles: BTreeMap<&'a str, Role>,
	policy: &'a Policy,
	runtime: Graph<'a>,
	development: Graph<'a>,
}

impl<'a> Check<'a> {
	pub(super) fn new(
		root: &Path,
		packages: &'a BTreeMap<&'a str, &'a Package>,
		policy: &'a Policy,
	) -> Self {
		let roles = packages
			.iter()
			.filter_map(|(&name, package)| {
				let directory = package.manifest_path.as_std_path().parent()?;
				Some((name, Role::at(directory.strip_prefix(root).ok()?)))
			})
			.collect();
		Self {
			packages,
			roles,
			policy,
			runtime: Graph::new(),
			development: Graph::new(),
		}
	}

	pub(super) fn edge(
		&mut self,
		from: &'a str,
		manifest: &Path,
		dependency: &'a Dependency,
		workspace: bool,
		findings: &mut Findings,
	) {
		let to = dependency.name.as_str();
		let from_role = self.roles.get(from).copied().unwrap_or_default();
		let to_role = match workspace {
			true => self.roles.get(to).copied().unwrap_or_default(),
			false if self.policy.concrete_external.contains(to) => Role::Adapter,
			false => return,
		};
		let from_may_compose = to_role == Role::Adapter
			&& (from_role == Role::Application || !workspace && from_role == Role::Adapter);
		if matches!(to_role, Role::Adapter | Role::Application) && !from_may_compose {
			findings.add(
				manifest,
				format_args!(
					"composition boundary forbids {} dependency {from} -> {to}",
					dependency.kind
				),
			);
		}
		let graph = match dependency.kind {
			DependencyKind::Development => &mut self.development,
			_ => &mut self.runtime,
		};
		graph.entry(from).or_default().insert(to);
	}

	pub(super) fn check(&self, findings: &mut Findings) {
		for (&engine, _) in self.roles.iter().filter(|(_, role)| **role == Role::Engine) {
			let mut visited = BTreeSet::from([engine]);
			let mut pending = VecDeque::from([vec![engine]]);
			while let Some(path) = pending.pop_front() {
				let Some(&name) = path.last() else { continue };
				let children = self.runtime.get(name).into_iter().flatten();
				let direct_dev = self
					.development
					.get(name)
					.filter(|_| name == engine)
					.into_iter()
					.flatten();
				for &dependency in children.chain(direct_dev) {
					if !visited.insert(dependency) {
						continue;
					}
					let mut next = path.clone();
					next.push(dependency);
					if self.is_composition_dependency(dependency) {
						findings.add(
							self.packages[engine].manifest_path.as_std_path(),
							format_args!(
								"engine dependency reaches concrete implementation or composition: {}",
								next.join(" -> ")
							),
						);
					} else {
						pending.push_back(next);
					}
				}
			}
		}
	}

	fn is_composition_dependency(&self, dependency: &str) -> bool {
		matches!(
			self.roles.get(dependency),
			Some(Role::Adapter | Role::Application)
		) || self.policy.concrete_external.contains(dependency)
	}
}
