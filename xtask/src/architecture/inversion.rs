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
	Transport,
	Application,
}

impl Role {
	pub(super) fn at(directory: &Path) -> Self {
		if directory.starts_with("crates/engines") || directory.starts_with("crates/runtime") {
			Self::Engine
		} else if directory.starts_with("crates/net") {
			Self::Transport
		} else if directory.starts_with("crates/platform")
			|| directory.starts_with("crates/adapters")
		{
			Self::Adapter
		} else if directory.starts_with("apps") {
			Self::Application
		} else {
			Self::Shared
		}
	}

	fn is_composition_target(self) -> bool {
		matches!(self, Self::Adapter | Self::Transport | Self::Application)
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
	concrete_external: BTreeSet<String>,
	#[serde(default)]
	adapter_transport: Vec<AdapterTransport>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterTransport {
	from: String,
	to: String,
}

pub(super) struct Check<'a> {
	packages: &'a BTreeMap<&'a str, &'a Package>,
	roles: BTreeMap<&'a str, Role>,
	policy: &'a Policy,
	adapter_transport: BTreeMap<(&'a str, &'a str), bool>,
	runtime: Graph<'a>,
	development: Graph<'a>,
}

impl<'a> Check<'a> {
	pub(super) fn new(
		root: &Path,
		packages: &'a BTreeMap<&'a str, &'a Package>,
		policy: &'a Policy,
		matrix: &Path,
		findings: &mut Findings,
	) -> Self {
		let roles: BTreeMap<_, _> = packages
			.iter()
			.filter_map(|(&name, package)| {
				let directory = package.manifest_path.as_std_path().parent()?;
				Some((name, Role::at(directory.strip_prefix(root).ok()?)))
			})
			.collect();
		let mut adapter_transport = BTreeMap::new();
		for edge in &policy.adapter_transport {
			let pair = (edge.from.as_str(), edge.to.as_str());
			let member_in = |name: &str, group: &str| {
				packages.get(name).is_some_and(|package| {
					package.manifest_path.as_std_path().parent()
						== Some(root.join(group).join(name).as_path())
				})
			};
			if !member_in(pair.0, "crates/adapters") || !member_in(pair.1, "crates/net") {
				findings.add(
					matrix,
					format_args!(
						"invalid adapter-to-transport allowance {} -> {}",
						pair.0, pair.1
					),
				);
			} else if adapter_transport.insert(pair, false).is_some() {
				findings.add(
					matrix,
					format_args!(
						"duplicate adapter-to-transport allowance {} -> {}",
						pair.0, pair.1
					),
				);
			}
		}
		Self {
			packages,
			roles,
			policy,
			adapter_transport,
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
		let may_compose = match (from_role, to_role, workspace, dependency.kind) {
			(Role::Application, Role::Adapter | Role::Transport, _, _) => true,
			(Role::Adapter | Role::Transport, Role::Adapter, false, _) => true,
			(Role::Adapter, Role::Transport, true, DependencyKind::Normal) => {
				if let Some(used) = self.adapter_transport.get_mut(&(from, to)) {
					*used = true;
					true
				} else {
					false
				}
			}
			_ => false,
		};
		let infrastructure_reaches_workflow = matches!(from_role, Role::Adapter | Role::Transport)
			&& to_role == Role::Engine
			&& dependency.kind != DependencyKind::Development;
		if (to_role.is_composition_target() && !may_compose) || infrastructure_reaches_workflow {
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

	pub(super) fn check(&self, matrix: &Path, findings: &mut Findings) {
		for (&(from, to), &used) in &self.adapter_transport {
			if !used {
				findings.add(
					matrix,
					format_args!("unused adapter-to-transport allowance {from} -> {to}"),
				);
			}
		}
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

	pub(super) fn is_workspace_composition(&self, dependency: &str) -> bool {
		self.roles
			.get(dependency)
			.is_some_and(|role| role.is_composition_target())
	}

	fn is_composition_dependency(&self, dependency: &str) -> bool {
		self.is_workspace_composition(dependency)
			|| self.policy.concrete_external.contains(dependency)
	}
}
