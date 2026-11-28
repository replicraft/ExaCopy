use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use cargo_metadata::{Dependency, DependencyKind, Metadata};
use serde::Deserialize;

use crate::finding::Findings;

mod graph;
mod inversion;
mod placement;

const MATRIX_PATH: &str = "specs/architecture/dependencies.toml";
const SCHEMA_VERSION: u32 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
	schema_version: u32,
	inversion: inversion::Policy,
	groups: BTreeMap<String, Group>,
	#[serde(default)]
	transitional_normal: Vec<Transition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
	members: BTreeMap<String, PathBuf>,
	#[serde(default)]
	role: inversion::Role,
	#[serde(default)]
	engineering: bool,
	#[serde(default)]
	normal: Allowances,
	#[serde(default)]
	build: Allowances,
	#[serde(default)]
	dev: Allowances,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowances {
	#[serde(default)]
	groups: BTreeSet<String>,
	#[serde(default)]
	external: BTreeSet<String>,
	#[serde(default)]
	optional_external: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
	from: String,
	to: String,
	targets: BTreeSet<String>,
}

struct Member<'matrix> {
	group_name: &'matrix str,
	group: &'matrix Group,
	directory: &'matrix Path,
}

pub(crate) fn check(metadata: &Metadata, findings: &mut Findings) -> BTreeSet<String> {
	let root = metadata.workspace_root.as_std_path();
	let path = root.join(MATRIX_PATH);
	let contents = match fs::read_to_string(&path) {
		Ok(contents) => contents,
		Err(error) => {
			findings.add(&path, error);
			return BTreeSet::new();
		}
	};
	let matrix: Matrix = match toml::from_str(&contents) {
		Ok(matrix) => matrix,
		Err(error) => {
			findings.add(&path, error);
			return BTreeSet::new();
		}
	};
	if matrix.schema_version != SCHEMA_VERSION {
		findings.add(
			&path,
			format_args!(
				"unsupported architecture matrix schema version {}",
				matrix.schema_version
			),
		);
		return BTreeSet::new();
	}
	let members = matrix.members(&path, findings);
	check_workspace(root, &path, metadata, &matrix, &members, findings);
	members
		.into_iter()
		.filter(|(_, member)| member.group.engineering)
		.map(|(name, _)| name.to_owned())
		.collect()
}

impl Matrix {
	fn members<'matrix>(
		&'matrix self,
		path: &Path,
		findings: &mut Findings,
	) -> BTreeMap<&'matrix str, Member<'matrix>> {
		let mut members = BTreeMap::new();
		let mut directories = BTreeSet::new();
		for (group_name, group) in &self.groups {
			for allowed in [&group.normal, &group.build, &group.dev] {
				for target in &allowed.groups {
					if !self.groups.contains_key(target) {
						findings.add(
							path,
							format_args!("group {group_name} references unknown group {target}"),
						);
					}
				}
			}
			for (name, directory) in &group.members {
				if directory.as_os_str().is_empty()
					|| !directory
						.components()
						.all(|part| matches!(part, Component::Normal(_)))
				{
					findings.add(
						path,
						format_args!(
							"architecture directory for {name} must be relative and traversals are forbidden"
						),
					);
				}
				let engineering_directory =
					directory == Path::new("xtask") || directory.starts_with("crates/engineering");
				if group.engineering != engineering_directory {
					findings.add(
						path,
						format_args!("{name} has an engineering role and directory mismatch"),
					);
				}
				if group.role != inversion::Role::at(directory) {
					findings.add(
						path,
						format_args!("{name} has an inversion role and directory mismatch"),
					);
				}
				if !directories.insert(directory) {
					findings.add(
						path,
						format_args!("duplicate architecture directory {}", directory.display()),
					);
				}
				let member = Member {
					group_name,
					group,
					directory,
				};
				if members.insert(name.as_str(), member).is_some() {
					findings.add(path, format_args!("{name} belongs to multiple groups"));
				}
			}
		}
		members
	}
}

fn check_workspace(
	root: &Path,
	path: &Path,
	metadata: &Metadata,
	matrix: &Matrix,
	members: &BTreeMap<&str, Member<'_>>,
	findings: &mut Findings,
) {
	let workspace = metadata
		.workspace_packages()
		.into_iter()
		.map(|package| (package.name.as_str(), package))
		.collect::<BTreeMap<_, _>>();
	let mut transitions = matrix
		.transitional_normal
		.iter()
		.flat_map(|entry| {
			entry.targets.iter().map(|target| {
				(
					(entry.from.as_str(), entry.to.as_str(), target.as_str()),
					false,
				)
			})
		})
		.collect::<BTreeMap<_, _>>();
	if matrix
		.transitional_normal
		.iter()
		.any(|entry| entry.targets.is_empty())
	{
		findings.add(
			path,
			"transitional allowances must name specific Cargo targets",
		);
	}
	for name in members.keys() {
		if !workspace.contains_key(name) {
			findings.add(
				path,
				format_args!("architecture member {name} is absent from the workspace"),
			);
		}
	}
	let mut graph = graph::Graph::new();
	let mut inversion = inversion::Check::new(root, &workspace, &matrix.inversion, path, findings);
	for (&name, package) in &workspace {
		let manifest = package.manifest_path.as_std_path();
		placement::check(root, package, findings);
		let Some(member) = members.get(name) else {
			findings.add(manifest, format_args!("{name} has no architectural group"));
			continue;
		};
		if manifest.parent() != Some(root.join(member.directory).as_path()) {
			findings.add(
				manifest,
				format_args!("{name} must live at {}", member.directory.display()),
			);
		}
		for dependency in &package.dependencies {
			let to = dependency.name.as_str();
			let target = dependency.target.as_ref().map(ToString::to_string);
			let target_member = workspace.get(to).filter(|target_package| {
				dependency
					.path
					.as_ref()
					.is_some_and(|path| target_package.manifest_path.parent() == Some(path))
			});
			inversion.edge(
				name,
				manifest,
				dependency,
				target_member.is_some(),
				findings,
			);
			let allowed = if target_member.is_some() {
				graph.entry(name).or_default().insert(to);
				members.get(to).is_some_and(|target_member| {
					if member.allows_internal(dependency.kind, target_member) {
						return true;
					}
					if dependency.kind == DependencyKind::Normal
						&& !target_member.group.engineering
						&& !inversion.is_workspace_composition(to)
						&& let Some((_, used)) =
							transitions.iter_mut().find(|((from, to, cfg), _)| {
								(*from, *to, Some(*cfg))
									== (name, dependency.name.as_str(), target.as_deref())
							}) {
						*used = true;
						return true;
					}
					false
				})
			} else {
				let allowed_source = match to {
					"apfs-mounted" => {
						allowed_apfs_sibling(root, name, dependency, target.as_deref())
					}
					"boringtun" | "russh" => allowed_transport_sibling(root, name, dependency),
					_ => dependency.path.is_none(),
				};
				allowed_source && !workspace.contains_key(to) && member.allows_external(dependency)
			};
			if !allowed {
				let kind = dependency.kind;
				let target = target.as_deref().unwrap_or("all targets");
				findings.add(
					manifest,
					format_args!(
						"architecture forbids {kind} dependency {name} -> {to} ({target})"
					),
				);
			}
		}
	}
	inversion.check(path, findings);
	for ((from, to, target), used) in transitions {
		if !used {
			findings.add(
				path,
				format_args!("unused transitional allowance {from} -> {to} ({target})"),
			);
		}
	}
	if let Some(cycle) = graph::dependency_cycle(&graph) {
		findings.add(
			path,
			format_args!("workspace dependency cycle: {}", cycle.join(" -> ")),
		);
	}
}

impl Member<'_> {
	fn allowances(&self, kind: DependencyKind) -> Option<&Allowances> {
		match kind {
			DependencyKind::Normal => Some(&self.group.normal),
			DependencyKind::Build => Some(&self.group.build),
			DependencyKind::Development => Some(&self.group.dev),
			DependencyKind::Unknown => None,
		}
	}

	fn allows_internal(&self, kind: DependencyKind, other: &Member<'_>) -> bool {
		if !self.group.engineering && other.group.engineering && kind != DependencyKind::Development
		{
			return false;
		}
		self.allowances(kind)
			.is_some_and(|rules| rules.groups.contains(other.group_name))
	}

	fn allows_external(&self, dependency: &Dependency) -> bool {
		self.allowances(dependency.kind).is_some_and(|rules| {
			rules.external.contains(&dependency.name)
				|| dependency.optional && rules.optional_external.contains(&dependency.name)
		})
	}
}

#[cfg(test)]
mod tests;

fn allowed_apfs_sibling(
	root: &Path,
	consumer: &str,
	dependency: &Dependency,
	target: Option<&str>,
) -> bool {
	if consumer != "exacopy-platform"
		|| dependency.name != "apfs-mounted"
		|| dependency.source.is_some()
		|| dependency.kind != DependencyKind::Normal
		|| dependency.optional
		|| dependency.uses_default_features
		|| !dependency.features.is_empty()
		|| target != Some(r#"cfg(target_os = "macos")"#)
	{
		return false;
	}
	let Some(path) = dependency.path.as_ref() else {
		return false;
	};
	root.join("../pomologie/apfs/crates/platform/apfs-mounted")
		.canonicalize()
		.is_ok_and(|expected| {
			path.as_std_path()
				.canonicalize()
				.is_ok_and(|actual| actual == expected)
		})
}

fn allowed_transport_sibling(root: &Path, consumer: &str, dependency: &Dependency) -> bool {
	const UNIX_FIXTURES: &str = r#"cfg(any(target_os = "linux", target_os = "macos"))"#;
	const WINDOWS_FIXTURE: &str = r#"cfg(target_os = "windows")"#;
	let target = dependency.target.as_ref().map(ToString::to_string);
	let (version, features, optional): (&str, &[&str], bool) = match (
		dependency.name.as_str(),
		consumer,
		dependency.kind,
		target.as_deref(),
	) {
		("boringtun", "exacopy-wireguard", DependencyKind::Normal, None) => ("=0.7.1", &[], true),
		("russh", "exacopy-ssh", DependencyKind::Normal, None) => ("=0.65.4", &["ring"], true),
		(
			"russh",
			"exacopy-cli" | "exacopy-sftp",
			DependencyKind::Development,
			Some(UNIX_FIXTURES | WINDOWS_FIXTURE),
		) => ("=0.65.4", &["ring"], false),
		_ => return false,
	};
	if dependency.req.to_string() != version
		|| dependency.source.is_some()
		|| dependency.rename.is_some()
		|| dependency.optional != optional
		|| dependency.uses_default_features
		|| dependency
			.features
			.iter()
			.map(String::as_str)
			.ne(features.iter().copied())
	{
		return false;
	}
	let Some(path) = dependency.path.as_ref() else {
		return false;
	};
	root.join("../local-deps")
		.join(&dependency.name)
		.canonicalize()
		.is_ok_and(|expected| {
			path.as_std_path()
				.canonicalize()
				.is_ok_and(|actual| actual == expected)
		})
}
