use std::collections::{BTreeMap, BTreeSet};

pub(super) type Graph<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;

pub(super) fn dependency_cycle<'a>(graph: &Graph<'a>) -> Option<Vec<&'a str>> {
	let mut visited = BTreeSet::new();
	let mut ancestors = Vec::new();
	graph
		.keys()
		.find_map(|name| visit(name, graph, &mut visited, &mut ancestors))
}

fn visit<'a>(
	name: &'a str,
	graph: &Graph<'a>,
	visited: &mut BTreeSet<&'a str>,
	ancestors: &mut Vec<&'a str>,
) -> Option<Vec<&'a str>> {
	if !visited.insert(name) {
		let start = ancestors.iter().position(|&ancestor| ancestor == name)?;
		let mut cycle = ancestors[start..].to_vec();
		cycle.push(name);
		return Some(cycle);
	}
	ancestors.push(name);
	if let Some(cycle) = graph
		.get(name)
		.into_iter()
		.flatten()
		.find_map(|dependency| visit(dependency, graph, visited, ancestors))
	{
		return Some(cycle);
	}
	ancestors.pop();
	None
}
