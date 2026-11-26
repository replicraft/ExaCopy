//! A small kernel oracle whose object labels are invisible to policy.

use super::{
	NameObservation, NamespaceObservation, RecoveryObservation, RecoveryReadback, held, intent,
	live, names, observe_recovery,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Object {
	Original,
	External,
}

#[derive(Clone, Copy)]
enum Name {
	Stage = 0,
	Witness = 1,
	Target = 2,
}

#[derive(Clone, Copy)]
struct Kernel {
	links: [Option<usize>; 3],
	open: [Option<usize>; 3],
	origins: [Option<Object>; 2],
}

impl Kernel {
	const fn new() -> Self {
		Self {
			links: [Some(0), None, None],
			open: [Some(0), None, None],
			origins: [Some(Object::Original), None],
		}
	}

	const fn link_witness(&mut self) {
		assert!(self.links[1].is_none());
		self.links[1] = self.links[0];
	}

	fn rename_no_replace(&mut self) -> bool {
		if self.links[2].is_some() {
			return false;
		}
		self.links[2] = self.links[0].take();
		true
	}

	const fn crash(&mut self) {
		self.open = [None; 3];
	}

	fn open(&mut self, name: Name) {
		self.open[name as usize] = self.links[name as usize];
	}

	fn allocate_target(&mut self) -> Option<usize> {
		assert!(self.links[2].is_none());
		let slot = (0..self.origins.len())
			.find(|slot| !self.links.contains(&Some(*slot)) && !self.open.contains(&Some(*slot)))?;
		self.origins[slot] = Some(Object::External);
		self.links[2] = Some(slot);
		Some(slot)
	}

	fn observation(self) -> NamespaceObservation {
		let observe = |name: usize| match (self.links[name], self.open[name]) {
			(None, _) => NameObservation::Absent,
			(Some(named), Some(fd)) if named == fd => held(
				u64::try_from(fd + 1).unwrap(),
				u64::try_from(self.links.iter().filter(|slot| **slot == Some(fd)).count()).unwrap(),
			),
			_ => NameObservation::Uncertain,
		};
		names(live(7), observe(0), observe(1), observe(2))
	}
}

#[test]
fn external_replacement_cannot_reuse_witnessed_inode_even_when_open_refs_die() {
	let mut kernel = Kernel::new();
	kernel.link_witness();
	assert!(kernel.rename_no_replace());
	kernel.crash();
	kernel.open(Name::Witness);
	kernel.open(Name::Target);
	assert!(matches!(
		observe_recovery(
			&intent(),
			live(7),
			kernel.observation(),
			RecoveryReadback::Complete
		),
		RecoveryObservation::Recovered(_)
	));
	kernel.links[2] = None;
	assert_eq!(
		observe_recovery(
			&intent(),
			live(7),
			kernel.observation(),
			RecoveryReadback::Complete
		),
		RecoveryObservation::Reconcile
	);

	// Both descriptor refs close, but the protected witness still pins slot zero.
	kernel.crash();
	assert_eq!(kernel.allocate_target(), Some(1));
	kernel.open(Name::Witness);
	kernel.open(Name::Target);
	assert_eq!(kernel.origins[0], Some(Object::Original));
	assert_eq!(
		observe_recovery(
			&intent(),
			live(7),
			kernel.observation(),
			RecoveryReadback::Complete
		),
		RecoveryObservation::Reconcile
	);
}

#[test]
fn unlinked_open_ref_and_incumbent_survive_conflict_until_ordinary_release() {
	let mut kernel = Kernel::new();
	kernel.link_witness();
	assert_eq!(kernel.allocate_target(), Some(1));
	kernel.open(Name::Target);
	assert!(!kernel.rename_no_replace());
	kernel.open(Name::Stage);
	kernel.open(Name::Witness);
	assert_eq!(kernel.links, [Some(0), Some(0), Some(1)]);
	assert_eq!(
		observe_recovery(
			&intent(),
			live(7),
			kernel.observation(),
			RecoveryReadback::Complete
		),
		RecoveryObservation::Reconcile
	);
	kernel.links[2] = None;
	assert_eq!(kernel.allocate_target(), None);
	kernel.crash();
	assert_eq!(kernel.allocate_target(), Some(1));
}
