use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::plan_bundle::PlanBundleSink;

use super::super::{LinuxPlanBundle, PlanInputDirectory};
use super::{Directory, Mode, MountObservations, PlanBundleError, ancestry, check_protected};
use crate::scratch::Scratch;

const PLAN_NAME: &str = "plan.json";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

fn private_directory(path: PathBuf) -> PathBuf {
	DirBuilder::new()
		.mode(PRIVATE_DIRECTORY_MODE)
		.create(&path)
		.expect("create private fixture directory");
	path
}

fn input(path: &Path) -> PlanInputDirectory {
	PlanInputDirectory::open(path.as_os_str()).expect("hold fixture input directory")
}

fn assert_bundle_absent(directory: &Path) {
	for name in ["pages", PLAN_NAME] {
		let path = directory.join(name);
		let error = fs::symlink_metadata(&path).expect_err("bundle artifact must be absent");
		assert_eq!(error.kind(), ErrorKind::NotFound, "checking {path:?}");
	}
}

#[test]
fn bundle_refuses_overlap_with_any_held_input_role() {
	let scratch = Scratch::new();
	let bundle_path = private_directory(scratch.path("bundle"));
	let nested = private_directory(bundle_path.join("nested"));
	let sibling_paths =
		["source", "destination", "profile"].map(|role| private_directory(scratch.path(role)));
	let siblings = sibling_paths.each_ref().map(|path| input(path));
	let output = UnixComponent::new(PLAN_NAME.as_bytes()).expect("valid test basename");

	let admitted = LinuxPlanBundle::open(bundle_path.as_os_str(), output, siblings.each_ref())
		.expect("sibling input directories are disjoint");
	admitted
		.check_scope()
		.expect("the initially admitted scope remains live");

	let overlaps = [scratch.path("."), bundle_path.clone(), nested];
	for path in &overlaps {
		fs::write(path.join("protected.bin"), b"protected bytes").expect("create fixture sentinel");
	}
	for path in &overlaps {
		let held = input(path);
		let protected_file = path.join("protected.bin");
		let before = fs::metadata(&protected_file).expect("observe fixture identity");
		for role in 0..siblings.len() {
			let mut protected = siblings.each_ref();
			protected[role] = &held;
			assert!(
				matches!(
					LinuxPlanBundle::open(bundle_path.as_os_str(), output, protected),
					Err(PlanBundleError::Scope(None))
				),
				"overlap with protected role {role} at {path:?} must be refused"
			);
			assert_bundle_absent(&bundle_path);
			let after =
				fs::metadata(&protected_file).expect("protected fixture file remains named");
			assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
			assert_eq!(
				fs::read(&protected_file).expect("read preserved fixture bytes"),
				b"protected bytes".as_slice(),
			);
		}
	}
}

#[test]
fn scope_recheck_uses_the_live_parent_of_a_held_input() {
	let scratch = Scratch::new();
	let bundle_path = private_directory(scratch.path("bundle"));
	let source = private_directory(scratch.path("source"));
	let destination = private_directory(scratch.path("destination"));
	let profile = private_directory(scratch.path("profile"));
	let held = [input(&source), input(&destination), input(&profile)];
	let output = UnixComponent::new(PLAN_NAME.as_bytes()).expect("valid test basename");
	let bundle = LinuxPlanBundle::open(bundle_path.as_os_str(), output, held.each_ref())
		.expect("admit the initially disjoint bundle");
	let source_file = source.join("source.bin");
	fs::write(&source_file, b"source bytes").expect("create fixture source");
	let before = fs::metadata(&source_file).expect("observe source identity");

	let moved_source = bundle_path.join("moved-source");
	fs::rename(&source, &moved_source).expect("move the held source beneath the bundle");
	let _replacement = private_directory(source);

	assert!(
		matches!(bundle.check_scope(), Err(PlanBundleError::Scope(None))),
		"the original path now names a disjoint directory, but the held source overlaps"
	);
	assert_bundle_absent(&bundle_path);
	let moved_file = moved_source.join("source.bin");
	let after = fs::metadata(&moved_file).expect("source remains named under its new parent");
	assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
	assert_eq!(
		fs::read(moved_file).expect("read preserved source bytes"),
		b"source bytes".as_slice(),
	);
}

#[test]
fn writable_bundle_ancestor_requires_sticky_protection() {
	let scratch = Scratch::new();
	let ancestor = private_directory(scratch.path("ancestor"));
	let bundle_path = private_directory(ancestor.join("bundle"));
	let sibling_paths =
		["source", "destination", "profile"].map(|role| private_directory(scratch.path(role)));
	let held = sibling_paths.each_ref().map(|path| input(path));
	let output = UnixComponent::new(PLAN_NAME.as_bytes()).expect("valid test basename");

	const STICKY: u32 = 0o1000;
	const GROUP_WRITABLE: u32 = 0o770;
	const OTHER_WRITABLE: u32 = 0o707;
	for writable in [GROUP_WRITABLE, OTHER_WRITABLE] {
		fs::set_permissions(&ancestor, fs::Permissions::from_mode(writable))
			.expect("make fixture ancestor writable");
		assert!(
			matches!(
				LinuxPlanBundle::open(bundle_path.as_os_str(), output, held.each_ref()),
				Err(PlanBundleError::Unsafe(None))
			),
			"non-sticky ancestor with mode {writable:o} must be refused"
		);
		assert_bundle_absent(&bundle_path);
		fs::set_permissions(&ancestor, fs::Permissions::from_mode(writable | STICKY))
			.expect("add sticky protection to fixture ancestor");
		LinuxPlanBundle::open(bundle_path.as_os_str(), output, held.each_ref())
			.expect("admit a sticky writable ancestor inside the private fixture");
	}
}

#[test]
fn foreign_owner_is_refused_even_with_sticky_protection() {
	let observed = Directory {
		key: (0, 0),
		mount: 0,
		mode: Mode::WGRP | Mode::SVTX,
		owner: if rustix::process::geteuid().as_raw() == 1 {
			2
		} else {
			1
		},
	};

	assert!(
		matches!(
			check_protected(observed),
			Err(PlanBundleError::Unsafe(None))
		),
		"sticky mode cannot authorize an unrelated effective owner"
	);
	assert!(
		check_protected(Directory {
			owner: 0,
			..observed
		})
		.is_ok(),
		"the same permissions are admitted with a root owner"
	);
}

#[test]
fn held_walk_refuses_to_truncate_a_deep_chain() {
	// This many distinct directories below the fixture root cannot reach
	// the filesystem root within the 256-observation Plan bundle profile.
	const FIXTURE_DEPTH: usize = 256;
	let scratch = Scratch::new();
	let mounts = MountObservations::capture().expect("capture native fixture mount observations");
	ancestry(&scratch.open(), &mounts, false).expect("observe the shallow fixture ancestry");

	let mut deepest = scratch.path(".");
	for _ in 0..FIXTURE_DEPTH {
		deepest = private_directory(deepest.join("d"));
	}
	let held = File::open(&deepest).expect("hold the deep fixture directory");

	assert!(
		matches!(
			ancestry(&held, &mounts, false),
			Err(PlanBundleError::Scope(None))
		),
		"a partially observed chain cannot establish scope"
	);
}

#[test]
fn held_walk_refuses_unobserved_mount_identity() {
	let scratch = Scratch::new();
	let held = scratch.open();
	let mounts = MountObservations::capture().expect("capture native fixture mount observations");
	let actual = mounts
		.whole_filesystem_mount(&held)
		.expect("observe the fixture mount identity");
	let other = if actual == 1 { 2 } else { 1 };
	let unrelated = format!("{other} {other} 0:1 / / rw - tmpfs fixture rw\n");
	let incomplete = MountObservations::parse(unrelated.as_bytes())
		.expect("parse bounded synthetic mount facts");

	let Err(PlanBundleError::Scope(Some(error))) = ancestry(&held, &incomplete, false) else {
		panic!("the held directory's missing mount identity must refuse scope");
	};
	assert_eq!(error.kind(), ErrorKind::Unsupported);
}
