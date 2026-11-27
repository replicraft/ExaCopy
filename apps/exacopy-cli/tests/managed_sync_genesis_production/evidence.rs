//! Bounded independent observations from actual published names and descriptors.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use exacopy_cli::assembly::linux::managed_sync::genesis::{
	ManagedGenesisPublished, ManagedGenesisRequest,
};
use exacopy_plan::workflow_sync::{WorkflowKind, WorkflowRef};
use exacopy_transfer::sync_genesis::{
	ExpectedSyncGenesis, SelectedSyncGenesisMember, inspect_selected_sync_genesis,
};
use rustix::fs::{Dir, OFlags};
use serde_json::{Value, json};

use super::observe::Anchor;
use super::rig::{Sandbox, assert_missing, open_child};
use super::{INITIAL, ROOT_NAMES, SUBJECT, TestResult, approval};

pub(super) const NAMES: [&[u8]; 4] = [b"root.cbor", b"left.cbor", b"right.cbor", b"leaf.cbor"];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Stamp {
	dev: u64,
	ino: u64,
	mode: u32,
	uid: u32,
	gid: u32,
	size: u64,
	links: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}

impl From<&Metadata> for Stamp {
	fn from(meta: &Metadata) -> Self {
		Self {
			dev: meta.dev(),
			ino: meta.ino(),
			mode: meta.mode(),
			uid: meta.uid(),
			gid: meta.gid(),
			size: meta.size(),
			links: meta.nlink(),
			modified: (meta.mtime(), meta.mtime_nsec()),
			changed: (meta.ctime(), meta.ctime_nsec()),
		}
	}
}

impl Stamp {
	fn frame(&self) -> Value {
		json!([
			self.dev,
			self.ino,
			self.mode,
			self.uid,
			self.gid,
			self.size,
			self.links,
			self.modified,
			self.changed
		])
	}
}

struct Member {
	held: File,
	stamp: Stamp,
	bytes: Vec<u8>,
}

impl Member {
	fn read(parent: &File, name: &[u8], owner: (u32, u32), extent: usize) -> TestResult<Self> {
		let held = open_child(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
		let meta = held.metadata()?;
		assert!(meta.is_file());
		let stamp = Stamp::from(&meta);
		assert_eq!(
			(stamp.mode & 0o7777, stamp.uid, stamp.gid, stamp.links),
			(0o600, owner.0, owner.1, 1)
		);
		assert!((1..=2048).contains(&extent));
		assert_eq!(stamp.size, u64::try_from(extent)?);
		let bytes = exact_bytes(&held, extent)?;
		assert_eq!(Stamp::from(&held.metadata()?), stamp);
		assert_eq!(
			Stamp::from(&open_child(parent, name, OFlags::PATH)?.metadata()?),
			stamp
		);
		Ok(Self { held, stamp, bytes })
	}

	fn recheck(&self, parent: &File, name: &[u8]) -> TestResult {
		assert_eq!(Stamp::from(&self.held.metadata()?), self.stamp);
		assert_eq!(exact_bytes(&self.held, self.bytes.len())?, self.bytes);
		assert_eq!(
			Stamp::from(&open_child(parent, name, OFlags::PATH)?.metadata()?),
			self.stamp
		);
		Ok(())
	}
}

fn exact_bytes(held: &File, extent: usize) -> TestResult<Vec<u8>> {
	assert!(extent <= 8192);
	let mut bytes = vec![0; extent];
	held.read_exact_at(&mut bytes, 0)?;
	assert_eq!(held.read_at(&mut [0], u64::try_from(extent)?)?, 0);
	Ok(bytes)
}

pub(super) fn live_sources(
	roots: [&File; 2],
	files: [&File; 2],
	streams: [&[u8]; 2],
) -> TestResult<[Stamp; 2]> {
	let read_source = |index: usize| -> TestResult<Stamp> {
		let held = files[index];
		let meta = held.metadata()?;
		let stamp = Stamp::from(&meta);
		assert!(meta.is_file());
		assert_eq!((stamp.mode & 0o7777, stamp.links), (0o600, 1));
		assert_eq!(exact_bytes(held, streams[index].len())?, streams[index]);
		assert_eq!(Stamp::from(&held.metadata()?), stamp);
		assert_eq!(
			Stamp::from(&open_child(roots[index], SUBJECT, OFlags::PATH)?.metadata()?),
			stamp
		);
		Ok(stamp)
	};
	let stamps = [read_source(0)?, read_source(1)?];
	assert_ne!(
		(stamps[0].dev, stamps[0].ino),
		(stamps[1].dev, stamps[1].ino)
	);
	Ok(stamps)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Inventory {
	directory: Stamp,
	entries: Vec<(Vec<u8>, Stamp, Option<Vec<u8>>)>,
}

pub(super) fn inventory(parent: &File) -> TestResult<Inventory> {
	let directory = Stamp::from(&parent.metadata()?);
	let mut entries = Vec::new();
	for record in Dir::read_from(parent)? {
		let record = record?;
		let name = record.file_name().to_bytes();
		if matches!(name, b"." | b"..") {
			continue;
		}
		assert!(entries.len() < 16);
		let pinned = open_child(parent, name, OFlags::PATH)?;
		let meta = pinned.metadata()?;
		let stamp = Stamp::from(&meta);
		let contents = if meta.is_file() {
			let file = open_child(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
			assert_eq!(Stamp::from(&file.metadata()?), stamp);
			let contents = exact_bytes(&file, usize::try_from(stamp.size)?)?;
			assert_eq!(Stamp::from(&file.metadata()?), stamp);
			Some(contents)
		} else {
			assert!(meta.is_dir());
			None
		};
		entries.push((name.to_vec(), stamp, contents));
	}
	entries.sort_by(|left, right| left.0.cmp(&right.0));
	assert_eq!(Stamp::from(&parent.metadata()?), directory);
	Ok(Inventory { directory, entries })
}

pub(super) struct Published {
	pub(super) directory: File,
	pub(super) final_name: Vec<u8>,
	pub(super) refs: [WorkflowRef; 4],
	stamp: Stamp,
	stage_name: Vec<u8>,
	intent_name: Vec<u8>,
	intent: Member,
	members: [Member; 4],
}

impl Published {
	pub(super) fn read(
		output: &File,
		request: &ManagedGenesisRequest<'_>,
		owner_profile: [u8; 16],
		published: &ManagedGenesisPublished,
	) -> TestResult<Self> {
		let operation = published.publication.operation;
		assert_eq!(operation, request.operation);
		let operation_hex = hex(&operation.bytes());
		let final_name = format!("genesis-{operation_hex}").into_bytes();
		let stage_name = format!(".exacopy-genesis-stage-{operation_hex}").into_bytes();
		let intent_name = format!(".exacopy-genesis-intent-{operation_hex}.v1").into_bytes();
		assert_eq!(operation.final_name(), final_name);
		assert_eq!(operation.stage_name(), stage_name);
		assert_eq!(operation.intent_name(), intent_name);
		assert_missing(output, &stage_name);
		let owner = (request.native.uid.get(), request.native.gid.get());
		let directory = open_child(output, &final_name, OFlags::RDONLY | OFlags::DIRECTORY)?;
		let stamp = Stamp::from(&directory.metadata()?);
		assert_eq!(
			(stamp.dev, stamp.ino),
			(
				published.publication.identity.device(),
				published.publication.identity.inode()
			)
		);
		assert_eq!(
			(stamp.mode & 0o7777, stamp.uid, stamp.gid),
			(0o700, owner.0, owner.1)
		);
		assert_eq!(stamp.dev, request.output_identity.device);
		assert_ne!(stamp.ino, request.output_identity.inode.get());
		let intent = Member::read(output, &intent_name, owner, 364)?;
		let mut preimage = Vec::from(b"EXSYNINT\x01\0\0\0".as_slice());
		preimage.extend(operation.bytes());
		preimage.extend(request.output_identity.device.to_le_bytes());
		preimage.extend(request.output_identity.inode.get().to_le_bytes());
		preimage.extend(stamp.dev.to_le_bytes());
		preimage.extend(stamp.ino.to_le_bytes());
		preimage.extend(approval::intent(
			request,
			owner_profile,
			published.root.digest,
		));
		let [left, right, leaf] = published.children;
		let refs = [published.root, left, right, leaf];
		assert_eq!(
			refs.map(|reference| reference.kind),
			[
				WorkflowKind::Root,
				WorkflowKind::Endpoint,
				WorkflowKind::Endpoint,
				WorkflowKind::Leaf
			]
		);
		let get = |index: usize| {
			Member::read(&directory, NAMES[index], owner, refs[index].byte_len.into())
		};
		let members = [get(0)?, get(1)?, get(2)?, get(3)?];
		for (reference, member) in refs.iter().zip(&members) {
			preimage.extend((reference.kind as u16).to_le_bytes());
			preimage.extend(reference.byte_len.to_le_bytes());
			preimage.extend(reference.digest);
			preimage.extend(blake3::hash(&member.bytes).as_bytes());
		}
		assert_eq!(intent.bytes, preimage);

		let owner = ed25519_dalek::VerifyingKey::from_bytes(&request.owner_key)
			.map_err(|_| "fixture owner key was invalid")?;
		let expected = ExpectedSyncGenesis {
			root_digest: published.root.digest,
			profile: owner_profile,
			revision: request.profile_revision,
			owner: &owner,
			subject: request.native.subject,
			endpoints: request.endpoints,
			scan: Some(request.scan),
		};
		let children = [1, 2, 3].map(|index| SelectedSyncGenesisMember {
			reference: refs[index],
			locator: index,
		});
		let mut root_buffer = [0; 2048];
		let history = inspect_selected_sync_genesis(
			members[0].bytes.as_slice(),
			std::num::NonZeroU16::new(refs[0].byte_len).ok_or("zero genesis root length")?,
			&mut root_buffer,
			&expected,
			children,
			|index| Ok(members[index].bytes.as_slice()),
		)?;
		let expected_digest = *blake3::hash(INITIAL).as_bytes();
		assert!(
			history
				.sides()
				.iter()
				.all(|side| side.stream_digest == expected_digest)
		);
		let selected = Self {
			directory,
			final_name,
			refs,
			stamp,
			stage_name,
			intent_name,
			intent,
			members,
		};
		selected.recheck(output)?;
		Ok(selected)
	}

	pub(super) fn recheck(&self, output: &File) -> TestResult {
		assert_missing(output, &self.stage_name);
		assert_eq!(Stamp::from(&self.directory.metadata()?), self.stamp);
		assert_eq!(
			Stamp::from(&open_child(output, &self.final_name, OFlags::PATH)?.metadata()?),
			self.stamp
		);
		self.intent.recheck(output, &self.intent_name)?;
		let mut names: Vec<_> = NAMES.into_iter().map(<[u8]>::to_vec).collect();
		names.sort();
		assert_eq!(
			inventory(&self.directory)?
				.entries
				.into_iter()
				.map(|(name, _, _)| name)
				.collect::<Vec<_>>(),
			names
		);
		for (name, member) in NAMES.into_iter().zip(&self.members) {
			member.recheck(&self.directory, name)?;
		}
		Ok(())
	}

	pub(super) fn track(&self, sandbox: &mut Sandbox, output: &File) -> TestResult {
		sandbox.track_held_slot(output, &self.intent_name, &self.intent.held)?;
		sandbox.track_directory(output, &self.final_name, &self.directory)?;
		for (name, member) in NAMES.into_iter().zip(&self.members) {
			sandbox.track_held_slot(&self.directory, name, &member.held)?;
		}
		Ok(())
	}

	pub(super) fn frame(
		&self,
		sandbox: &Sandbox,
		anchor: &Anchor,
		request: &ManagedGenesisRequest<'_>,
		owner_profile: [u8; 16],
		sources: &[Stamp; 2],
	) -> Value {
		let expected_object = |object: exacopy_platform::linux::ManagedSyncExpectedObject| {
			json!([object.major, object.minor, object.inode.get()])
		};
		let native = request.native;
		let endpoint = |index: usize| {
			let ep = request.endpoints[index];
			json!([
				hex(&ep.endpoint),
				hex(&ep.root),
				hex(&ep.parent),
				hex(ROOT_NAMES[index]),
				expected_object(native.roots[index].identity),
				ep.max_bytes
			])
		};
		let paths_hex = [request.profile, native.parent_path, request.output_parent]
			.map(|path| hex(path.as_os_str().as_bytes()));
		json!({
			"version": 1,
			"fixture": sandbox.path.file_name().and_then(OsStr::to_str).unwrap(),
			"anchors": anchor.sides.map(|id| [u64::from(id.major), u64::from(id.minor), id.inode.get()]),
			"boot": hex(&native.boot),
			"mount_namespace": expected_object(native.mount_namespace),
			"user_namespace": expected_object(native.user_namespace),
			"ordinary_mount": native.ordinary_mount.get(),
			"unique_mount": native.unique_mount.get(),
			"native_live_parent": expected_object(native.parent),
			"native_profile": [request.profile_identity.device(), request.profile_identity.inode()],
			"native_output": [request.output_identity.device, request.output_identity.inode.get()],
			"actor": [native.uid.get(), native.gid.get()],
			"paths_hex": paths_hex,
			"owner": hex(&request.owner_key), "owner_profile": hex(&owner_profile),
			"profile_revision": request.profile_revision.get(),
			"operation": hex(&request.operation.bytes()),
			"enrollment": [hex(&request.enrollment.id), hex(&request.enrollment.expected_digest)],
			"participants": request.enrollment.participants.iter().map(|id| hex(id)).collect::<Vec<_>>(),
			"subject_hex": hex(SUBJECT),
			"endpoints": [endpoint(0), endpoint(1)],
			"records": [hex(&request.records.root), hex(&request.records.endpoints[0]), hex(&request.records.endpoints[1])],
			"creation": [12, 19],
			"scan": request.scan.get(),
			"live_stream_hex": hex(INITIAL),
			"source_stamps": [sources[0].frame(), sources[1].frame()],
			"final_stamp": self.stamp.frame(),
			"intent_stamp": self.intent.stamp.frame(),
			"intent_hex": hex(&self.intent.bytes),
			"members": self.members.iter().enumerate().map(|(index, member)| {
				let reference = self.refs[index];
				json!([hex(NAMES[index]), member.stamp.frame(), reference.kind as u16, hex(&reference.digest), hex(&member.bytes)])
			}).collect::<Vec<_>>(),
		})
	}
}

fn hex(bytes: &[u8]) -> String {
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(out, "{byte:02x}").unwrap();
	}
	out
}
