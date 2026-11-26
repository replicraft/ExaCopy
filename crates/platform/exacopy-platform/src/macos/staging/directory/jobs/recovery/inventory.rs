use apfs_mounted::metadata::{MAX_EXTENDED_SECURITY_BYTES, Metadata, ObjectFlags};
use apfs_mounted::publication::{
	AnchorError, EntrySnapshot, EntrySnapshotError, EntrySpelling, OwnedEventEntry,
};
use apfs_mounted::{EntryName, IdentityError, ObjectIdentity};
use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use rustix::fs::{FileType, Mode, Stat};
use std::fmt;

use super::super::super::super::super::{FILE_MODE, materialized, metadata::observation_io_error};
use super::super::STAGE;
use super::{
	DirectoryLease, JobArtifact, ManagedObjectIdentity, RecoveryDirectory, RecoveryError,
	RecoveryJob, acl, check_absent, component, lookup_stat, with_materialization_disabled,
};

mod readback;

pub use readback::RecoveryStageReader;

/// The selected name whose namespace observation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryName {
	/// The payload name within the private stage directory.
	Stage,
	/// The public target name within the held destination root.
	Target,
}

/// Native identity and logical extent of a checked regular inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryFileObservation {
	identity: ManagedObjectIdentity,
	length: u64,
}

impl RecoveryFileObservation {
	/// Returns the observed native device, volume and inode identity.
	#[must_use]
	pub const fn identity(self) -> ManagedObjectIdentity {
		self.identity
	}

	/// Returns the observed logical length in bytes.
	#[must_use]
	pub const fn length(self) -> u64 {
		self.length
	}
}

impl RecoveryJob<'_> {
	/// Captures the selected private stage and public target names.
	///
	/// Pass the authorized plan components only after binding them to this job.
	/// The stage directory gets its own lease when present. Each present regular
	/// inode is held by a metadata-only inventory capability backed by an event descriptor.
	/// Public APFS aliases still occupy the target. A private stage uses exact spelling.
	///
	/// # Errors
	/// Refuses unsafe namespace bindings, changed observations, and system failures.
	pub fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<RecoveryInventory<'job>, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			let directory =
				RecoveryDirectory::open_optional(&self.directory.lease, STAGE, JobArtifact::Stage)?;
			let staged = match &directory {
				Some(directory) => HeldEntry::open(&directory.lease, stage, RecoveryName::Stage)?,
				None => None,
			};
			let target_entry =
				HeldEntry::open(&self.container.root.lease, target, RecoveryName::Target)?;
			let inventory = RecoveryInventory {
				job: self,
				directory,
				stage_name: stage,
				target_name: target,
				stage: staged,
				target: target_entry,
			};
			inventory.check_current()?;
			Ok(inventory)
		})
	}
}

/// Revalidatable observations of the stage directory and two selected names.
pub struct RecoveryInventory<'job> {
	job: &'job RecoveryJob<'job>,
	directory: Option<RecoveryDirectory>,
	stage_name: UnixComponent<'job>,
	target_name: UnixComponent<'job>,
	stage: Option<HeldEntry>,
	target: Option<HeldEntry>,
}

impl RecoveryInventory<'_> {
	/// Returns the held stage directory identity, if the directory was present.
	#[must_use]
	pub fn stage_directory_identity(&self) -> Option<ManagedObjectIdentity> {
		self.directory.as_ref().map(|directory| directory.identity)
	}

	/// Returns the checked private stage observation, if its name was present.
	#[must_use]
	pub fn stage(&self) -> Option<RecoveryFileObservation> {
		self.stage.as_ref().map(|stage| stage.observation)
	}

	/// Returns the checked public target observation, if its name was occupied.
	#[must_use]
	pub fn target(&self) -> Option<RecoveryFileObservation> {
		self.target.as_ref().map(|target| target.observation)
	}

	/// Revalidates held directories, absence observations and checked regular inodes.
	///
	/// # Errors
	/// Fails if any observed name or authority changed or cannot be revalidated.
	pub fn revalidate(&self) -> Result<(), RecoveryError> {
		with_materialization_disabled(|| self.check_current())
	}

	fn check_current(&self) -> Result<(), RecoveryError> {
		self.job.check_current()?;
		let job = &self.job.directory.lease;
		if let Some(directory) = &self.directory {
			directory.check_current(job, STAGE)?;
			HeldEntry::recheck(
				self.stage.as_ref(),
				&directory.lease,
				self.stage_name,
				RecoveryName::Stage,
			)?;
			directory.check_current(job, STAGE)?;
		} else {
			check_absent(
				job,
				component(STAGE, JobArtifact::Stage)?,
				JobArtifact::Stage,
			)?;
		}
		HeldEntry::recheck(
			self.target.as_ref(),
			&self.job.container.root.lease,
			self.target_name,
			RecoveryName::Target,
		)?;
		self.job.check_current()
	}
}

impl fmt::Debug for RecoveryInventory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryInventory")
			.finish_non_exhaustive()
	}
}

struct HeldEntry {
	anchor: OwnedEventEntry,
	initial: EntrySnapshot,
	observation: RecoveryFileObservation,
}

impl HeldEntry {
	fn open(
		parent: &DirectoryLease,
		component: UnixComponent<'_>,
		role: RecoveryName,
	) -> Result<Option<Self>, RecoveryError> {
		let invalid = || RecoveryError::InvalidEntry(role);
		// Preserve the regular-file admission before any open. Correlate this
		// no-follow baseline with the first coherent owned observation.
		let Some(initial) = lookup_stat(parent, component, invalid())? else {
			return Ok(None);
		};
		let observation = observe(&initial, parent, role)?;
		let name = EntryName::new(component.as_bytes()).map_err(|_| invalid())?;
		let anchor = OwnedEventEntry::open_named(&parent.directory, name)
			.map_err(|error| anchor_error(role, error))?
			.ok_or_else(invalid)?;
		let snapshot = observe_anchor(&anchor, role)?;
		if ManagedObjectIdentity::from_mounted(&snapshot.identity) != observation.identity
			|| !matches_preopen(&initial, snapshot.metadata, observation.length)
		{
			return Err(invalid());
		}
		Ok(Some(Self {
			anchor,
			initial: snapshot,
			observation,
		}))
	}

	fn recheck(
		expected: Option<&Self>,
		parent: &DirectoryLease,
		component: UnixComponent<'_>,
		role: RecoveryName,
	) -> Result<(), RecoveryError> {
		let valid = if let Some(entry) = expected {
			let snapshot = observe_anchor(&entry.anchor, role)?;
			same_inventory_observation(entry.initial, snapshot)
		} else {
			let name = EntryName::new(component.as_bytes())
				.map_err(|_| RecoveryError::InvalidEntry(role))?;
			ObjectIdentity::named(&parent.directory, &name)
				.map_err(|error| identity_error(role, error))?
				.is_none()
		};
		if valid {
			Ok(())
		} else {
			Err(RecoveryError::InvalidEntry(role))
		}
	}
}

fn observe_anchor(
	anchor: &OwnedEventEntry,
	role: RecoveryName,
) -> Result<EntrySnapshot, RecoveryError> {
	let spelling = match role {
		RecoveryName::Stage => EntrySpelling::Exact,
		RecoveryName::Target => EntrySpelling::Lookup,
	};
	let (snapshot, security) = anchor
		.with_observation(spelling, |_, view| {
			Ok(match role {
				RecoveryName::Stage => {
					acl::basic_security(view.extended_security(MAX_EXTENDED_SECURITY_BYTES))
				}
				RecoveryName::Target => Ok(true),
			})
		})
		.map_err(|error| snapshot_error(role, error))?;
	if !security? {
		return Err(RecoveryError::InvalidEntry(role));
	}
	Ok(snapshot)
}

fn matches_preopen(initial: &Stat, metadata: Metadata, length: u64) -> bool {
	let modified = metadata.times.modification;
	let change = metadata.change;
	(metadata.file_type.as_raw_mode() | metadata.mode.as_raw_mode()) == initial.st_mode
		&& metadata.uid == initial.st_uid
		&& metadata.gid == initial.st_gid
		&& metadata.link_count == initial.st_nlink
		&& metadata.bsd_flags == initial.st_flags
		&& metadata.length == length
		&& modified.seconds() == initial.st_mtime
		&& modified.nanoseconds() == initial.st_mtime_nsec
		&& change.seconds() == initial.st_ctime
		&& change.nanoseconds() == initial.st_ctime_nsec
}

fn same_inventory_observation(initial: EntrySnapshot, current: EntrySnapshot) -> bool {
	let mut metadata = current.metadata;
	// A separately admitted data read can advance atime without changing
	// the identity or fixed inventory baseline.
	metadata.times.access = initial.metadata.times.access;
	current.identity == initial.identity && metadata == initial.metadata
}

fn identity_error(role: RecoveryName, error: IdentityError) -> RecoveryError {
	match error {
		IdentityError::Io(error) => error.into(),
		_ => RecoveryError::InvalidEntry(role),
	}
}

fn anchor_error(role: RecoveryName, error: AnchorError) -> RecoveryError {
	match error {
		AnchorError::Identity(error) => identity_error(role, error),
		AnchorError::Open(error) | AnchorError::Directory(error) => error.into(),
		_ => RecoveryError::InvalidEntry(role),
	}
}

fn snapshot_error(role: RecoveryName, error: EntrySnapshotError) -> RecoveryError {
	match error {
		EntrySnapshotError::Identity(error) => identity_error(role, error),
		EntrySnapshotError::Metadata(error) => observation_io_error(error).into(),
		_ => RecoveryError::InvalidEntry(role),
	}
}

fn observe(
	stat: &Stat,
	parent: &DirectoryLease,
	role: RecoveryName,
) -> Result<RecoveryFileObservation, RecoveryError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_nlink != 1
		|| !materialized(ObjectFlags::from_raw(stat.st_flags))
	{
		return Err(RecoveryError::InvalidEntry(role));
	}
	if role == RecoveryName::Stage
		&& (Mode::from_raw_mode(stat.st_mode) != FILE_MODE
			|| stat.st_uid != parent.owner
			|| stat.st_flags != 0)
	{
		return Err(RecoveryError::InvalidEntry(role));
	}
	let identity = ManagedObjectIdentity::from_stat(stat, parent.identity.physical_fsid)
		.ok_or(RecoveryError::InvalidEntry(role))?;
	let length = u64::try_from(stat.st_size)
		.ok()
		.filter(|&length| length <= MAX_FILE_LENGTH)
		.ok_or(RecoveryError::InvalidEntry(role))?;
	Ok(RecoveryFileObservation { identity, length })
}

#[test]
fn recovery_observation_preserves_public_and_private_flag_policies() {
	use std::fs::File;
	use std::os::unix::fs::OpenOptionsExt as _;

	use rustix::fs;

	use super::super::super::super::tests::Fixture;

	let fixture = Fixture::new();
	let root = fixture.bind();
	let file = File::options()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(fixture.path("flag-observation"))
		.unwrap();
	let mut stat = fs::fstat(&file).unwrap();

	// Compare the production observation with the former masks using synthetic
	// flag bits and otherwise native stat fields.
	const LEGACY_UNSUPPORTED: u32 = 0x0080_0000 | 0x4000_0000;
	for flags in core::iter::once(0)
		.chain((0..u32::BITS).map(|bit| 1 << bit))
		.chain([LEGACY_UNSUPPORTED, u32::MAX])
	{
		stat.st_flags = flags;
		for (role, allowed) in [
			(RecoveryName::Target, flags & LEGACY_UNSUPPORTED == 0),
			(RecoveryName::Stage, flags == 0),
		] {
			let result = observe(&stat, &root.lease, role);
			if allowed {
				assert_eq!(result.unwrap().length(), 0, "{role:?}: {flags:#x}");
			} else {
				assert!(
					matches!(result, Err(RecoveryError::InvalidEntry(rejected)) if rejected == role),
					"{role:?}: {flags:#x}"
				);
			}
		}
	}
}

#[test]
fn owned_stage_and_target_reject_replacement_and_preserve_both_entries() {
	use std::fs::{self, File};
	use std::io::Write as _;
	use std::os::unix::fs::OpenOptionsExt as _;

	use super::super::super::super::tests::Fixture;

	let fixture = Fixture::new();
	let root = fixture.bind();
	for (role, name, saved_name) in [
		(RecoveryName::Stage, "stage", "saved-stage"),
		(RecoveryName::Target, "target", "saved-target"),
	] {
		let path = fixture.path(name);
		let saved = fixture.path(saved_name);
		let replacement = fixture.path("replacement");
		for (entry, bytes) in [(&path, b"before"), (&replacement, b"after!")] {
			File::options()
				.create_new(true)
				.write(true)
				.mode(0o600)
				.open(entry)
				.unwrap()
				.write_all(bytes)
				.unwrap();
		}
		let name = UnixComponent::new(name.as_bytes()).unwrap();
		let held = HeldEntry::open(&root.lease, name, role).unwrap().unwrap();
		HeldEntry::recheck(Some(&held), &root.lease, name, role).unwrap();

		fs::rename(&path, &saved).unwrap();
		fs::rename(&replacement, &path).unwrap();

		assert!(matches!(
			HeldEntry::recheck(Some(&held), &root.lease, name, role),
			Err(RecoveryError::InvalidEntry(rejected)) if rejected == role
		));
		assert_eq!(fs::read(saved).unwrap(), b"before");
		assert_eq!(fs::read(path).unwrap(), b"after!");
	}
}

#[test]
fn owned_inventory_baseline_allows_only_access_time_to_differ() {
	use std::fs::File;
	use std::os::unix::fs::OpenOptionsExt as _;

	use apfs_mounted::metadata::Timestamp;

	use super::super::super::super::tests::Fixture;

	let fixture = Fixture::new();
	let root = fixture.bind();
	let name = UnixComponent::new(b"observed-time").unwrap();
	File::options()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(fixture.path("observed-time"))
		.unwrap();

	let held = HeldEntry::open(&root.lease, name, RecoveryName::Stage)
		.unwrap()
		.unwrap();
	let before = held.initial;
	let updated = |time: Timestamp| Timestamp::new(time.seconds() + 1, time.nanoseconds()).unwrap();
	let mut current = before;
	current.metadata.times.access = updated(before.metadata.times.access);
	assert!(same_inventory_observation(before, current));

	current.metadata.times.modification = updated(before.metadata.times.modification);
	assert!(!same_inventory_observation(before, current));

	current.metadata.times.modification = before.metadata.times.modification;
	current.metadata.change = updated(before.metadata.change);
	assert!(!same_inventory_observation(before, current));
}
