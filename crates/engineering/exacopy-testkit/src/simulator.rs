use std::io;
use std::sync::Arc;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};

use crate::fault::{
	EffectError, EffectFault, EffectOperation, Faults, Rejection, TransferFault, TransferOperation,
	queue_fault,
};
use crate::namespace::{
	Area, DiskId, MAX_FILE_BYTES, MAX_OBJECTS, NameEntry, Names, ObjectId, Snapshot, WritableArea,
};

#[derive(Debug)]
struct Process;

#[derive(Debug)]
struct OpenFile {
	identity: ObjectId,
	process: Arc<Process>,
}

/// A source or quiesced stage file opened for read-only access.
#[derive(Debug)]
pub struct ReadHandle(OpenFile);

impl ReadHandle {
	/// Returns the physical identity captured when this file was opened.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.0.identity
	}
}

/// Exclusive positioned write capability for a simulator-owned stage.
#[derive(Debug)]
pub struct StageWriter {
	file: OpenFile,
	name: Vec<u8>,
	target: Vec<u8>,
}

impl StageWriter {
	/// Returns the observed physical identity of the newly created stage.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.file.identity
	}

	/// Consumes the unique write capability. Read-back must reopen the same stage by identity.
	#[must_use]
	pub fn quiesce(self) -> QuiescedStage {
		QuiescedStage(self)
	}
}

/// A stage for which the caller has given up its write capability.
#[derive(Debug)]
pub struct QuiescedStage(StageWriter);

impl QuiescedStage {
	/// Returns the physical identity to verify on reopen and publication.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.0.identity()
	}
}

#[derive(Debug, Default)]
struct File {
	live: Vec<u8>,
	stable: Vec<u8>,
}

/// One small disk with separate process, volatile storage, and stable storage state.
///
/// Each area models a single already-open directory and contains exact byte names. A file
/// barrier persists only that file's bytes. A directory barrier persists only that directory's
/// name map. Unflushed effects never persist on their own. This is one deterministic fault
/// model, with no external filesystem access or OS or hardware durability guarantees.
#[derive(Debug)]
pub struct Simulator {
	disk: DiskId,
	process: Arc<Process>,
	live_names: Names,
	stable_names: Names,
	files: Vec<File>,
	faults: Faults,
}

impl Simulator {
	/// Starts an empty disk fixture with a fresh process.
	#[must_use]
	pub fn new(disk: DiskId) -> Self {
		Self {
			disk,
			process: Arc::new(Process),
			live_names: Names::default(),
			stable_names: Names::default(),
			files: Vec::new(),
			faults: Faults::default(),
		}
	}

	/// Queues one fault for a future valid positional call in the given direction.
	///
	/// # Errors
	///
	/// Rejects more than 64 queued calls per direction.
	pub fn inject_transfer(
		&mut self,
		operation: TransferOperation,
		fault: TransferFault,
	) -> Result<(), Rejection> {
		let queue = match operation {
			TransferOperation::Read => &mut self.faults.read,
			TransferOperation::Write => &mut self.faults.write,
		};
		queue_fault(queue, fault)
	}

	/// Queues one fault for a future valid call of an effect.
	///
	/// # Errors
	///
	/// Rejects more than 64 queued calls per effect.
	pub fn inject_effect(
		&mut self,
		operation: EffectOperation,
		fault: EffectFault,
	) -> Result<(), Rejection> {
		let queue = match operation {
			EffectOperation::Create => &mut self.faults.create,
			EffectOperation::FlushFile => &mut self.faults.flush_file,
			EffectOperation::Publish => &mut self.faults.publish,
			EffectOperation::FlushDirectory => &mut self.faults.flush_directory,
		};
		queue_fault(queue, fault)
	}

	/// Installs pre-existing content into both storage views as an external fixture action.
	///
	/// # Errors
	///
	/// Rejects occupied names in either view and fixtures exceeding the storage bounds.
	pub fn seed_file(
		&mut self,
		area: Area,
		name: &UnixComponent<'_>,
		bytes: &[u8],
	) -> Result<ObjectId, Rejection> {
		let name = name.as_bytes();
		self.live_names.admit(area, name)?;
		self.stable_names.admit(area, name)?;
		let identity = self.allocate_file(bytes, bytes)?;
		self.seed_name(area, name, NameEntry::File(identity));
		Ok(identity)
	}

	/// Installs a pre-existing symlink occupying an exact name in both storage views.
	///
	/// # Errors
	///
	/// Rejects occupied names in either view and directories at their name limit.
	pub fn seed_symlink(&mut self, area: Area, name: &UnixComponent<'_>) -> Result<(), Rejection> {
		let name = name.as_bytes();
		self.live_names.admit(area, name)?;
		self.stable_names.admit(area, name)?;
		self.seed_name(area, name, NameEntry::Symlink);
		Ok(())
	}

	/// Installs a destination hard-link fixture to a pre-existing source file.
	///
	/// # Errors
	///
	/// Rejects absent or non-file sources, occupied destinations and full directories.
	pub fn seed_source_alias(
		&mut self,
		source: &UnixComponent<'_>,
		destination: &UnixComponent<'_>,
	) -> Result<(), Rejection> {
		let identity = self.source_identity(source)?;
		let name = destination.as_bytes();
		self.live_names.admit(Area::Destination, name)?;
		self.stable_names.admit(Area::Destination, name)?;
		self.seed_name(Area::Destination, name, NameEntry::File(identity));
		Ok(())
	}

	/// Simulates an external actor rebinding an existing private name to unrelated live bytes.
	///
	/// # Errors
	///
	/// Rejects an absent name and fixtures exceeding the storage bounds.
	pub fn rebind_stage(
		&mut self,
		name: &UnixComponent<'_>,
		bytes: &[u8],
	) -> Result<ObjectId, Rejection> {
		let name = name.as_bytes();
		self.live_names
			.get(Area::Private, name)
			.ok_or(Rejection::Missing)?;
		let identity = self.allocate_file(bytes, &[])?;
		self.live_names
			.insert(Area::Private, name.to_vec(), NameEntry::File(identity));
		Ok(identity)
	}

	/// Opens exactly one regular source component without following links.
	///
	/// # Errors
	///
	/// Rejects an absent name or one that names a symlink.
	pub fn open_source(&self, name: &UnixComponent<'_>) -> Result<ReadHandle, Rejection> {
		Ok(ReadHandle(self.bind(self.source_identity(name)?)))
	}

	/// Creates a private file bound to one target and returns its unique write capability.
	///
	/// # Errors
	///
	/// Rejects occupied names and exhausted fixtures, or reports the scripted effect failure.
	pub fn create_stage(
		&mut self,
		name: &UnixComponent<'_>,
		target: &UnixComponent<'_>,
	) -> Result<StageWriter, EffectError> {
		let name = name.as_bytes();
		self.live_names.admit(Area::Private, name)?;
		self.admit_file(0)?;
		let fault = self.faults.create.pop_front().unwrap_or(EffectFault::Pass);
		fault.begin()?;
		let identity = self.allocate_file(&[], &[])?;
		self.live_names
			.insert(Area::Private, name.to_vec(), NameEntry::File(identity));
		fault.finish(StageWriter {
			file: self.bind(identity),
			name: name.to_vec(),
			target: target.as_bytes().to_vec(),
		})
	}

	/// Reopens a quiesced stage for independent read-back, checking its physical identity.
	///
	/// # Errors
	///
	/// Rejects process-stale handles and names rebound or removed since stage creation.
	pub fn open_quiesced(&self, stage: &QuiescedStage) -> Result<ReadHandle, Rejection> {
		let identity = self.check_stage(&stage.0)?;
		Ok(ReadHandle(self.bind(identity)))
	}

	/// Performs one positional read call for use with the endpoint's complete-read loop.
	///
	/// # Errors
	///
	/// Rejects a stale handle or invalid range, or returns the next scripted I/O error.
	pub fn read_at(
		&mut self,
		handle: &ReadHandle,
		offset: u64,
		buffer: &mut [u8],
	) -> io::Result<usize> {
		let index = self.file_index(&handle.0)?;
		if offset > MAX_FILE_LENGTH {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let fault = self.faults.read.pop_front().unwrap_or(TransferFault::Pass);
		let limit = fault.begin(buffer.len())?;
		let bytes = &self.files[index].live;
		let start = usize::try_from(offset).unwrap_or(usize::MAX);
		let available = bytes.get(start..).unwrap_or_default();
		let count = limit.min(available.len());
		buffer[..count].copy_from_slice(&available[..count]);
		fault.finish(count)
	}

	/// Performs one positional write call for use with the endpoint's complete-write loop.
	///
	/// Only the issued stage file is modified. A gap within the fixture size bound reads as zero.
	///
	/// # Errors
	///
	/// Rejects a stale handle or an out-of-bounds write, or returns the scripted I/O error.
	pub fn write_at(
		&mut self,
		stage: &StageWriter,
		offset: u64,
		buffer: &[u8],
	) -> io::Result<usize> {
		let index = self.file_index(&stage.file)?;
		let start = bounded_write(offset, buffer.len())?;
		let fault = self.faults.write.pop_front().unwrap_or(TransferFault::Pass);
		let count = fault.begin(buffer.len())?;
		if count != 0 {
			let bytes = &mut self.files[index].live;
			let end = start + count;
			if end > bytes.len() {
				bytes.resize(end, 0);
			}
			bytes[start..end].copy_from_slice(&buffer[..count]);
		}
		fault.finish(count)
	}

	/// Copies the open stage file's live data into the stable data view.
	///
	/// # Errors
	///
	/// Rejects stale handles or reports the scripted effect failure.
	pub fn flush_file(&mut self, stage: &QuiescedStage) -> Result<(), EffectError> {
		let index = self.file_index(&stage.0.file)?;
		let fault = self
			.faults
			.flush_file
			.pop_front()
			.unwrap_or(EffectFault::Pass);
		fault.begin()?;
		let file = &mut self.files[index];
		file.stable.clone_from(&file.live);
		fault.finish(())
	}

	/// Moves the exact owned stage entry to its pre-bound destination if that name is absent.
	///
	/// This is the namespace primitive. The caller supplies verification and intent evidence.
	///
	/// # Errors
	///
	/// Rejects stale or rebound stages, occupied destinations and full directories, or reports
	/// the scripted effect failure. Inspect the namespace after an unknown result.
	pub fn publish_no_clobber(&mut self, stage: QuiescedStage) -> Result<(), EffectError> {
		let identity = self.check_stage(&stage.0)?;
		self.live_names.admit(Area::Destination, &stage.0.target)?;
		let fault = self.faults.publish.pop_front().unwrap_or(EffectFault::Pass);
		fault.begin()?;
		self.live_names.remove(Area::Private, &stage.0.name);
		self.live_names
			.insert(Area::Destination, stage.0.target, NameEntry::File(identity));
		fault.finish(())
	}

	/// Copies one directory's live entries to its stable view without persisting file data.
	///
	/// # Errors
	///
	/// Returns the scripted error if the barrier does not report success.
	pub fn flush_directory(&mut self, area: WritableArea) -> Result<(), EffectError> {
		let fault = self
			.faults
			.flush_directory
			.pop_front()
			.unwrap_or(EffectFault::Pass);
		fault.begin()?;
		self.stable_names.persist(&self.live_names, area.into());
		fault.finish(())
	}

	/// Captures the names and bytes visible between processes while storage remains running.
	#[must_use]
	pub fn live_snapshot(&self) -> Snapshot {
		Snapshot::new(&self.live_names, |number| {
			self.files.get(number).map(|file| &file.live)
		})
	}

	/// Captures the exact names and bytes this fixture retains on loss of volatile storage.
	#[must_use]
	pub fn stable_snapshot(&self) -> Snapshot {
		Snapshot::new(&self.stable_names, |number| {
			self.files.get(number).map(|file| &file.stable)
		})
	}

	/// Invalidates open handles and clears the process's scripted faults, retaining live storage.
	pub fn process_crash(&mut self) {
		self.process = Arc::new(Process);
		self.faults = Faults::default();
	}

	/// Crashes the process and restores only the state copied by the fixture or barriers.
	///
	/// For cross-directory publication, the two names can survive independently. The simulator
	/// does not model journaling, reorderings, writeback without barriers, or device behavior.
	pub fn lose_volatile_state(&mut self) {
		self.process_crash();
		self.live_names.clone_from(&self.stable_names);
		for file in &mut self.files {
			file.live.clone_from(&file.stable);
		}
	}

	fn seed_name(&mut self, area: Area, name: &[u8], entry: NameEntry) {
		self.live_names.insert(area, name.to_vec(), entry);
		self.stable_names.insert(area, name.to_vec(), entry);
	}

	fn admit_file(&self, bytes: usize) -> Result<(), Rejection> {
		if self.files.len() == MAX_OBJECTS || bytes > MAX_FILE_BYTES {
			return Err(Rejection::Limit);
		}
		Ok(())
	}

	fn allocate_file(&mut self, live: &[u8], stable: &[u8]) -> Result<ObjectId, Rejection> {
		self.admit_file(live.len().max(stable.len()))?;
		let index = self.files.len();
		self.files.push(File {
			live: live.to_vec(),
			stable: stable.to_vec(),
		});
		Ok(ObjectId::new(self.disk, index))
	}

	fn source_identity(&self, name: &UnixComponent<'_>) -> Result<ObjectId, Rejection> {
		match self.live_names.get(Area::Source, name.as_bytes()) {
			Some(NameEntry::File(identity)) => Ok(identity),
			Some(NameEntry::Symlink) => Err(Rejection::NotAFile),
			None => Err(Rejection::Missing),
		}
	}

	fn bind(&self, identity: ObjectId) -> OpenFile {
		OpenFile {
			identity,
			process: Arc::clone(&self.process),
		}
	}

	fn file_index(&self, handle: &OpenFile) -> Result<usize, Rejection> {
		if !Arc::ptr_eq(&self.process, &handle.process) {
			return Err(Rejection::StaleHandle);
		}
		Ok(handle.identity.number())
	}

	fn check_stage(&self, stage: &StageWriter) -> Result<ObjectId, Rejection> {
		self.file_index(&stage.file)?;
		match self.live_names.get(Area::Private, &stage.name) {
			Some(NameEntry::File(identity)) if identity == stage.identity() => Ok(identity),
			_ => Err(Rejection::StageRebound),
		}
	}
}

fn bounded_write(offset: u64, length: usize) -> io::Result<usize> {
	let start = usize::try_from(offset).map_err(|_| Rejection::Limit)?;
	match start.checked_add(length) {
		Some(end) if end <= MAX_FILE_BYTES => Ok(start),
		_ => Err(Rejection::Limit.into()),
	}
}
