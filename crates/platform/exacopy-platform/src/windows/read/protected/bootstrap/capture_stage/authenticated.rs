use std::cell::Cell;
use std::fmt;
use std::io;
use std::os::windows::io::AsHandle as _;

use windows_sys::Win32::Storage::FileSystem::{
	FILE_APPEND_DATA, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
};

use crate::windows::WindowsStageIdentity;
use crate::windows::stage::publication::native::require_access;

use super::super::record::{MetadataPin, Record};
use super::super::{
	WindowsBootstrapLayout, WindowsBootstrapRoleObservations, WindowsCaptureBootstrapScope,
	WindowsCaptureBootstrapSegment,
};
use super::{
	Error, FILE_METADATA_ACCESS, WindowsCaptureStageError, WindowsCaptureStageScope,
	WindowsCaptureStageWriter, WindowsComponent,
};

mod journal;
mod stage;

pub use journal::{
	WindowsCaptureJournalAdmission, WindowsCaptureJournalGuard, WindowsCaptureJournalSegment,
};
pub use stage::{
	WindowsGuardedCaptureReadBack, WindowsGuardedCaptureStage, WindowsGuardedCaptureView,
};

/// Maximum extent of the separate authenticated capture history.
pub const MAX_WINDOWS_CAPTURE_SEGMENT_BYTES: usize = 1_114_982;

const CAPTURE_NAME: [u16; 17] = [
	99, 97, 112, 116, 117, 114, 101, 45, 118, 49, 46, 101, 120, 97, 106, 110, 108,
];

fn open_empty_sibling(
	parent: &super::Directory,
	name: WindowsComponent<'_>,
	subject: &super::security::Subject,
	expected: WindowsStageIdentity,
) -> Result<Record, Error> {
	let pin = MetadataPin::open(parent, name, subject, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
	if pin.binding.identity != expected {
		return Err(Error::Changed);
	}
	let journal = pin.open_data(parent, name, true)?;
	require_access(
		journal.file.as_handle(),
		FILE_METADATA_ACCESS | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA,
	)
	.map_err(|_| Error::Unprotected)?;
	journal.eof()?;
	journal.check(parent, name)?;
	Ok(journal)
}

#[cfg(test)]
mod tests;

/// One exact synchronous effect on the already selected Windows capture scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowsCaptureEffect {
	/// The complete original bounded V1 append and its file barriers.
	Bootstrap,
	/// Exclusive creation of the fixed private stage directory.
	CreateStageDirectory,
	/// Exclusive creation of the private payload under the actual new directory.
	CreateStageFile {
		/// Full actual directory identity.
		directory: WindowsStageIdentity,
		/// Exact declared source extent.
		length: u64,
	},
	/// A private contiguous write, including bounded short-write completion.
	StageWrite {
		/// Full actual private stage identity.
		stage: WindowsStageIdentity,
		/// Exact start offset.
		offset: u64,
		/// Exact proposed request length.
		length: usize,
	},
	/// A full file barrier at the exact written prefix.
	StagePrefixBarrier {
		/// Full actual private stage identity.
		stage: WindowsStageIdentity,
		/// Exact proposed prefix end.
		end: u64,
	},
	/// The completed stage file barrier and verified writer close.
	StageCloseBarrier {
		/// Full actual private stage identity.
		stage: WindowsStageIdentity,
		/// Exact completed extent.
		end: u64,
	},
	/// One bounded capture frame append and full file barrier.
	JournalAppend {
		/// Full original capture sibling identity.
		segment: WindowsStageIdentity,
		/// Exact starting append offset.
		offset: u64,
		/// Exact complete frame size, including its envelope.
		length: usize,
	},
}

/// Live app authority for the selected protected capture operation.
///
/// The application rechecks its actual scope and serializes revocation through
/// the returned guard. Dropping the guard must only release that admission.
pub trait WindowsCaptureAdmission {
	/// Guard covering the started synchronous native effect.
	type Guard<'gate>
	where
		Self: 'gate;

	/// Enters live admission immediately before the selected effect.
	/// # Errors
	/// A refusal prevents submission of the requested effect.
	fn enter(&self, effect: WindowsCaptureEffect) -> io::Result<Self::Guard<'_>>;
}

/// Original provisioned Windows bootstrap and separate empty capture journal.
pub struct WindowsAuthenticatedCaptureScope<'name> {
	bootstrap: WindowsCaptureBootstrapScope<'name>,
	journal: Record,
	name: WindowsComponent<'static>,
}

impl<'name> WindowsAuthenticatedCaptureScope<'name> {
	/// Holds the original fresh bootstrap and exact originally provisioned sibling.
	///
	/// The caller supplies independent physical selections, protected namespace
	/// provenance and the cooperative custody contract of the bootstrap scope.
	/// The fixed capture sibling is already provisioned under the original journal
	/// directory. The sibling must already exist and have zero extent.
	/// # Errors
	/// Refuses an unsafe or occupied sibling, changed original role, insufficient
	/// access or unsupported native custody.
	pub fn open_provisioned(
		root: &'name [u16],
		bootstrap_roles: WindowsBootstrapRoleObservations,
		layout: WindowsBootstrapLayout<'name>,
		capture_segment: WindowsStageIdentity,
	) -> Result<Self, Error> {
		let bootstrap =
			WindowsCaptureBootstrapScope::open_provisioned(root, bootstrap_roles, layout)?;
		let records = &bootstrap.bootstrap.records;
		let name = WindowsComponent::new(&CAPTURE_NAME).map_err(|_| Error::InvalidPath)?;
		let other_roles = [
			bootstrap_roles.root,
			bootstrap_roles.job_directory,
			bootstrap_roles.owner_file,
			bootstrap_roles.journal_directory,
			bootstrap_roles.first_segment,
		];
		if other_roles.contains(&capture_segment) {
			return Err(Error::Unprotected);
		}
		let journal =
			open_empty_sibling(&records.journal, name, &records.subject, capture_segment)?;
		records.recheck()?;
		Ok(Self {
			bootstrap,
			journal,
			name,
		})
	}

	/// Returns all five original V1 role identities for independent authentication.
	#[must_use]
	pub fn roles(&self) -> WindowsBootstrapRoleObservations {
		self.bootstrap.bootstrap.records.roles()
	}

	/// Returns the exact admitted native identity of the separate empty sibling.
	#[must_use]
	pub fn capture_segment_identity(&self) -> WindowsStageIdentity {
		self.journal.pin.binding.identity
	}

	/// Confirms the expected bounded owner bytes on the original held descriptor.
	/// This remains an observation. The application verifies the expected owner
	/// independently before the call, and the V1 transfer compares it again.
	/// # Errors
	/// Refuses a changed owner, extent, protected role or physical EOF.
	pub fn confirm_owner_bytes(&mut self, expected: &[u8]) -> Result<(), Error> {
		let records = &mut self.bootstrap.bootstrap.records;
		if expected.len() != records.layout.owner_bytes {
			return Err(Error::Changed);
		}
		self.journal.check(&records.journal, self.name)?;
		let observed = records.read_owner()?;
		if observed != expected {
			return Err(Error::Changed);
		}
		self.journal.eof()?;
		self.journal.check(&records.journal, self.name)?;
		records.recheck()
	}

	/// Performs the original exact V1 append under one live guard.
	/// The guard spans both file barriers in the standard V1 handoff. The
	/// callback must use its native segment directly without reacquiring this gate.
	/// # Errors
	/// Refuses changed custody, declined admission or an unconfirmed V1 effect.
	/// The physical records are retained on failure.
	pub fn append_first_segment<'gate, A: WindowsCaptureAdmission>(
		self,
		owner: &[u8],
		first: &[u8],
		admission: &'gate A,
		append: impl for<'scope> FnOnce(WindowsCaptureBootstrapSegment<'scope, 'name>) -> io::Result<()>,
	) -> io::Result<WindowsPreparedCaptureScope<'name, 'gate, A>> {
		let Self {
			bootstrap,
			journal,
			name,
		} = self;
		bootstrap.bootstrap.check()?;
		journal.eof().map_err(io::Error::other)?;
		journal
			.check(&bootstrap.bootstrap.records.journal, name)
			.map_err(io::Error::other)?;
		let guard = admission.enter(WindowsCaptureEffect::Bootstrap)?;
		let stage = bootstrap.append_first_segment(owner, first, append)?;
		journal.eof().map_err(io::Error::other)?;
		journal
			.check(&stage.bootstrap.records.journal, name)
			.map_err(io::Error::other)?;
		drop(guard);
		Ok(WindowsPreparedCaptureScope {
			stage,
			journal,
			name,
			admission,
		})
	}
}

/// Original V1 scope after exact append, with the same held capture sibling.
pub struct WindowsPreparedCaptureScope<'name, 'gate, A> {
	stage: WindowsCaptureStageScope<'name>,
	journal: Record,
	name: WindowsComponent<'static>,
	admission: &'gate A,
}

impl<A: WindowsCaptureAdmission> WindowsPreparedCaptureScope<'_, '_, A> {
	/// Creates one guarded protected private stage and lends both original writers.
	/// Native capabilities cannot escape the callback. Calls that perform writes
	/// or barriers acquire a current synchronous effect guard. After returning
	/// success the callback must have closed the stage and synchronized a nonempty
	/// capture journal. The caller establishes all authentication and storage meaning.
	/// # Errors
	/// Refuses blocked creation, custody, or an unconfirmed terminal observation.
	/// Application errors remain distinct. All possibly written objects are retained.
	pub async fn with_capture<T, E>(
		self,
		target: WindowsComponent<'_>,
		length: u64,
		run: impl for<'stage> AsyncFnOnce(
			WindowsGuardedCaptureStage<'stage, A>,
			WindowsCaptureJournalSegment<'stage>,
			WindowsCaptureJournalAdmission<'stage, A>,
		) -> Result<T, E>,
	) -> Result<Result<T, E>, WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		let Self {
			stage,
			mut journal,
			name,
			admission,
		} = self;
		let descriptor = stage.prepare_capture(target, length)?;
		let journal_parent = &stage.bootstrap.records.journal;
		journal.eof().map_err(Failure::Custody)?;
		journal
			.check(journal_parent, name)
			.map_err(Failure::Custody)?;
		let custody = stage.capture_custody(target, &descriptor, || {
			admission
				.enter(WindowsCaptureEffect::CreateStageDirectory)
				.map_err(Failure::Admission)
		})?;
		let directory = custody.stage_directory()?;
		let writer = custody.create_payload(&directory, length, &descriptor, || {
			admission
				.enter(WindowsCaptureEffect::CreateStageFile {
					directory: custody.directory.binding.identity,
					length,
				})
				.map_err(Failure::Admission)
		})?;
		let leaf = custody.capture_leaf(writer.identity())?;
		let closed = Cell::new(false);
		let guarded = WindowsGuardedCaptureStage::new(
			WindowsCaptureStageWriter {
				custody: &custody,
				writer: Some(writer),
				leaf: &leaf,
			},
			admission,
			length,
			&closed,
		);
		let state = journal::AppendState::new();
		let segment_identity = journal.pin.binding.identity;
		let segment = WindowsCaptureJournalSegment::new(
			&mut journal,
			journal_parent,
			name,
			&state,
			&custody,
			&leaf,
		);
		let journal_admission = WindowsCaptureJournalAdmission::new(
			admission,
			&state,
			segment_identity,
			&custody,
			&leaf,
		);
		let result = run(guarded, segment, journal_admission).await;
		if result.is_ok() {
			if !closed.get() {
				return Err(Failure::Stage(
					crate::windows::WindowsStageError::Incomplete,
				));
			}
			state
				.finish(journal.pin.stamp.length)
				.map_err(Failure::CaptureJournal)?;
			custody.check_leaf(&leaf)?;
			journal.eof().map_err(Failure::Custody)?;
			journal
				.check(journal_parent, name)
				.map_err(Failure::Custody)?;
			custody.check_leaf(&leaf)?;
		}
		Ok(result)
	}
}

impl fmt::Debug for WindowsAuthenticatedCaptureScope<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsAuthenticatedCaptureScope")
			.finish_non_exhaustive()
	}
}

impl<A> fmt::Debug for WindowsPreparedCaptureScope<'_, '_, A> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsPreparedCaptureScope")
			.finish_non_exhaustive()
	}
}
