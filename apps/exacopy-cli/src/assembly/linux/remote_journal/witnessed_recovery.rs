//! Test-gated Linux SDK for recording one recovered selector-2 observation.

use std::fmt;

use exacopy_endpoint::ReadView;
use exacopy_journal::JournalJobId;
use exacopy_journal::remote_download::RemoteDownloadScope;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedPublicExpectation, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_model::retained_prefix::Head;
use exacopy_platform::linux::{
	DestinationRoot, ReadError, RecoveredWitnessJournal, RecoveredWitnessJournalError,
	ReservedJournalRead, StageError, WitnessObservationAppend, WitnessedPublicPins,
	WitnessedPublicSelection,
};
use exacopy_transfer::remote_witnessed_finalization::WitnessedAppendError;
use exacopy_transfer::remote_witnessed_recovery::{
	HeldWitnessRecovery, WitnessedRecoveryCut, WitnessedRecoveryFailure, WitnessedRecoveryRequest,
	record_recovered_witness_observation,
};

use crate::profile::LocalProfile;

use super::admission::OwnerDialect;
use super::lease::{check_root, read_owner};
use super::witnessed_inspection::{WitnessedInspectionError, intent_history, public_selection};
use super::{Error, component, job_name, record_identity};

mod authority;

use authority::CurrentRecoveryAuthority;
pub(in crate::assembly::linux) use authority::{AuthorityError, RecoveryApproval};

/// Independent selections for one destination-local restart.
pub(in crate::assembly::linux) struct RecoverWitnessedObservation<'scope, 'history> {
	pub(in crate::assembly::linux) root: &'scope DestinationRoot,
	pub(in crate::assembly::linux) profile: &'scope LocalProfile,
	pub(in crate::assembly::linux) job: JournalJobId,
	pub(in crate::assembly::linux) scope: &'scope RemoteDownloadScope,
	pub(in crate::assembly::linux) selection: &'scope RemoteWitnessedReplaySelection<'history>,
	pub(in crate::assembly::linux) approval: &'scope RecoveryApproval<'scope>,
}

#[derive(Debug)]
pub(in crate::assembly::linux) enum RecoverWitnessedObservationError {
	Job(Error),
	Authority(AuthorityError),
	History(WitnessedInspectionError),
	Recovery(WitnessedRecoveryFailure<RecoveryAdapterError>),
}

impl From<Error> for RecoverWitnessedObservationError {
	fn from(error: Error) -> Self {
		Self::Job(error)
	}
}

impl From<StageError> for RecoverWitnessedObservationError {
	fn from(error: StageError) -> Self {
		Self::Job(Error::from(error))
	}
}

impl RecoverWitnessedObservation<'_, '_> {
	/// Records only the canonical recovered observation and returns its confirmed head.
	///
	/// The application supplies fresh approval for the exact original kind-7
	/// boundary. Repeat calls must reconcile from the current authoritative
	/// history. No file, namespace or subsequent durability authority escapes.
	///
	/// # Errors
	/// Rejects incompatible authority or history and preserves uncertain append evidence.
	pub(in crate::assembly::linux) fn record(
		self,
		scratch: &mut [u8],
	) -> Result<RemoteReplayBoundary, RecoverWitnessedObservationError> {
		let dialect =
			OwnerDialect::select(self.scope.source.route(), self.scope.source.path_root())?;
		let key = self.profile.verification_key();
		if !self.selection.qualification.matches_owner(&key) {
			return Err(Error::Binding.into());
		}
		let name = job_name(self.job);
		check_root(self.root, self.profile, self.scope, name.as_bytes())?;
		let name = component(name.as_bytes())?;
		let observed = self.root.open_recovery_job(name)?;
		let lease = self
			.root
			.try_recovery_write_lease(name, observed.identity())?;
		observed.recheck()?;

		let journal = lease.hold_recovered_witness_journal()?;
		let owner = read_owner(journal.owner(), self.profile, dialect)?;
		let manifest = owner.manifest();
		if manifest.job != self.job
			|| manifest.job_directory != record_identity(lease.job().identity())
			|| &manifest.scope != self.scope
		{
			return Err(Error::Binding.into());
		}
		let trust = dialect.trust(&owner, self.profile.id(), &key)?;
		let authority = self
			.approval
			.bind(self.root, &owner, &key, self.scope, self.selection)
			.map_err(RecoverWitnessedObservationError::Authority)?;
		let current = authority
			.current()
			.map_err(RecoverWitnessedObservationError::Authority)?;
		let (input, end) = journal.journal()?;
		let replay =
			replay_remote_witnessed_closeout(input, &trust, self.selection).map_err(Error::from)?;
		let expected =
			intent_history(&replay, end).map_err(RecoverWitnessedObservationError::History)?;
		if expected.boundary() != self.approval.intent()
			|| expected.destination() != &self.scope.destination
		{
			return Err(Error::Binding.into());
		}
		journal.recheck(end)?;
		let selected = WitnessedPublicSelection::from(public_selection(&expected)?);
		let pins = lease.hold_witnessed_public(selected)?;
		let held = HeldRecovery {
			journal,
			pins,
			selected,
			intent: expected.boundary(),
			authority: &authority,
		};
		record_recovered_witness_observation(
			WitnessedRecoveryRequest {
				trust: &trust,
				selection: self.selection,
				current: &current,
			},
			held,
			scratch,
		)
		.map_err(RecoverWitnessedObservationError::Recovery)
	}
}

struct HeldRecovery<'lease, 'name, 'authority, 'scope> {
	journal: RecoveredWitnessJournal<'lease>,
	pins: WitnessedPublicPins<'lease, 'name>,
	selected: WitnessedPublicSelection<'name>,
	intent: RemoteReplayBoundary,
	authority: &'authority CurrentRecoveryAuthority<'scope>,
}

#[derive(Debug)]
pub(in crate::assembly::linux) enum RecoveryAdapterError {
	Binding,
	Native(StageError),
	Read(ReadError),
	Authority(AuthorityError),
}

impl fmt::Display for RecoveryAdapterError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Binding => formatter.write_str("native recovered observation binding disagrees"),
			Self::Native(cause) => fmt::Display::fmt(cause, formatter),
			Self::Read(cause) => fmt::Display::fmt(cause, formatter),
			Self::Authority(cause) => fmt::Display::fmt(cause, formatter),
		}
	}
}

impl std::error::Error for RecoveryAdapterError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Binding => None,
			Self::Native(cause) => Some(cause),
			Self::Read(cause) => Some(cause),
			Self::Authority(cause) => Some(cause),
		}
	}
}

impl ReadView for HeldRecovery<'_, '_, '_, '_> {
	type Error = RecoveryAdapterError;

	fn length(&self) -> u64 {
		self.pins.target().len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.pins.recheck().map_err(RecoveryAdapterError::Native)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.pins
			.target()
			.read_exact_at(offset, bytes)
			.map_err(RecoveryAdapterError::Read)
	}
}

impl HeldWitnessRecovery for HeldRecovery<'_, '_, '_, '_> {
	type JournalRead<'held>
		= ReservedJournalRead<'held>
	where
		Self: 'held;

	fn read_journal(&self) -> Result<(Self::JournalRead<'_>, u64), Self::Error> {
		self.journal.journal().map_err(RecoveryAdapterError::Native)
	}

	fn recheck_journal(&self, expected: RemoteReplayBoundary) -> Result<(), Self::Error> {
		self.journal
			.recheck(expected.offset)
			.map_err(RecoveryAdapterError::Native)?;
		self.pins.recheck().map_err(RecoveryAdapterError::Native)
	}

	fn check_public(
		&self,
		expected: &RemoteWitnessedPublicExpectation<'_>,
	) -> Result<(), Self::Error> {
		let selected = public_selection(expected).map_err(|_| RecoveryAdapterError::Binding)?;
		if expected.boundary() != self.intent
			|| WitnessedPublicSelection::from(selected) != self.selected
		{
			return Err(RecoveryAdapterError::Binding);
		}
		self.pins.recheck().map_err(RecoveryAdapterError::Native)
	}

	fn append_recovered_observation(
		&mut self,
		cut: WitnessedRecoveryCut<'_, '_, '_>,
	) -> Result<(), WitnessedAppendError<Self::Error>> {
		self.check_public(cut.expected())
			.map_err(WitnessedAppendError::Unconfirmed)?;
		let frame = cut.frame();
		if frame.previous() != self.intent {
			return Err(WitnessedAppendError::Refused(RecoveryAdapterError::Binding));
		}
		let proposed = WitnessObservationAppend {
			previous: model_head(frame.previous()),
			successor: model_head(frame.successor()),
			encoded: frame.encoded().to_vec(),
		};
		let authority = self.authority;
		self.journal
			.append_recovered_observation(
				&self.pins,
				proposed,
				|| authority.enter(cut.expected()),
				|guard| guard.confirm(),
			)
			.map_err(|error| match error {
				RecoveredWitnessJournalError::Preflight(error) => {
					WitnessedAppendError::Unconfirmed(RecoveryAdapterError::Native(error))
				}
				RecoveredWitnessJournalError::Bounds => {
					WitnessedAppendError::Refused(RecoveryAdapterError::Binding)
				}
				RecoveredWitnessJournalError::Gate(error) => {
					WitnessedAppendError::Refused(RecoveryAdapterError::Authority(error))
				}
				RecoveredWitnessJournalError::Submitted(error) => WitnessedAppendError::Uncertain(
					RecoveryAdapterError::Native(StageError::System(error)),
				),
				RecoveredWitnessJournalError::Readback(error) => {
					WitnessedAppendError::Uncertain(RecoveryAdapterError::Native(error))
				}
			})
	}
}

fn model_head(boundary: RemoteReplayBoundary) -> Head {
	Head {
		digest: boundary.head.digest(),
		sequence: boundary.head.sequence(),
		end: boundary.offset,
	}
}
