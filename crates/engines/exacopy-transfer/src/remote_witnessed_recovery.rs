//! Exclusive restart sequencing for one recovered witnessed publication observation.

use std::io::Read;
use std::{error::Error, fmt};

use exacopy_content::{MeasureError, measure_at};
use exacopy_endpoint::ReadView;
use exacopy_journal::remote_download::qualification::continuation::CurrentRemoteWitnessQualification;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedCloseoutReplay, RemoteWitnessedPublicExpectation,
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadError};

use crate::remote_witnessed_finalization::WitnessedAppendError;

/// The restricted effects and observations of a newly acquired exclusive recovery lease.
///
/// The read view must retain the same public target throughout the operation, with its
/// original protected witness, exact target parent, job root and private stage directory
/// pinned on the same mount. The adapter supplies these current capabilities independently
/// of journal replay and of the earlier read-only inspection. It supplies no rename,
/// source, stage writer, receipt or subsequent durability operation.
pub trait HeldWitnessRecovery: ReadView {
	/// A fresh read aperture over the complete held first journal segment.
	type JournalRead<'held>: Read
	where
		Self: 'held;

	/// Opens an independent scan from byte zero and returns the separately observed logical EOF.
	///
	/// # Errors
	/// Refuses a lost lease, changed segment binding or unconfirmed exact EOF.
	fn read_journal(&self) -> Result<(Self::JournalRead<'_>, u64), Self::Error>;

	/// Confirms the completed scan still names the unchanged held segment at the exact EOF.
	///
	/// # Errors
	/// Refuses a changed journal observation, segment name, logical EOF or exclusive lease.
	fn recheck_journal(&self, expected: RemoteReplayBoundary) -> Result<(), Self::Error>;

	/// Checks the complete published namespace and metadata on the held public read view.
	///
	/// Require the exact original inode at both held names simultaneously, exactly two links,
	/// continuous witness protection, absence of the old private name, exact file extent and
	/// EOF, and the selected mode, UID, GID and empty visible attributes and ACLs.
	///
	/// # Errors
	/// Refuses any missing, changed or unconfirmed held fact.
	fn check_public(
		&self,
		expected: &RemoteWitnessedPublicExpectation<'_>,
	) -> Result<(), Self::Error>;

	/// Submits one exact recovered observation and synchronizes the held journal segment.
	///
	/// Finish other fallible preparation before the final gate. Recheck the selected OP2 facts,
	/// same held lease and clean kind-7 EOF/head, exact public custody and unchanged read-back
	/// observation, and capacity for this exact frame. Acquire the current base-grant guard and
	/// the independently admitted live retention-approval guard matching the signed commitment.
	/// Submit immediately while holding both. Success requires a barrier and exact native
	/// read-back of the appended frame and resulting logical EOF.
	///
	/// # Errors
	/// A definite refusal means submission never began. Changed or uncertain custody requires
	/// reconciliation. A possibly started append poisons the native appender on failure.
	fn append_recovered_observation(
		&mut self,
		cut: WitnessedRecoveryCut<'_, '_, '_>,
	) -> Result<(), WitnessedAppendError<Self::Error>>;
}

/// A clean kind-7 cut whose public bytes and metadata were independently checked.
///
/// Only the coordinator can construct this value. The adapter must still complete its
/// final current-authority and custody checks before submitting the prepared frame.
#[derive(Debug)]
pub struct WitnessedRecoveryCut<'cut, 'history, 'facts> {
	current: &'cut CurrentRemoteWitnessQualification<'facts>,
	expected: &'cut RemoteWitnessedPublicExpectation<'history>,
	frame: &'cut PreparedWitnessedCloseout,
}

impl<'history, 'facts> WitnessedRecoveryCut<'_, 'history, 'facts> {
	/// Returns the current qualification selected independently of the journal.
	pub const fn current(&self) -> &CurrentRemoteWitnessQualification<'facts> {
		self.current
	}

	/// Returns the exact authenticated cut and public object expectations.
	pub const fn expected(&self) -> &RemoteWitnessedPublicExpectation<'history> {
		self.expected
	}

	/// Returns the exact canonical frame bound to this verified cut.
	pub const fn frame(&self) -> &PreparedWitnessedCloseout {
		self.frame
	}
}

/// Independent inputs for a newly entered witnessed restart.
pub struct WitnessedRecoveryRequest<'scope, 'history> {
	/// Expected owner and signed destination scope.
	pub trust: &'scope RemoteBootstrapTrust<'history>,
	/// Independent historical selections for the full witnessed replay.
	pub selection: &'scope RemoteWitnessedReplaySelection<'history>,
	/// Selected OP2 qualification matched to independently observed current facts.
	pub current: &'scope CurrentRemoteWitnessQualification<'history>,
}

/// The stopped restart and its last independently confirmed replay boundary.
#[derive(Debug)]
pub struct WitnessedRecoveryFailure<E> {
	/// Last exact clean kind-7 cut, where one was confirmed. Later bytes may exist.
	pub confirmed: Option<RemoteReplayBoundary>,
	/// First failed check, observation, record construction or append.
	pub cause: WitnessedRecoveryCause<E>,
}

/// Why the restart could not confirm an exact recovered kind-8 successor.
#[derive(Debug)]
#[non_exhaustive]
pub enum WitnessedRecoveryCause<E> {
	/// Selected qualification, phase, exact boundary or successor disagreed.
	Binding,
	/// A held observation or journal read aperture could not be confirmed.
	Native(E),
	/// Complete independent public-file measurement failed.
	ReadBack(MeasureError<E>),
	/// The held public extent or digest disagreed with authenticated expectations.
	Verification,
	/// Canonical replay or record construction refused the selected input.
	Format(RemoteDownloadError),
	/// The one recovered observation submission failed.
	Append(WitnessedAppendError<E>),
}

impl<E: fmt::Display> fmt::Display for WitnessedRecoveryFailure<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match &self.cause {
			WitnessedRecoveryCause::Binding => {
				formatter.write_str("witnessed restart binding could not be confirmed")
			}
			WitnessedRecoveryCause::Native(cause) => {
				write!(
					formatter,
					"could not confirm held witnessed restart evidence ({cause})"
				)
			}
			WitnessedRecoveryCause::ReadBack(cause) => cause.fmt(formatter),
			WitnessedRecoveryCause::Verification => {
				formatter.write_str("witnessed restart public verification disagreed")
			}
			WitnessedRecoveryCause::Format(cause) => cause.fmt(formatter),
			WitnessedRecoveryCause::Append(WitnessedAppendError::Refused(cause)) => {
				write!(
					formatter,
					"recovered observation append was refused ({cause})"
				)
			}
			WitnessedRecoveryCause::Append(WitnessedAppendError::Unconfirmed(cause)) => {
				write!(
					formatter,
					"recovered observation custody became unconfirmed ({cause})"
				)
			}
			WitnessedRecoveryCause::Append(WitnessedAppendError::Uncertain(cause)) => {
				write!(
					formatter,
					"recovered observation append is uncertain ({cause})"
				)
			}
		}
	}
}

impl<E: Error + 'static> Error for WitnessedRecoveryFailure<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match &self.cause {
			WitnessedRecoveryCause::Binding | WitnessedRecoveryCause::Verification => None,
			WitnessedRecoveryCause::Native(cause)
			| WitnessedRecoveryCause::Append(
				WitnessedAppendError::Refused(cause)
				| WitnessedAppendError::Unconfirmed(cause)
				| WitnessedAppendError::Uncertain(cause),
			) => Some(cause),
			WitnessedRecoveryCause::ReadBack(cause) => Some(cause),
			WitnessedRecoveryCause::Format(cause) => Some(cause),
		}
	}
}

/// Records and independently confirms one recovered kind 8 from the exact held kind 7.
///
/// Consumes the exclusive holder on every path. The result confirms the exact journal
/// successor only. Any later durability or receipt operation requires separate admission.
///
/// # Errors
/// Stops for reconciliation on refusal, uncertainty or an unconfirmed successor.
pub fn record_recovered_witness_observation<H: HeldWitnessRecovery>(
	request: WitnessedRecoveryRequest<'_, '_>,
	mut held: H,
	scratch: &mut [u8],
) -> Result<RemoteReplayBoundary, WitnessedRecoveryFailure<H::Error>> {
	use WitnessedRecoveryCause as Cause;

	let before = |cause| WitnessedRecoveryFailure {
		confirmed: None,
		cause,
	};
	if !std::ptr::eq(request.selection.qualification, request.current.verified()) {
		return Err(before(Cause::Binding));
	}
	let replay = scan(&request, &held).map_err(before)?;
	let expected = replay
		.publish_intent_inspection()
		.map_err(|cause| before(Cause::Format(cause)))?;
	let after = |cause| WitnessedRecoveryFailure {
		confirmed: Some(expected.boundary()),
		cause,
	};

	let ids = request.current.facts().ids();
	let metadata = expected.metadata();
	if (metadata.uid, metadata.gid) != (ids.effective_uid, ids.effective_gid) {
		return Err(after(Cause::Binding));
	}
	verify_public(&held, &expected, scratch).map_err(after)?;
	let witness = expected.witness();
	let target = expected.stage().file;
	let frame = replay
		.prepare_recovered_observation(request.trust, witness, target)
		.map_err(|cause| after(Cause::Format(cause)))?;

	let cut = WitnessedRecoveryCut {
		current: request.current,
		expected: &expected,
		frame: &frame,
	};
	held.append_recovered_observation(cut)
		.map_err(|cause| after(Cause::Append(cause)))?;
	let observed = scan(&request, &held).map_err(after)?;
	if !frame.confirms_recovered_observation(&observed, witness, target) {
		return Err(after(Cause::Binding));
	}
	Ok(observed.boundary())
}

fn verify_public<H: HeldWitnessRecovery>(
	held: &H,
	expected: &RemoteWitnessedPublicExpectation<'_>,
	scratch: &mut [u8],
) -> Result<(), WitnessedRecoveryCause<H::Error>> {
	use WitnessedRecoveryCause as Cause;

	held.check_public(expected).map_err(Cause::Native)?;
	held.recheck_observation().map_err(Cause::Native)?;
	let length = expected.extent().get();
	if held.length() != length {
		return Err(Cause::Verification);
	}
	let measured = measure_at(length, scratch, |offset, bytes| {
		held.read_exact_at(offset, bytes)
	})
	.map_err(Cause::ReadBack)?;
	held.recheck_observation().map_err(Cause::Native)?;
	held.check_public(expected).map_err(Cause::Native)?;
	if measured.as_bytes() != expected.stage_digest().as_bytes() {
		return Err(Cause::Verification);
	}
	Ok(())
}

fn scan<H: HeldWitnessRecovery>(
	request: &WitnessedRecoveryRequest<'_, '_>,
	held: &H,
) -> Result<RemoteWitnessedCloseoutReplay, WitnessedRecoveryCause<H::Error>> {
	use WitnessedRecoveryCause as Cause;

	let (input, end) = held.read_journal().map_err(Cause::Native)?;
	let replay = replay_remote_witnessed_closeout(input, request.trust, request.selection)
		.map_err(Cause::Format)?;
	if replay.issue().is_some() || replay.boundary().offset != end {
		return Err(Cause::Binding);
	}
	held.recheck_journal(replay.boundary())
		.map_err(Cause::Native)?;
	Ok(replay)
}
