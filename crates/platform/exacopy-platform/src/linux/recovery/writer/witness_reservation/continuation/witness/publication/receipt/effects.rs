use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;

use rustix::fs;

use super::super::super::super::{append_held, observe_successor};
use super::native::{
	confirm_transition, exact_receipt, link_pending, pin_receipt_name, rename_pending,
	reopen_sealed, require_absent,
};
use super::{
	ActiveWitnessReservation, Effect, Error, Placement, ReservedJournalRead, SourceObservation,
	StageError, WitnessReceiptAppend, WitnessReceiptNames, WitnessReceiptPlan,
	WitnessReceiptRequest, admitted, preflight, request,
};
use crate::linux::WitnessReservationObservationError;

#[derive(Clone, Copy)]
pub(super) struct NamedReceipt<'a> {
	pub(super) names: &'a WitnessReceiptNames,
	pub(super) bytes: &'a [u8],
	pub(super) stamp: SourceObservation,
	pub(super) is_final: bool,
}

pub(super) fn prepare_pending<G, E>(
	active: &mut ActiveWitnessReservation<'_>,
	plan: &WitnessReceiptPlan,
	pin: &impl Fn() -> Result<[Option<File>; 3], StageError>,
	enter: &mut impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
	placement: &mut Placement,
) -> Result<SourceObservation, Error<E>> {
	let job = active.reservation.held.lease.job();
	let root = &job.directory.file;
	let mount = job.root.mount;
	let reserved = &active.reservation.receipt;
	let original = reserved.observation;

	active.check_active().map_err(Error::Preflight)?;
	require_absent(root, &plan.names).map_err(preflight)?;
	let _pins = pin().map_err(preflight)?;
	let effect = Effect::Write;
	let guard = admitted(request(active, &plan.names, &plan.append, effect), enter)?;
	let written = reserved.file().write_at(&plan.bytes, 0);
	drop(guard);
	let length = written.map_err(|cause| submitted(effect, StageError::System(cause)))?;
	if length != plan.bytes.len() {
		return Err(submitted(
			effect,
			StageError::System(io::ErrorKind::WriteZero.into()),
		));
	}

	active.check_active_journal().map_err(Error::Preflight)?;
	let written =
		exact_receipt(reserved.file(), original, &plan.bytes, 0, mount).map_err(readback)?;
	require_absent(root, &plan.names).map_err(preflight)?;
	let _pins = pin().map_err(preflight)?;
	let effect = Effect::AnonymousFileBarrier;
	let guard = admitted(request(active, &plan.names, &plan.append, effect), enter)?;
	let synced = fs::fsync(reserved.file());
	drop(guard);
	synced.map_err(|cause| submitted(effect, StageError::BarrierFailed(cause.into())))?;

	let _pins = pin().map_err(preflight)?;
	let (readonly, sealed) =
		reopen_sealed(reserved.file(), original, &plan.bytes, mount).map_err(readback)?;
	written
		.recheck(sealed)
		.map_err(|cause| readback(StageError::ReadBack(cause)))?;
	active.reservation.receipt.close_writer(readonly);
	let readonly = active.reservation.receipt.file();

	active.check_active_journal().map_err(Error::Preflight)?;
	let current = exact_receipt(readonly, sealed, &plan.bytes, 0, mount).map_err(readback)?;
	sealed
		.recheck(current)
		.map_err(|cause| readback(StageError::ReadBack(cause)))?;
	require_absent(root, &plan.names).map_err(preflight)?;
	let _pins = pin().map_err(preflight)?;
	let effect = Effect::LinkPending;
	let guard = admitted(request(active, &plan.names, &plan.append, effect), enter)?;
	*placement = Placement::PendingLinkSubmitted;
	let linked = link_pending(readonly, root, &plan.names);
	drop(guard);
	linked.map_err(|cause| submitted(effect, cause))?;
	*placement = Placement::PendingLinked;
	let pending = exact_receipt(readonly, sealed, &plan.bytes, 1, mount).map_err(readback)?;
	confirm_transition(sealed, pending).map_err(readback)?;
	let _alias = pin_receipt_name(root, mount, pending, &plan.names, false).map_err(readback)?;
	let _pins = pin().map_err(readback)?;
	Ok(pending)
}

pub(super) fn promote_pending<G, E>(
	active: &ActiveWitnessReservation<'_>,
	pending: NamedReceipt<'_>,
	append: &WitnessReceiptAppend,
	pin: &impl Fn() -> Result<[Option<File>; 3], StageError>,
	enter: &mut impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
	placement: &mut Placement,
) -> Result<SourceObservation, Error<E>> {
	let job = active.reservation.held.lease.job();
	let root = &job.directory.file;
	let mount = job.root.mount;
	let readonly = active.reservation.receipt.file();
	let _receipt = recheck_named(active, pending).map_err(Error::Preflight)?;
	let _pins = pin().map_err(preflight)?;
	let effect = Effect::Promote;
	let guard = admitted(request(active, pending.names, append, effect), enter)?;
	*placement = Placement::PromotionSubmitted;
	let promoted = rename_pending(root, pending.names);
	drop(guard);
	promoted.map_err(|cause| submitted(effect, cause))?;
	*placement = Placement::FinalRenamed;
	let final_stamp =
		exact_receipt(readonly, pending.stamp, pending.bytes, 1, mount).map_err(readback)?;
	confirm_transition(pending.stamp, final_stamp).map_err(readback)?;
	let _receipt =
		pin_receipt_name(root, mount, final_stamp, pending.names, true).map_err(readback)?;
	let _pins = pin().map_err(readback)?;
	Ok(final_stamp)
}

pub(super) fn recheck_named(
	active: &ActiveWitnessReservation<'_>,
	receipt: NamedReceipt<'_>,
) -> Result<File, WitnessReservationObservationError> {
	active.check_active_journal()?;
	let job = active.reservation.held.lease.job();
	confirm_named_receipt(
		&job.directory.file,
		job.root.mount,
		active.reservation.receipt.file(),
		receipt,
	)
}

pub(super) fn confirm_named_receipt(
	job: &File,
	mount: u64,
	file: &File,
	receipt: NamedReceipt<'_>,
) -> Result<File, WitnessReservationObservationError> {
	let current = exact_receipt(file, receipt.stamp, receipt.bytes, 1, mount)?;
	receipt
		.stamp
		.recheck(current)
		.map_err(StageError::ReadBack)?;
	let alias = pin_receipt_name(job, mount, receipt.stamp, receipt.names, receipt.is_final)?;
	receipt
		.stamp
		.recheck(super::native::capture(file)?)
		.map_err(StageError::ReadBack)?;
	Ok(alias)
}

pub(super) fn named_barriers<G, E>(
	active: &ActiveWitnessReservation<'_>,
	receipt: NamedReceipt<'_>,
	append: &WitnessReceiptAppend,
	pin: &impl Fn() -> Result<[Option<File>; 3], StageError>,
	enter: &mut impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
) -> Result<(), Error<E>> {
	let reservation = &active.reservation;
	let barriers = if receipt.is_final {
		[Effect::FinalFileBarrier, Effect::FinalJobBarrier]
	} else {
		[Effect::PendingFileBarrier, Effect::PendingJobBarrier]
	};
	for (effect, file) in barriers
		.into_iter()
		.zip([reservation.receipt.file(), &reservation.held.lease.lock])
	{
		let _alias = recheck_named(active, receipt).map_err(Error::Preflight)?;
		let _pins = pin().map_err(preflight)?;
		let guard = admitted(request(active, receipt.names, append, effect), enter)?;
		let synced = fs::fsync(file);
		drop(guard);
		synced.map_err(|cause| {
			let cause = cause.into();
			let cause = match effect {
				Effect::PendingFileBarrier | Effect::FinalFileBarrier => {
					StageError::BarrierFailed(cause)
				}
				_ => StageError::DirectoryBarrierFailed(cause),
			};
			submitted(effect, cause)
		})?;
	}
	Ok(())
}

pub(super) fn accept_frame<G, E>(
	active: &mut ActiveWitnessReservation<'_>,
	receipt: NamedReceipt<'_>,
	append: &WitnessReceiptAppend,
	pin: &impl Fn() -> Result<[Option<File>; 3], StageError>,
	enter: &mut impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
	verify: impl FnOnce(ReservedJournalRead<'_>, &WitnessReceiptAppend) -> Result<(), E>,
) -> Result<(), Error<E>> {
	let effect = if receipt.is_final {
		Effect::AppendCommitted
	} else {
		Effect::AppendReady
	};
	let _alias = recheck_named(active, receipt).map_err(Error::Preflight)?;
	let _pins = pin().map_err(preflight)?;
	let guard = admitted(request(active, receipt.names, append, effect), enter)?;
	let reservation = &mut active.reservation;
	append_held(&mut reservation.journal, &append.encoded, guard)
		.map_err(|cause| submitted(effect, StageError::System(cause)))?;
	reservation.readback = observe_successor(
		&reservation.journal,
		reservation.held.lease,
		&reservation.readback,
		append.previous.end,
		append.successor.end,
		&append.encoded,
	)
	.map_err(Error::Readback)?;
	verify(reservation.read_aperture(), append).map_err(Error::SuccessorReplay)?;
	let _alias = recheck_named(active, receipt).map_err(Error::Readback)?;
	let _pins = pin().map_err(readback)?;
	Ok(())
}

fn readback<E>(cause: StageError) -> Error<E> {
	Error::Readback(cause.into())
}

fn submitted<E>(effect: Effect, cause: StageError) -> Error<E> {
	Error::Submitted { effect, cause }
}
