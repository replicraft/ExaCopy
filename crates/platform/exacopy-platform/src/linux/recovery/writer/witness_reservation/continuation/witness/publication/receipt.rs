use exacopy_model::retained_prefix::Head;

use super::super::super::super::native::RECEIPT_CAPACITY;
use super::super::super::ActiveWitnessReservation;
use super::{ReservedJournalRead, WitnessPublication, WitnessPublicationObservation};
use crate::linux::recovery::witnessed_names::matches_names;
use crate::linux::{SourceObservation, StageError, WitnessReservationPlan};

mod native;
mod types;

use WitnessReceiptEffect as Effect;
use WitnessReceiptError as Error;
use WitnessReceiptPlacement as Placement;
pub use types::{
	WitnessReceiptAppend, WitnessReceiptEffect, WitnessReceiptError, WitnessReceiptIdentity,
	WitnessReceiptNames, WitnessReceiptPlacement, WitnessReceiptPlan, WitnessReceiptRequest,
};

const FRAME_OVERHEAD: usize = 92;
const MAX_READY: usize = 689 + FRAME_OVERHEAD;
const MAX_COMMITTED: usize = 455 + FRAME_OVERHEAD;

#[derive(Default)]
pub(super) struct Progress {
	ready_spent: bool,
	commit_spent: bool,
	ready: Option<Ready>,
	committed: Option<Head>,
	placement: Placement,
}

struct Ready {
	head: Head,
	names: WitnessReceiptNames,
	bytes: Vec<u8>,
	stamp: SourceObservation,
}

impl WitnessPublication<'_, '_> {
	/// Returns the last independently confirmed kind-42 boundary from this holder.
	#[must_use]
	pub const fn receipt_ready_head(&self) -> Option<Head> {
		match &self.receipt.ready {
			Some(ready) => Some(ready.head),
			None => None,
		}
	}

	/// Returns the independently confirmed live kind-18 boundary.
	#[must_use]
	pub const fn receipt_committed_head(&self) -> Option<Head> {
		self.receipt.committed
	}

	/// Returns the strongest observed result of a live receipt namespace call.
	#[must_use]
	pub const fn receipt_placement(&self) -> WitnessReceiptPlacement {
		self.receipt.placement
	}

	/// Writes and seals the initially anonymous reservation, then records kind 42.
	///
	/// The trusted application derives canonical receipt bytes, names and the
	/// proposed frame from the exact held kind 9 and native identity. It performs
	/// full prospective and actual replay independently. Each effect takes a
	/// fresh exact current guard after native probes. The guard performs no I/O,
	/// await, credential change or lease reentry.
	///
	/// # Errors
	/// The first attempt spends this holder's transition. Native failures and
	/// refused replay or admission preserve the publication and receipt custody.
	pub fn record_receipt_ready<G, E>(
		&mut self,
		expected_kind9: Head,
		build: impl FnOnce(
			WitnessReceiptIdentity,
			ReservedJournalRead<'_>,
		) -> Result<WitnessReceiptPlan, E>,
		verify_proposed: impl FnOnce(ReservedJournalRead<'_>, &WitnessReceiptAppend) -> Result<(), E>,
		mut enter: impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>, &WitnessReceiptAppend) -> Result<(), E>,
	) -> Result<Head, WitnessReceiptError<E>> {
		if std::mem::replace(&mut self.receipt.ready_spent, true)
			|| self.durability_head() != Some(expected_kind9)
			|| self.held.active.head() != expected_kind9
		{
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		}
		let WitnessPublicationObservation::Published(published) = self.observation else {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		};
		let names = self.held.stage.held_names().map_err(preflight)?;
		let pin = || names.pin_published(published);
		let active = &mut self.held.active;
		let result = (|| {
			active.check_active().map_err(Error::Preflight)?;
			let _pins = pin().map_err(preflight)?;
			let identity = identities(active);
			let plan =
				build(identity, active.reservation.read_aperture()).map_err(Error::PriorReplay)?;
			if plan.bytes.is_empty()
				|| plan.bytes.len() as u64 > RECEIPT_CAPACITY
				|| !matches_names(&plan.names, self.held.stage.witness_name())
				|| !matches_bounds(active.plan(), expected_kind9, &plan.append, true)
			{
				return Err(Error::Bounds);
			}
			active.check_active().map_err(Error::Preflight)?;
			verify_proposed(active.reservation.read_aperture(), &plan.append)
				.map_err(Error::ProposedReplay)?;
			let stamp =
				prepare_pending(active, &plan, &pin, &mut enter, &mut self.receipt.placement)?;
			let pending = NamedReceipt {
				names: &plan.names,
				bytes: &plan.bytes,
				stamp,
				is_final: false,
			};
			named_barriers(active, pending, &plan.append, &pin, &mut enter)?;
			accept_frame(
				active,
				pending,
				&plan.append,
				&pin,
				&mut enter,
				verify_successor,
			)?;
			Ok(Ready {
				head: plan.append.successor,
				names: plan.names,
				bytes: plan.bytes,
				stamp,
			})
		})();
		match result {
			Ok(ready) => {
				let head = ready.head;
				active.head = head;
				self.receipt.ready = Some(ready);
				Ok(head)
			}
			Err(error) => {
				active.stop();
				Err(error)
			}
		}
	}

	/// Promotes the exact sealed pending receipt once, then records kind 18.
	///
	/// The builder receives the actual held kind-42 journal. Fresh live
	/// admission guards the no-replace rename and each later barrier and append.
	/// The trusted replay callbacks check the full prospective and actual history.
	///
	/// # Errors
	/// The first attempt spends promotion. Preserve the original publication,
	/// actual reported namespace result and durable knowledge on any failure.
	pub fn commit_receipt<G, E>(
		&mut self,
		expected_kind42: Head,
		build: impl FnOnce(ReservedJournalRead<'_>) -> Result<WitnessReceiptAppend, E>,
		verify_proposed: impl FnOnce(ReservedJournalRead<'_>, &WitnessReceiptAppend) -> Result<(), E>,
		mut enter: impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>, &WitnessReceiptAppend) -> Result<(), E>,
	) -> Result<Head, WitnessReceiptError<E>> {
		if std::mem::replace(&mut self.receipt.commit_spent, true)
			|| self.receipt_ready_head() != Some(expected_kind42)
			|| self.held.active.head() != expected_kind42
		{
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		}
		let (Some(ready), WitnessPublicationObservation::Published(published)) =
			(&self.receipt.ready, &self.observation)
		else {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		};
		let names = self.held.stage.held_names().map_err(preflight)?;
		let pin = || names.pin_published(*published);
		let active = &mut self.held.active;
		let result = (|| {
			let pending = NamedReceipt {
				names: &ready.names,
				bytes: &ready.bytes,
				stamp: ready.stamp,
				is_final: false,
			};
			let _receipt = recheck_named(active, pending).map_err(Error::Preflight)?;
			let _pins = pin().map_err(preflight)?;
			let append = build(active.reservation.read_aperture()).map_err(Error::PriorReplay)?;
			if !matches_bounds(active.plan(), expected_kind42, &append, false) {
				return Err(Error::Bounds);
			}
			active.check_active_journal().map_err(Error::Preflight)?;
			verify_proposed(active.reservation.read_aperture(), &append)
				.map_err(Error::ProposedReplay)?;
			let stamp = promote_pending(
				active,
				pending,
				&append,
				&pin,
				&mut enter,
				&mut self.receipt.placement,
			)?;
			let final_receipt = NamedReceipt {
				stamp,
				is_final: true,
				..pending
			};
			named_barriers(active, final_receipt, &append, &pin, &mut enter)?;
			accept_frame(
				active,
				final_receipt,
				&append,
				&pin,
				&mut enter,
				verify_successor,
			)?;
			Ok(append.successor)
		})();
		match result {
			Ok(head) => {
				active.head = head;
				self.receipt.committed = Some(head);
				Ok(head)
			}
			Err(error) => {
				active.stop();
				Err(error)
			}
		}
	}
}

fn identities(active: &ActiveWitnessReservation<'_>) -> WitnessReceiptIdentity {
	let reservation = &active.reservation;
	let job = reservation.held.lease.job();
	WitnessReceiptIdentity {
		receipt: reservation.receipt.observation.identity(),
		job: job.identity(),
		destination: job.destination_identity(),
	}
}

fn request<'name>(
	active: &'name ActiveWitnessReservation<'_>,
	names: &'name WitnessReceiptNames,
	append: &WitnessReceiptAppend,
	effect: Effect,
) -> WitnessReceiptRequest<'name> {
	WitnessReceiptRequest {
		effect,
		previous: append.previous,
		successor: append.successor,
		stage: active.reservation.held.stage.selection(),
		identity: identities(active),
		names,
		authority: active.reservation.authority,
	}
}

fn preflight<E>(cause: StageError) -> Error<E> {
	Error::Preflight(cause.into())
}

fn admitted<G, E>(
	request: WitnessReceiptRequest<'_>,
	enter: &mut impl FnMut(WitnessReceiptRequest<'_>) -> Result<G, E>,
) -> Result<G, Error<E>> {
	enter(request).map_err(|cause| Error::Admission {
		effect: request.effect,
		cause,
	})
}

fn matches_bounds(
	plan: WitnessReservationPlan,
	previous: Head,
	append: &WitnessReceiptAppend,
	ready: bool,
) -> bool {
	let Ok(width) = u64::try_from(append.encoded.len()) else {
		return false;
	};
	let next = append.successor;
	let (current_max, following_max, following_slots) = if ready {
		(MAX_READY, MAX_COMMITTED as u64, 1)
	} else {
		(MAX_COMMITTED, 0, 0)
	};
	let last = plan.accepted().sequence + plan.reserve_frames().get();
	append.previous == previous
		&& append.encoded.len() > FRAME_OVERHEAD
		&& append.encoded.len() <= current_max
		&& previous.end.checked_add(width) == Some(next.end)
		&& previous.sequence.checked_add(1) == Some(next.sequence)
		&& next.digest != [0; 32]
		&& next.digest != previous.digest
		&& next
			.end
			.checked_add(following_max)
			.is_some_and(|end| end <= plan.reserve_end())
		&& next
			.sequence
			.checked_add(following_slots)
			.is_some_and(|sequence| sequence <= last)
}

mod effects;
use effects::{
	NamedReceipt, accept_frame, named_barriers, prepare_pending, promote_pending, recheck_named,
};

#[cfg(test)]
mod tests;
