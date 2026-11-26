//! Pure ordering and range decisions for a retained private stage.

use core::num::NonZeroU64;

use crate::checked_range_end;

mod budget;

use budget::ReservedCheckpoint;
pub use budget::{BudgetReservation, Head};

const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SIGNED_EXTENT: u64 = i64::MAX as u64;
/// Opaque checked native and authorization identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guard {
	/// Binds job, owner, entry, signed scope, current grant and qualification.
	pub authority: [u8; 32],
	/// Binds the exact held local root, directory, raw name and physical file.
	pub stage: [u8; 32],
	/// Binds the current, independently revalidated exclusive writer lease.
	pub lease: [u8; 32],
}

/// Run and source labels consumed by an admitted capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pass {
	/// Allocation or continuation number.
	pub run: NonZeroU64,
	/// Label of the held source view.
	pub source: NonZeroU64,
}

/// Classification of the historical capture boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum History {
	/// Complete replay of the current unsealed, unambiguous capture.
	CleanCapture,
	/// A missing, unclear or unconfirmed effect.
	Uncertain,
	/// Publication intent already exists or could have been written.
	PostIntent,
}

/// Selected historical proof under the current lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prior {
	/// Revalidated scope and current held capability identities.
	pub guard: Guard,
	/// Exact latest clean consumed boundary.
	pub head: Head,
	/// Exact original preparation for this physical stage.
	pub preparation: Head,
	/// Historical run and source labels.
	pub pass: Pass,
	/// Exclusive end of positive contiguous historical checkpoint coverage.
	pub checkpoint_end: u64,
	/// Exact source extent admitted by the old writer's allocation.
	pub authorized_end: u64,
	/// Exact replay disposition.
	pub history: History,
	/// Confirmed old writer retirement and quiescence.
	pub writer_quiesced: bool,
}

/// Caller-supplied results of the fresh, complete retained-prefix proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixProof {
	/// The current held stage extent.
	pub local_end: u64,
	/// Exclusive end of exact independent comparison of fresh source and local bytes from zero.
	pub compared_end: u64,
	/// Exclusive end of independently recomputed matching historical checkpoint hashes.
	pub rehashed_end: u64,
	/// Aggregate digest of all compared prefix bytes.
	pub digest: [u8; 32],
}

/// Exact fields selected for the continuation record and data barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Basis {
	prior: Prior,
	pass: Pass,
	proof: PrefixProof,
	source_len: u64,
}

impl Basis {
	/// Returns the original held context and replay evidence.
	pub const fn prior(self) -> Prior {
		self.prior
	}

	/// Returns the fresh run and source labels.
	pub const fn pass(self) -> Pass {
		self.pass
	}

	/// Returns compared prefix proof and adopted end.
	pub const fn prefix(self) -> PrefixProof {
		self.proof
	}

	/// Returns the exact fresh source extent.
	pub const fn source_len(self) -> u64 {
		self.source_len
	}
}

/// Fresh caller observation at one operation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Live {
	/// Same rechecked held identities and current authorization.
	pub guard: Guard,
	/// Exact current committed journal boundary.
	pub head: Head,
	/// Freshly observed source epoch.
	pub source: NonZeroU64,
	/// Actual extent of the currently held private file.
	pub local_end: u64,
}

/// Model refusal. An indeterminate effect must enter reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
	/// Prior history is ambiguous, sealed by intent or still has a live writer.
	History,
	/// Run succession or fresh-source ordering failed.
	Pass,
	/// Prefix verification is incomplete, inconsistent or exceeds source length.
	Prefix,
	/// The stage, lease, authority, journal head or fresh source changed.
	Binding,
	/// The asserted barrier or durable continuation did not match the exact basis.
	Evidence,
	/// The operation is too early, blocked, or another tail write is outstanding.
	Order,
	/// The requested window would overwrite the prefix, leave a hole or exceed the extent.
	Range,
	/// The next checkpoint or closure lacks a matching bounded reservation.
	Budget,
	/// The reported completion does not match the outstanding permit.
	Completion,
}

/// One issued tail range, bound to its exact continuation and source epoch.
#[derive(Debug, PartialEq, Eq)]
pub struct TailWrite {
	live: Live,
	start: u64,
	end: u64,
}

impl TailWrite {
	/// Returns the admitted half-open tail range.
	pub const fn range(&self) -> core::ops::Range<u64> {
		self.start..self.end
	}
}

/// Confirmed and independently reread checkpoint for the last completed tail range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
	/// First synced continuation head for this pass.
	pub lineage: Head,
	/// Exact predecessor of the checkpoint frame.
	pub predecessor: Head,
	/// One-based checkpoint ordinal under the current continuation head.
	pub ordinal: u16,
	/// Synced checkpoint frame boundary.
	pub head: Head,
	/// Exact continuing run/source labels.
	pub pass: Pass,
	/// Current scope, stage identity and lease.
	pub guard: Guard,
	/// Start of the verified increment.
	pub start: u64,
	/// Verified exclusive end of the completed increment.
	pub end: u64,
}

#[derive(Debug)]
enum Phase {
	Compared,
	Barrier,
	Continued {
		lineage: Head,
		head: Head,
		checkpoint_end: u64,
		cursor: u64,
		pending: Option<u64>,
		ordinal: u16,
		reserved: Option<ReservedCheckpoint>,
	},
	Blocked,
}

/// Serialized model for one exact continuation on an exclusively held stage.
///
/// Caller keeps a single live coordinator under the identified lease,
/// supplies truthful held observations, drains the old writer, verifies
/// all prefix/checkpoint bytes and rechecks the source around effects.
/// The model has no I/O and the permit carries no operating-system rights.
#[derive(Debug)]
pub struct Continuation {
	basis: Basis,
	phase: Phase,
}

impl Continuation {
	/// Admits fresh matching prefix evidence under a clean prior boundary.
	///
	/// # Errors
	/// Refuses ambiguous history, a live old writer, stale labels or incomplete proof.
	pub fn begin(
		prior: Prior,
		pass: Pass,
		proof: PrefixProof,
		source_len: u64,
	) -> Result<Self, Refusal> {
		if prior.history != History::CleanCapture || !prior.writer_quiesced {
			return Err(Refusal::History);
		}
		if prior.pass.run.get().checked_add(1) != Some(pass.run.get())
			|| pass.source <= prior.pass.source
		{
			return Err(Refusal::Pass);
		}
		if prior.checkpoint_end == 0
			|| proof.rehashed_end != prior.checkpoint_end
			|| proof.compared_end != proof.local_end
			|| !matches!(proof.compared_end.checked_sub(proof.rehashed_end),
					Some(extra) if extra <= MAX_CHECKPOINT_BYTES)
			|| proof.compared_end > prior.authorized_end
			|| proof.compared_end > source_len
			|| source_len > MAX_SIGNED_EXTENT
		{
			return Err(Refusal::Prefix);
		}
		Ok(Self {
			basis: Basis {
				prior,
				pass,
				proof,
				source_len,
			},
			phase: Phase::Compared,
		})
	}

	/// Returns the selected immutable basis.
	pub const fn basis(&self) -> Basis {
		self.basis
	}

	/// Accepts a successful prefix data barrier for the observed basis.
	///
	/// # Errors
	/// Refuses a stale context, different basis or invalid order.
	pub fn prefix_barrier(&mut self, live: Live, observed: Basis) -> Result<(), Refusal> {
		if !matches!(self.phase, Phase::Compared) {
			return Err(Refusal::Order);
		}
		self.check_live(live, self.basis.prior.head, self.basis.proof.compared_end)?;
		self.check_basis(observed)?;
		self.phase = Phase::Barrier;
		Ok(())
	}

	/// Accepts a durable, independently reread canonical successor under the same lease.
	///
	/// The caller verifies exact predecessor, record content and next head
	/// through the bounded storage owner and reports them here.
	///
	/// # Errors
	/// Refuses stale or mismatching evidence and skipped ordering.
	pub fn continued(&mut self, live: Live, observed: Basis, next: Head) -> Result<(), Refusal> {
		if !matches!(self.phase, Phase::Barrier) {
			return Err(Refusal::Order);
		}
		self.check_live(live, next, self.basis.proof.compared_end)?;
		self.check_basis(observed)?;
		if !next.is_successor_of(self.basis.prior.head) {
			self.block();
			return Err(Refusal::Evidence);
		}
		self.phase = Phase::Continued {
			lineage: next,
			head: next,
			checkpoint_end: self.basis.proof.compared_end,
			cursor: self.basis.proof.compared_end,
			pending: None,
			ordinal: 0,
			reserved: None,
		};
		Ok(())
	}

	/// Reserves one contiguous bounded tail window at the next offset.
	///
	/// # Errors
	/// Refuses invalid order, changed context, invalid ranges or insufficient budget.
	pub fn permit_tail(
		&mut self,
		live: Live,
		offset: u64,
		length: u64,
		budget: BudgetReservation,
	) -> Result<TailWrite, Refusal> {
		let Phase::Continued {
			lineage,
			head,
			checkpoint_end,
			cursor,
			pending: None,
			ordinal,
			reserved: None,
		} = self.phase
		else {
			return Err(Refusal::Order);
		};
		self.check_live(live, head, cursor)?;
		if checkpoint_end != cursor {
			return Err(Refusal::Order);
		}
		if offset != cursor || length > MAX_CHECKPOINT_BYTES {
			return Err(Refusal::Range);
		}
		let end = checked_range_end(self.basis.source_len, offset, length).ok_or(Refusal::Range)?;
		let reservation = budget.reserve(live, end, ordinal).ok_or(Refusal::Budget)?;
		self.phase = Phase::Continued {
			lineage,
			head,
			checkpoint_end,
			cursor,
			pending: Some(end),
			ordinal,
			reserved: Some(reservation),
		};
		Ok(TailWrite {
			live,
			start: offset,
			end,
		})
	}

	/// Records a fully confirmed completion of the exact issued window.
	///
	/// Lost, partial or uncertain effects must call `block` and reconcile.
	///
	/// # Errors
	/// An unexpected or nonmatching completion blocks the active stage.
	pub fn complete_tail(&mut self, live: Live, permit: TailWrite) -> Result<(), Refusal> {
		let Phase::Continued {
			lineage,
			head,
			checkpoint_end,
			cursor,
			pending,
			ordinal,
			reserved,
		} = self.phase
		else {
			return Err(Refusal::Order);
		};
		let Some(end) = pending else {
			self.block();
			return Err(Refusal::Completion);
		};
		self.check_live(live, head, end)?;
		if permit.live
			!= (Live {
				local_end: cursor,
				..live
			})
			|| permit.start != cursor
			|| permit.end != end
		{
			self.block();
			return Err(Refusal::Completion);
		}
		self.phase = Phase::Continued {
			lineage,
			head,
			checkpoint_end,
			cursor: end,
			pending: None,
			ordinal,
			reserved,
		};
		Ok(())
	}

	/// Accepts a synced checkpoint before permitting another bounded chunk.
	///
	/// The caller has confirmed the completed bytes and their data barrier, and
	/// authenticated the exact checkpoint and successor head in the storage owner.
	///
	/// # Errors
	/// Refuses in-flight, empty, stale or mismatching checkpoint evidence.
	pub fn checkpoint(&mut self, live: Live, record: Checkpoint) -> Result<(), Refusal> {
		let Phase::Continued {
			lineage,
			head,
			checkpoint_end,
			cursor,
			pending: None,
			reserved: Some(reservation),
			..
		} = self.phase
		else {
			return Err(Refusal::Order);
		};
		self.check_live(live, record.head, cursor)?;
		if record.lineage != lineage
			|| record.predecessor != head
			|| !record.head.is_successor_of(head)
			|| record.ordinal != reservation.ordinal
			|| record.head.end != reservation.end
			|| record.pass != self.basis.pass
			|| record.guard != self.basis.prior.guard
			|| record.start != checkpoint_end
			|| record.end != cursor
			|| checkpoint_end >= cursor
		{
			self.block();
			return Err(Refusal::Evidence);
		}
		self.phase = Phase::Continued {
			lineage,
			head: record.head,
			checkpoint_end: cursor,
			cursor,
			pending: None,
			ordinal: record.ordinal,
			reserved: None,
		};
		Ok(())
	}

	/// Permanently stops this continuation after uncertainty, lease loss or intent.
	pub fn block(&mut self) {
		self.phase = Phase::Blocked;
	}

	fn check_live(&mut self, live: Live, head: Head, local_end: u64) -> Result<(), Refusal> {
		if live.guard != self.basis.prior.guard
			|| live.head != head
			|| live.source != self.basis.pass.source
			|| live.local_end != local_end
		{
			self.block();
			Err(Refusal::Binding)
		} else {
			Ok(())
		}
	}

	fn check_basis(&mut self, basis: Basis) -> Result<(), Refusal> {
		if basis != self.basis {
			self.block();
			Err(Refusal::Evidence)
		} else {
			Ok(())
		}
	}
}
