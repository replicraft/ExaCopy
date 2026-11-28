use std::cell::Cell;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryOwner};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_journal::OwnerDigest;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::windows_bootstrap::WindowsBootstrapFileIdentity;
use exacopy_platform::windows::{WindowsCaptureAdmission, WindowsCaptureEffect};
use exacopy_platform::windows::{WindowsComponent, WindowsStageIdentity};

use super::selection::invalid_selection;

/// Independent trusted selection for one fresh capture invocation.
pub struct WindowsCaptureAuthorization<'a> {
	/// Fresh issuer-owned invocation nonce, unique among approvals.
	pub nonce: [u8; 32],
	/// Previously selected canonical resolved-direct source scope.
	pub source_scope: [u8; 32],
	/// Previously selected signed V1 owner envelope digest.
	pub owner_digest: OwnerDigest,
	/// Expected first frame of the exact V1 segment.
	pub bootstrap_head: ChainHead,
	/// Expected native identity of the privately provisioned empty sibling.
	pub sibling: WindowsBootstrapFileIdentity,
	/// Independently reserved unique supervisor lifetime.
	pub supervisor: RetryOwner,
	/// Independently reserved live source epoch.
	pub epoch: SourceEpoch,
	/// Exact authorized target component, to check for absence.
	pub target: WindowsComponent<'a>,
	/// Maximum allowed extent of the selected source.
	pub extent_ceiling: u64,
	/// Exclusive conservative process-monotonic deadline.
	pub expires_at: Instant,
}

/// Nonrenewable foreground approval issued by the embedding authority.
pub struct WindowsCaptureGrant<'a> {
	pub(super) approval: WindowsCaptureAuthorization<'a>,
	pub(super) gate: Arc<Gate>,
}

impl<'a> WindowsCaptureGrant<'a> {
	/// Issues one approval. The embedding authority independently selects and
	/// approves all fields, reserves the nonce and supervisor, and enforces
	/// authoritative clock and revocation policy. Issuance performs no I/O.
	///
	/// # Errors
	/// Refuses invalid scope values or an elapsed deadline.
	pub fn issue(approval: WindowsCaptureAuthorization<'a>) -> io::Result<Self> {
		let now = Instant::now();
		if approval.nonce == [0; 32]
			|| approval.source_scope == [0; 32]
			|| approval.owner_digest.as_bytes() == &[0; 32]
			|| approval.bootstrap_head.sequence() != 1
			|| approval.extent_ceiling > MAX_FILE_LENGTH
			|| now >= approval.expires_at
		{
			return Err(invalid_selection());
		}
		let gate = Arc::new(Gate {
			start: now,
			expires: approval.expires_at,
			approved_owner: approval.supervisor,
			approved_epoch: approval.epoch,
			state: Mutex::new(State {
				phase: Phase::Unused,
				latest: now,
			}),
		});
		Ok(Self { approval, gate })
	}

	/// Permanently refuses subsequent use. A currently admitted synchronous
	/// action keeps its guard until that action returns.
	///
	/// # Errors
	/// A poisoned gate is already permanently unusable.
	pub fn revoke(&self) -> io::Result<()> {
		self.gate.retire()
	}
}

struct State {
	phase: Phase,
	latest: Instant,
}

enum Phase {
	Unused,
	Connecting,
	Admitted(ConnectionBinding),
	Retired,
}

pub(super) struct Gate {
	pub(super) start: Instant,
	pub(super) expires: Instant,
	approved_owner: RetryOwner,
	approved_epoch: SourceEpoch,
	state: Mutex<State>,
}

impl Gate {
	pub(super) fn claim(&self) -> io::Result<Invocation<'_>> {
		let mut state = self.lock()?;
		match state.phase {
			Phase::Unused => {
				state.phase = Phase::Connecting;
				if let Err(cause) = self.check_time(&mut state) {
					state.phase = Phase::Retired;
					return Err(cause);
				}
				Ok(Invocation(self))
			}
			_ => Err(refused()),
		}
	}

	pub(super) fn admit(&self, binding: ConnectionBinding) -> io::Result<()> {
		let mut state = self.lock()?;
		self.check_time(&mut state)?;
		if !matches!(state.phase, Phase::Connecting)
			|| binding.attempt().owner() != self.approved_owner
			|| binding.source_epoch() != self.approved_epoch
		{
			return Err(refused());
		}
		state.phase = Phase::Admitted(binding);
		Ok(())
	}

	pub(super) fn route<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
		let mut state = self.lock()?;
		self.check_time(&mut state)?;
		match state.phase {
			Phase::Connecting | Phase::Admitted(_) => Ok(operation()),
			_ => Err(refused()),
		}
	}

	pub(super) fn check(&self, expected: ConnectionBinding) -> io::Result<()> {
		self.enter(expected).map(drop)
	}

	fn enter(&self, expected: ConnectionBinding) -> io::Result<MutexGuard<'_, State>> {
		let mut state = self.lock()?;
		self.check_time(&mut state)?;
		match state.phase {
			Phase::Admitted(current) if current == expected => Ok(state),
			_ => Err(refused()),
		}
	}

	fn check_time(&self, state: &mut State) -> io::Result<()> {
		let now = Instant::now();
		if now < state.latest || now >= self.expires {
			state.phase = Phase::Retired;
			return Err(refused());
		}
		state.latest = now;
		Ok(())
	}

	fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
		self.state.lock().map_err(|_| refused())
	}

	fn retire(&self) -> io::Result<()> {
		self.lock()?.phase = Phase::Retired;
		Ok(())
	}
}

pub(super) struct Invocation<'a>(&'a Gate);

impl Drop for Invocation<'_> {
	fn drop(&mut self) {
		let _ = self.0.retire();
	}
}

pub(super) struct EffectGuard<'a> {
	_current: MutexGuard<'a, State>,
}

#[derive(Clone, Copy)]
enum NativePhase {
	Selected,
	BootstrapStarted,
	DirectoryStarted,
	PayloadStarted(WindowsStageIdentity),
	Bound(WindowsStageIdentity),
	Closed,
}

/// Joins native effect requests to the same live connection and observed extent.
pub(super) struct Effects<'a> {
	gate: &'a Gate,
	binding: ConnectionBinding,
	sibling: WindowsStageIdentity,
	extent: u64,
	native: Cell<NativePhase>,
}

impl<'a> Effects<'a> {
	pub(super) fn new(
		gate: &'a Gate,
		binding: ConnectionBinding,
		sibling: WindowsStageIdentity,
		extent: u64,
	) -> Self {
		Self {
			gate,
			binding,
			sibling,
			extent,
			native: Cell::new(NativePhase::Selected),
		}
	}

	pub(super) fn bind_stage(
		&self,
		directory: WindowsStageIdentity,
		payload: WindowsStageIdentity,
	) -> io::Result<()> {
		let _current = self.gate.enter(self.binding)?;
		if !matches!(self.native.get(), NativePhase::PayloadStarted(expected) if directory == expected)
			|| directory == payload
		{
			return Err(refused());
		}
		self.native.set(NativePhase::Bound(payload));
		Ok(())
	}

	pub(super) fn check_current(&self) -> io::Result<()> {
		self.gate.check(self.binding)
	}
}

impl WindowsCaptureAdmission for Effects<'_> {
	type Guard<'gate>
		= EffectGuard<'gate>
	where
		Self: 'gate;

	fn enter(&self, effect: WindowsCaptureEffect) -> io::Result<Self::Guard<'_>> {
		use NativePhase as Phase;

		let current = self.gate.enter(self.binding)?;
		let phase = self.native.get();
		let next = match (phase, effect) {
			(Phase::Selected, WindowsCaptureEffect::Bootstrap) => Phase::BootstrapStarted,
			(Phase::BootstrapStarted, WindowsCaptureEffect::CreateStageDirectory) => {
				Phase::DirectoryStarted
			}
			(
				Phase::DirectoryStarted,
				WindowsCaptureEffect::CreateStageFile { directory, length },
			) if length == self.extent => Phase::PayloadStarted(directory),
			(
				Phase::Bound(bound),
				WindowsCaptureEffect::StageWrite {
					stage,
					offset,
					length,
				},
			) if stage == bound
				&& length != 0
				&& u64::try_from(length)
					.ok()
					.and_then(|length| offset.checked_add(length))
					.is_some_and(|end| end <= self.extent) =>
			{
				phase
			}
			(Phase::Bound(bound), WindowsCaptureEffect::StagePrefixBarrier { stage, end })
				if stage == bound && end != 0 && end <= self.extent =>
			{
				phase
			}
			(Phase::Bound(bound), WindowsCaptureEffect::StageCloseBarrier { stage, end })
				if stage == bound && end == self.extent =>
			{
				Phase::Closed
			}
			(
				Phase::Bound(_),
				WindowsCaptureEffect::JournalAppend {
					segment, length, ..
				},
			) if segment == self.sibling && length != 0 => phase,
			_ => return Err(refused()),
		};
		self.native.set(next);
		Ok(EffectGuard { _current: current })
	}
}

pub(super) fn refused() -> io::Error {
	io::Error::new(
		io::ErrorKind::PermissionDenied,
		"Windows capture grant is unavailable",
	)
}
