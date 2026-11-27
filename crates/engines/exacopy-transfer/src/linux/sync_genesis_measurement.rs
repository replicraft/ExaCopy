//! Independent live measurements for the one-subject Linux P-063 genesis profile.

use core::{fmt, num::NonZeroU64};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::ReadView;
use exacopy_manifest::sync_baseline::{
	Identity, LeafError, LinuxOwnerMode, Observation, SideEvidence,
};
use exacopy_model::SyncSide;
use exacopy_model::sync_genesis::GenesisRefusal;
use exacopy_plan::workflow_sync::{
	EndpointFacts, LinuxStability, NativeObject, WorkflowError, WorkflowTimestamp,
	linux_stability_digest, native_id, project_pair,
};

use super::sync_preview::{LiveSyncSelection, MAX_PREVIEW_FILE_BYTES};
use crate::manifest;
use crate::sync_genesis::{
	AssembledSyncGenesis, SyncGenesisError, SyncGenesisRecords, SyncGenesisSelection,
	assemble_sync_genesis,
};

mod model_admission;

#[cfg(test)]
mod tests;

const REGULAR_FILE_MODE: u32 = 0o100_000;
const ORDINARY_PERMISSIONS: u32 = 0o777;
const LEFT_READ: NonZeroU64 = NonZeroU64::new(1).unwrap();
const RIGHT_READ: NonZeroU64 = NonZeroU64::new(2).unwrap();
const FINAL_PAIR: NonZeroU64 = NonZeroU64::new(3).unwrap();

/// Actual native facts captured from the same held file as the data view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisFileFacts {
	/// Held file device and inode.
	pub object: NativeObject,
	/// Complete Linux stat mode including type bits.
	pub native_mode: u32,
	/// Observed logical stream length.
	pub length: u64,
	/// User ID in the admitted ownership namespace.
	pub uid: u32,
	/// Group ID in the admitted ownership namespace.
	pub gid: u32,
	/// Observed native link count.
	pub links: u64,
	/// Observed inode modification time.
	pub modified: WorkflowTimestamp,
	/// Observed inode change time.
	pub changed: WorkflowTimestamp,
}

/// One original held observation of the exact raw subject.
#[derive(Debug)]
pub enum GenesisInput<'view, R> {
	/// Independently held file and native observations.
	Present {
		/// Original positioned-read view of this file.
		view: &'view R,
		/// Facts from the same held view.
		facts: GenesisFileFacts,
	},
	/// Exact name is absent under the held root.
	Absent,
	/// An observed entry is outside the regular-file profile.
	Unsupported,
}

/// Fresh rooted observations sampled by one check of the same held pair.
#[derive(Clone, Copy, Debug)]
pub struct GenesisPairRecheck<'name> {
	/// Current scope including the freshly verified root locations.
	pub selection: LiveSyncSelection<'name>,
	/// Fresh native regular-file facts in left, right order.
	pub files: [Option<GenesisFileFacts>; 2],
}

/// Ordered observations under one independently admitted, continuously held managed lease.
///
/// The production adapter must retain the actual managed read lease and both original
/// files. Rechecks must confirm both original names, descriptor identities, native
/// facts and EOF under that same lease. The recheck must fail if those facts change.
pub trait HeldGenesisPair {
	/// The original read-only file view.
	type View: ReadView;
	/// A refusal while revalidating native pair custody.
	type Error;

	/// Supplies the original left and right observations without new lookups.
	fn observations(&self) -> [GenesisInput<'_, Self::View>; 2];

	/// Verifies original scope and both original observations together.
	///
	/// # Errors
	/// Reports any failed, changed or incomplete observation or scope check.
	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error>;

	/// Rechecks the original pair and returns the fresh observations from those checks.
	///
	/// # Errors
	/// Reports any failed, changed or incomplete observation or scope check.
	fn recheck_subjects(&self) -> Result<GenesisPairRecheck<'_>, Self::Error>;
}

/// Why exact held observations could not establish a genesis measurement.
#[derive(Debug)]
#[non_exhaustive]
pub enum GenesisMeasureFailure<R, P> {
	/// Scratch space was empty or over the fixed ceiling.
	ScratchLimit,
	/// The current scope differed from the independent selection.
	Selection,
	/// The selected endpoint profile could not be projected.
	Projection(WorkflowError),
	/// An exact-name observation was absent.
	Absent(SyncSide),
	/// The observation was unsupported or its native facts were inconsistent.
	Unsupported(SyncSide),
	/// A file aliases the other file, a root, or the common parent.
	Alias,
	/// An actual stream exceeded the appropriate ceiling.
	FileLimit(SyncSide),
	/// Independent stream lengths or digests differ.
	ContentMismatch,
	/// Actual required owner and mode values differ.
	MetadataMismatch,
	/// Required owner and mode could not be encoded.
	Metadata(SyncSide, LeafError),
	/// A bounded full read or its measurement recheck failed.
	Measure(SyncSide, manifest::Error<R>),
	/// The held pair could not be revalidated.
	Pair(P),
	/// The completed and independently rechecked observations failed model admission.
	Admission(GenesisRefusal),
}

impl<R: fmt::Display, P: fmt::Display> fmt::Display for GenesisMeasureFailure<R, P> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ScratchLimit => f.write_str("synchronization genesis scratch exceeds its bounds"),
			Self::Selection => f.write_str("synchronization genesis selection changed"),
			Self::Projection(error) => write!(f, "invalid synchronization genesis scope ({error})"),
			Self::Absent(side) => write!(f, "{side:?} synchronization genesis subject is absent"),
			Self::Unsupported(side) => {
				write!(f, "{side:?} synchronization genesis subject is unsupported")
			}
			Self::Alias => f.write_str("synchronization genesis objects alias"),
			Self::FileLimit(side) => write!(
				f,
				"{side:?} synchronization genesis stream exceeds its limit"
			),
			Self::ContentMismatch => f.write_str("synchronization genesis streams differ"),
			Self::MetadataMismatch => {
				f.write_str("synchronization genesis required metadata differs")
			}
			Self::Metadata(side, error) => write!(
				f,
				"{side:?} synchronization genesis metadata refused ({error})"
			),
			Self::Measure(side, error) => write!(
				f,
				"{side:?} synchronization genesis measurement failed ({error})"
			),
			Self::Pair(error) => write!(f, "synchronization genesis pair recheck failed ({error})"),
			Self::Admission(refusal) => {
				write!(f, "synchronization genesis evidence refused ({refusal:?})")
			}
		}
	}
}

impl<R: std::error::Error + 'static, P: std::error::Error + 'static> std::error::Error
	for GenesisMeasureFailure<R, P>
{
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Projection(error) => Some(error),
			Self::Metadata(_, error) => Some(error),
			Self::Measure(_, error) => Some(error),
			Self::Pair(error) => Some(error),
			_ => None,
		}
	}
}

/// Complete matched evidence that still borrows the original managed pair.
///
/// Retain this token and its concrete native adapter through signing and publication.
/// The caller supplies authority and rechecks custody at each effect boundary.
#[must_use]
pub struct MeasuredGenesisPair<'held, P> {
	pair: &'held P,
	selection: LiveSyncSelection<'held>,
	scan: NonZeroU64,
	sides: [SideEvidence; 2],
}

type GenesisPairError<P> = GenesisMeasureFailure<
	<<P as HeldGenesisPair>::View as ReadView>::Error,
	<P as HeldGenesisPair>::Error,
>;

impl<'held, P: HeldGenesisPair> MeasuredGenesisPair<'held, P> {
	/// The checked current ordered selection.
	#[must_use]
	pub const fn selection(&self) -> LiveSyncSelection<'held> {
		self.selection
	}

	/// The scan selected before either read.
	#[must_use]
	pub const fn scan(&self) -> NonZeroU64 {
		self.scan
	}

	/// Assembles an immutable P-063 closure from this held, model-admitted scan.
	///
	/// # Errors
	/// Refuses a mismatching signer, invalid records or failed closure verification.
	pub fn assemble(
		&self,
		records: SyncGenesisRecords,
		signer: &SigningKey,
	) -> Result<AssembledSyncGenesis, SyncGenesisError> {
		let live = self.selection;
		let owner =
			VerifyingKey::from_bytes(&live.owner_key).map_err(|_| SyncGenesisError::Signature)?;
		let selection = SyncGenesisSelection {
			profile: live.profile,
			revision: live.revision,
			owner: &owner,
			subject: live.subject,
			endpoints: live.endpoints,
			scan: self.scan,
		};
		assemble_sync_genesis(selection, records, self.sides, signer)
	}

	/// Left and right evidence from two independent full reads and a final pair recheck.
	#[must_use]
	pub const fn sides(&self) -> &[SideEvidence; 2] {
		&self.sides
	}

	/// Rechecks original native custody and scope before a later writer step.
	///
	/// # Errors
	/// Refuses stale, failed or incomplete observations and changed selection.
	pub fn recheck(&self) -> Result<(), GenesisPairError<P>> {
		check_selection(self.pair, self.selection).map(|_| ())
	}
}

/// Independently measures both originally held files under the admitted managed scope.
///
/// Both reads have their own bounds, digest computation and bracketed observations.
/// Keep the returned token through all writer effects and recheck it at the effect
/// boundaries. The operation creates no artifact or authority to mutate either root.
///
/// # Errors
/// Refuses incomplete, stale, mismatched, aliased or out-of-scope evidence.
pub fn measure_genesis_pair<'held, P: HeldGenesisPair>(
	pair: &'held P,
	expected: LiveSyncSelection<'_>,
	scan: NonZeroU64,
	scratch: &mut [u8],
) -> Result<MeasuredGenesisPair<'held, P>, GenesisPairError<P>> {
	use GenesisMeasureFailure as Failure;
	use SyncSide::{Left, Right};

	if scratch.is_empty() || scratch.len() > MAX_SCRATCH_BYTES {
		return Err(Failure::ScratchLimit);
	}
	let selection = check_selection(pair, expected)?;
	let projection = project_pair(
		selection.profile,
		selection.revision,
		selection.subject,
		selection.endpoints,
	)
	.map_err(Failure::Projection)?;
	let [left, right] = pair.observations();
	let [left_endpoint, right_endpoint] = selection.endpoints;
	let [left_root, right_root] = projection.roots;
	let left = admit::<_, P::Error>(left, Left, left_endpoint, left_root)?;
	let right = admit::<_, P::Error>(right, Right, right_endpoint, right_root)?;
	if left.identity.file == right.identity.file
		|| [left.identity.file, right.identity.file]
			.iter()
			.any(|id| projection.roots.contains(id) || *id == projection.parent)
	{
		return Err(Failure::Alias);
	}

	let left = left.measure::<P::Error>(Left, LEFT_READ, scratch)?;
	let right = right.measure::<P::Error>(Right, RIGHT_READ, scratch)?;
	if left.stream != right.stream {
		return Err(Failure::ContentMismatch);
	}
	if left.metadata != right.metadata {
		return Err(Failure::MetadataMismatch);
	}
	let final_pair = pair.recheck_subjects().map_err(Failure::Pair)?;
	if final_pair.selection != selection {
		return Err(Failure::Selection);
	}
	let [Some(left_final), Some(right_final)] = final_pair.files else {
		return Err(Failure::Admission(GenesisRefusal::StaleRecheck));
	};
	let reads = [left, right];
	let final_files = [left_final, right_final];
	model_admission::admit(
		[expected, selection, final_pair.selection],
		projection.policy,
		scan,
		&reads,
		final_files,
	)
	.map_err(Failure::Admission)?;
	let [left, right] = reads;
	let [left_root, right_root] = final_pair.selection.endpoints;
	Ok(MeasuredGenesisPair {
		pair,
		selection,
		scan,
		sides: [
			left.confirm(left_root, left_final),
			right.confirm(right_root, right_final),
		],
	})
}

fn check_selection<'held, P: HeldGenesisPair>(
	pair: &'held P,
	expected: LiveSyncSelection<'_>,
) -> Result<LiveSyncSelection<'held>, GenesisPairError<P>> {
	let current = pair
		.recheck_selection()
		.map_err(GenesisMeasureFailure::Pair)?;
	if current != expected {
		return Err(GenesisMeasureFailure::Selection);
	}
	Ok(current)
}

struct AdmittedFile<'view, R> {
	view: &'view R,
	facts: GenesisFileFacts,
	identity: Identity,
	metadata: LinuxOwnerMode,
}

fn admit<'view, R: ReadView, P>(
	input: GenesisInput<'view, R>,
	side: SyncSide,
	endpoint: EndpointFacts<'_>,
	root: [u8; 32],
) -> Result<AdmittedFile<'view, R>, GenesisMeasureFailure<R::Error, P>> {
	use GenesisMeasureFailure as Failure;

	let (view, facts) = match input {
		GenesisInput::Present { view, facts } => (view, facts),
		GenesisInput::Absent => return Err(Failure::Absent(side)),
		GenesisInput::Unsupported => return Err(Failure::Unsupported(side)),
	};
	let object = facts.object;
	let root_object = endpoint.location.root;
	if facts.native_mode & !ORDINARY_PERMISSIONS != REGULAR_FILE_MODE
		|| facts.links != 1
		|| facts.length != view.length()
		|| (object.major, object.minor) != (root_object.major, root_object.minor)
	{
		return Err(Failure::Unsupported(side));
	}
	if facts.length > endpoint.max_bytes.min(MAX_PREVIEW_FILE_BYTES) {
		return Err(Failure::FileLimit(side));
	}
	let mode = u16::try_from(facts.native_mode & ORDINARY_PERMISSIONS)
		.map_err(|_| Failure::Unsupported(side))?;
	Ok(AdmittedFile {
		view,
		facts,
		identity: Identity {
			root,
			file: native_id(endpoint.location.boot, object),
		},
		metadata: LinuxOwnerMode {
			mode,
			uid: facts.uid,
			gid: facts.gid,
		},
	})
}

impl<R: ReadView> AdmittedFile<'_, R> {
	fn measure<P>(
		self,
		side: SyncSide,
		read_position: NonZeroU64,
		scratch: &mut [u8],
	) -> Result<CompletedRead, GenesisMeasureFailure<R::Error, P>> {
		use GenesisMeasureFailure as Failure;

		let stream =
			manifest::measure(self.view, scratch).map_err(|error| Failure::Measure(side, error))?;
		let facts = self.facts;
		if stream.length != facts.length {
			return Err(Failure::Unsupported(side));
		}
		let metadata_digest = self
			.metadata
			.digest()
			.map_err(|error| Failure::Metadata(side, error))?;
		let stability = stability_digest(self.identity.file, facts);
		let measured = Observation {
			identity: self.identity,
			position: read_position,
			stability,
		};
		Ok(CompletedRead {
			measured,
			facts,
			stream,
			metadata: self.metadata,
			metadata_digest,
		})
	}
}

fn stability_digest(file: [u8; 32], facts: GenesisFileFacts) -> [u8; 32] {
	linux_stability_digest(LinuxStability {
		file,
		length: facts.length,
		mode: facts.native_mode,
		uid: facts.uid,
		gid: facts.gid,
		links: facts.links,
		modified: facts.modified,
		changed: facts.changed,
	})
}

struct CompletedRead {
	measured: Observation,
	facts: GenesisFileFacts,
	stream: manifest::Measurement,
	metadata: LinuxOwnerMode,
	metadata_digest: [u8; 32],
}

impl CompletedRead {
	fn confirm(self, endpoint: EndpointFacts<'_>, facts: GenesisFileFacts) -> SideEvidence {
		let identity = Identity {
			root: native_id(endpoint.location.boot, endpoint.location.root),
			file: native_id(endpoint.location.boot, facts.object),
		};
		SideEvidence {
			measured: self.measured,
			rechecked: Observation {
				identity,
				position: FINAL_PAIR,
				stability: stability_digest(identity.file, facts),
			},
			length: self.stream.length,
			stream_digest: self.stream.digest,
			metadata: self.metadata,
			metadata_digest: self.metadata_digest,
		}
	}
}
