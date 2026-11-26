use core::num::NonZeroU64;

use exacopy_core::UnixComponent;

use crate::{CopyBinding, RegularFileEvidence};

/// Opaque evidence digest, interpreted only by the authority or observation owner.
pub type Digest = [u8; 32];

/// Stable native identity of an observed entry, including its filesystem domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId(pub Digest);

/// Physical filesystem identity established by the qualified observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemId(pub Digest);

/// An exact, physically identified directory covered by the qualified layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Directory {
	/// Stable native identity of the directory.
	pub id: ObjectId,
	/// Identity of the physical filesystem containing it.
	pub filesystem: FilesystemId,
}

/// A single literal relative name under an independently held parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot<'name> {
	/// The exact native directory, not a displayed path.
	pub parent: Directory,
	/// The exact raw basename under the selected Unix name profile.
	pub name: UnixComponent<'name>,
}

/// The plan, held layout and qualified primitive used by this attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context<'name> {
	/// Coordinator-assigned job, entry, epoch and stage binding.
	pub attempt: CopyBinding,
	/// Independently approved plan identity.
	pub plan: Digest,
	/// Independently selected native capture and barrier qualification.
	pub qualification: Digest,
	/// Native proof binding the protected root topology and alias exclusions.
	pub layout: Digest,
	/// The current exclusive coordinator and lease binding.
	pub lease: Digest,
	/// Held read-only root for the source.
	pub source_root: Directory,
	/// The exact literal public name authorized for one relocation and publication.
	pub target: Slot<'name>,
	/// The already owned private name containing the sealed replacement.
	pub stage: Slot<'name>,
	/// The private reserved destination name for one exclusive capture.
	pub recovery: Slot<'name>,
}

impl Context<'_> {
	pub(super) fn is_admissible(self) -> bool {
		let public_filesystem = self.target.parent.filesystem;
		let source_filesystem = self.source_root.filesystem;
		public_filesystem != source_filesystem
			&& public_filesystem.0 != [0; 32]
			&& source_filesystem.0 != [0; 32]
			&& self.stage.parent.filesystem == public_filesystem
			&& self.recovery.parent.filesystem == public_filesystem
			&& self.qualification != [0; 32]
			&& self.plan != [0; 32]
			&& self.layout != [0; 32]
			&& self.lease != [0; 32]
			&& distinct(&[
				self.source_root.id.0,
				self.target.parent.id.0,
				self.stage.parent.id.0,
				self.recovery.parent.id.0,
			])
	}

	pub(super) fn binds(self, id: ObjectId) -> bool {
		[
			self.source_root.id,
			self.target.parent.id,
			self.stage.parent.id,
			self.recovery.parent.id,
		]
		.contains(&id)
	}
}

/// Identity and limits of one separately authorized grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
	/// Exact approved grant digest.
	pub id: Digest,
	/// Grant revision or revocation epoch selected by the authority owner.
	pub revision: NonZeroU64,
	/// Exclusive deadline on the admitted monotonic clock.
	pub expires_before: NonZeroU64,
}

/// Independent current authorization reported by the guard owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentGrant<'name> {
	/// Current attempt, plan, topology, qualification and held lease.
	pub context: Context<'name>,
	/// Current, unrevoked grant read under its serialization.
	pub grant: Grant,
	/// Current instant on the selected monotonic clock.
	pub now: u64,
}

impl CurrentGrant<'_> {
	pub(super) fn admits(self, expected: Context<'_>, grant: Grant) -> bool {
		self.context == expected && self.grant == grant && self.now < grant.expires_before.get()
	}
}

/// Recovery image policy fixed by the reviewed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImagePolicy {
	/// Retain the actual captured object without claiming a point-in-time copy.
	RetainObject,
	/// Require stable-view reads and independently verified image creation.
	IndependentImage {
		/// Exact read authority for the expected captured object.
		read: Grant,
		/// Separate authority to create the private image.
		create: Grant,
		/// Upper bound on the independently verified image extent.
		max_bytes: u64,
	},
}

/// Exact identities and limits selected independently of runtime observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection<'name> {
	/// Exact native scope of the attempt.
	pub context: Context<'name>,
	/// Source file identity associated with the verified stage.
	pub source: ObjectId,
	/// Replacement stage's physical object identity.
	pub replacement: ObjectId,
	/// Approved incumbent's physical object identity.
	pub incumbent: ObjectId,
	/// Expected replacement stream and required metadata measurements.
	pub replacement_evidence: RegularFileEvidence,
	/// Maximum authorized replacement logical bytes.
	pub max_replacement_bytes: u64,
	/// Authority for the actual occupant's single opaque relocation.
	pub capture: Grant,
	/// Separate authority for exclusive creation of the verified replacement name.
	pub publication: Grant,
	/// Policy for retaining or independently imaging the captured incumbent.
	pub image: ImagePolicy,
}

impl Selection<'_> {
	pub(super) fn is_admissible(self) -> bool {
		self.context.is_admissible()
			&& distinct(&[self.source.0, self.replacement.0, self.incumbent.0])
			&& [self.source, self.replacement, self.incumbent]
				.into_iter()
				.all(|id| !self.context.binds(id))
			&& self.replacement_evidence.byte_len <= self.max_replacement_bytes
			&& self.max_replacement_bytes <= MAX_LOGICAL_BYTES
			&& self.valid_authorities()
	}

	fn valid_authorities(self) -> bool {
		let capture = self.capture.id;
		let publication = self.publication.id;
		match self.image {
			ImagePolicy::RetainObject => distinct(&[capture, publication]),
			ImagePolicy::IndependentImage {
				read,
				create,
				max_bytes,
			} => {
				max_bytes <= MAX_LOGICAL_BYTES
					&& distinct(&[capture, publication, read.id, create.id])
			}
		}
	}
}

const MAX_LOGICAL_BYTES: u64 = i64::MAX as u64;

fn distinct(ids: &[Digest]) -> bool {
	ids.iter()
		.enumerate()
		.all(|(index, id)| *id != [0; 32] && !ids[..index].contains(id))
}
