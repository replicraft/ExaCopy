use exacopy_endpoint::UnixComponent;

use crate::StreamDigest;
use crate::frame::{FrameKind, FrameWriter};
use crate::remote_download::RemoteDownloadContext;
use crate::remote_download::finalization::{RemoteLocalMetadata, RemotePublishTarget};
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::replay::RemoteReplayBoundary;

use super::super::records::{RemoteWitnessCloseoutBody as Body, RemoteWitnessCloseoutRecord};
use super::super::successor_end;
use super::{
	Error, RemoteBootstrapTrust, RemoteWitnessIntent, RemoteWitnessedCloseoutReplay,
	RemoteWitnessedReplayPhase as Phase,
};

/// Exact declarations for the four witnessed phases before a rename submission.
///
/// The caller checks each native observation under the original live lease.
/// These values carry no authority or native evidence on their own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedPrepublicationFact {
	/// Original data writer is closed and both witness barriers were confirmed.
	Sealed,
	/// Whole-source and independent whole-stage BLAKE3 digests.
	Verified {
		/// Digest accumulated by the complete live source pass.
		source: StreamDigest,
		/// Digest measured by the independent local read-back.
		stage: StreamDigest,
	},
	/// Exact locally observed SFTP data-only metadata and policy barrier.
	Metadata(RemoteLocalMetadata),
	/// Current exact selected target was observed absent before durable intent.
	PublishIntent,
}

/// Canonical frame proposal for one clean witnessed prepublication successor.
///
/// A proposal supplies no append, synchronization or publication capability.
#[derive(Debug)]
#[must_use]
pub struct PreparedWitnessedCloseout {
	kind: FrameKind,
	previous: RemoteReplayBoundary,
	successor: RemoteReplayBoundary,
	bytes: Vec<u8>,
}

impl PreparedWitnessedCloseout {
	/// Exact selected frame kind.
	pub const fn kind(&self) -> FrameKind {
		self.kind
	}

	/// Original exact replay cut.
	pub const fn previous(&self) -> RemoteReplayBoundary {
		self.previous
	}

	/// Expected successor after the prospective frame.
	pub const fn successor(&self) -> RemoteReplayBoundary {
		self.successor
	}

	/// Complete bounded canonical frame bytes including the framing.
	pub fn encoded(&self) -> &[u8] {
		&self.bytes
	}
}

impl RemoteWitnessedCloseoutReplay {
	/// Prepares a single exact successor to the selected clean historical cut.
	///
	/// The caller independently observes the live witness, source, stage,
	/// policy and target under the original held lease. Replay cannot
	/// substitute for those observations or for current effect authority.
	///
	/// # Errors
	/// Refuses a different witness or owner, illegal phase, unequal digests,
	/// unsupported signed policy, or a frame outside selected bounds.
	pub fn prepare_prepublication(
		&self,
		trust: &RemoteBootstrapTrust<'_>,
		witness: RemoteWitnessIntent,
		fact: WitnessedPrepublicationFact,
	) -> Result<PreparedWitnessedCloseout, Error> {
		use WitnessedPrepublicationFact as Fact;

		let binding = witness.binding();
		let owner = trust.owner();
		let scope = &owner.manifest().scope;
		if self.issue().is_some()
			|| self.witness() != Some(witness)
			|| binding.context != RemoteDownloadContext::for_owner(owner)
			|| scope.metadata_policy != SftpDataOnlyV1::digest()
		{
			return Err(Error::Binding);
		}
		let previous = self.boundary();
		let extent = binding.coverage.end();
		let witness_head = witness.boundary().head;
		let body = match (self.phase(), fact) {
			(Phase::WitnessIntentRequiresInspection, Fact::Sealed)
				if previous == witness.boundary() =>
			{
				Body::Seal {
					directory: witness.stage_directory,
					extent,
					witness: witness_head,
					job_directory: witness.job_directory,
					name: witness.witness_name(),
				}
			}
			(Phase::Sealed, Fact::Verified { source, stage }) if source == stage => Body::Verify {
				extent,
				source,
				stage,
			},
			(Phase::Verified, Fact::Metadata(local)) => Body::Metadata(local),
			(Phase::MetadataReady, Fact::PublishIntent) => {
				let (seal, verification) =
					self.history.prepublication_heads.ok_or(Error::Binding)?;
				let destination = &scope.destination;
				Body::Intent {
					seal,
					verification,
					witness: witness_head,
					directory: witness.stage_directory,
					target: RemotePublishTarget {
						root: destination.root(),
						parent: destination.parent(),
						component: UnixComponent::new(destination.target())
							.map_err(|_| Error::Scope)?,
					},
					qualification: witness.qualification_digest,
					grant: witness.consent().base_grant_digest,
				}
			}
			_ => return Err(Error::Binding),
		};
		let kind = body.kind();
		let payload = RemoteWitnessCloseoutRecord::new(binding, previous, body).encode()?;
		let offset = successor_end(previous, payload.len())?;
		let mut writer = FrameWriter::new(Vec::new(), previous.head);
		let head = writer
			.append(kind, &payload)
			.map_err(|_| Error::FrameBinding)?;
		Ok(PreparedWitnessedCloseout {
			kind,
			previous,
			successor: RemoteReplayBoundary { head, offset },
			bytes: writer.into_inner(),
		})
	}
}
