use std::num::NonZeroU64;

use crate::frame::{Frame, FrameKind};
use crate::remote_download::continuation::replay::RemoteWitnessCoveragePredecessor;
use crate::remote_download::qualification::continuation::VerifiedRemoteWitnessQualification;
use crate::remote_download::replay::RemoteReplayBoundary;
use crate::remote_download::wire::{array, fixed, read_identity};

use super::super::{
	Error, MAX_REMOTE_RECEIPT_READY_BYTES, RemoteBootstrapTrust, RemoteWitnessIntent,
	RemoteWitnessIntentExpectation, WitnessRetentionCommitment, binding_for, wire,
};

pub(super) fn from_archived_intent(
	trust: &RemoteBootstrapTrust<'_>,
	frame: &Frame,
	end: RemoteReplayBoundary,
	coverage: RemoteWitnessCoveragePredecessor<'_>,
	qualification: &VerifiedRemoteWitnessQualification,
	grant: [u8; 32],
) -> Result<RemoteWitnessIntent, Error> {
	let (continued, precursor) = coverage.authenticated(trust)?;
	let active = continued.claims();
	let previous = coverage.boundary();
	let binding = binding_for(continued, precursor, previous)?;
	let (claims, _) = wire::read_witness_envelope(frame.payload())?;
	let mut body = wire::selected_body(
		claims,
		binding,
		previous.head,
		FrameKind::RemoteWitnessIntent,
	)?;
	array(&mut body, 8)?;
	read_identity(&mut body)?;
	read_identity(&mut body)?;
	fixed::<40>(&mut body)?;
	fixed::<32>(&mut body)?;
	let deadline = NonZeroU64::new(body.u64()?).ok_or(Error::Binding)?;
	let consent =
		WitnessRetentionCommitment::measure(active.context, active.scope, grant, deadline)?;
	// The exact codec authenticates the signature and compares the whole
	// canonical claims to this scanner-selected commitment and scope.
	trust.from_witness_intent_frame(
		frame,
		end,
		&RemoteWitnessIntentExpectation {
			coverage,
			qualification,
			stage_directory: active.directory,
			job_directory: trust.owner().manifest().job_directory,
			consent,
		},
	)
}

pub(super) fn receipt_inode(
	frame: &Frame,
	witness: RemoteWitnessIntent,
	previous: RemoteReplayBoundary,
) -> Result<crate::LinuxFileIdentity, Error> {
	if frame.kind() != FrameKind::RemoteReceiptReady
		|| frame.payload().len() > MAX_REMOTE_RECEIPT_READY_BYTES
	{
		return Err(Error::FrameBinding);
	}
	let mut body = wire::selected_body(
		frame.payload(),
		witness.binding(),
		previous.head,
		FrameKind::RemoteReceiptReady,
	)?;
	array(&mut body, 9)?;
	read_identity(&mut body)?;
	fixed::<101>(&mut body)?;
	fixed::<99>(&mut body)?;
	read_identity(&mut body)
}
