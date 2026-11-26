use exacopy_endpoint::UnixComponent;
use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use crate::RootCapabilityId;
use crate::frame::FrameKind;
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::wire::{array, fixed, read_head, write_head, write_identity};

use super::{
	Error, NamespaceObservation, RemoteLocalMetadata, RemotePublishTarget, RemoteRetainedWitness,
	RemoteWitnessCloseoutBody, RemoteWitnessRetirementReason, RemoteWitnessedOutcome, StreamDigest,
	StreamLength, native,
};

const ONE: u8 = 1;
const TWO: u8 = 2;
const THREE: u8 = 3;
const FOUR: u8 = 4;

pub(super) fn read<'frame>(
	kind: FrameKind,
	input: &mut Decoder<'frame>,
) -> Result<RemoteWitnessCloseoutBody<'frame>, Error> {
	use RemoteWitnessCloseoutBody as Body;
	Ok(match kind {
		FrameKind::StageSealed => {
			array(input, 9)?;
			let directory = native(input)?;
			let extent = length(input)?;
			let witness = read_head(input)?;
			let job_directory = native(input)?;
			let name = fixed(input)?;
			markers(input, [ONE, ONE, ONE, TWO])?;
			Body::Seal {
				directory,
				extent,
				witness,
				job_directory,
				name,
			}
		}
		FrameKind::VerificationRecorded => {
			array(input, 7)?;
			let extent = length(input)?;
			let source = StreamDigest::from_bytes(fixed(input)?);
			let stage = StreamDigest::from_bytes(fixed(input)?);
			if source != stage {
				return Err(Error::Binding);
			}
			markers(input, [ONE; 4])?;
			Body::Verify {
				extent,
				source,
				stage,
			}
		}
		FrameKind::MetadataRecorded => {
			array(input, 7)?;
			if fixed::<32>(input)? != SftpDataOnlyV1::digest()
				|| input.u16()? != SftpDataOnlyV1::LOCAL_MODE
			{
				return Err(Error::Binding);
			}
			let local = RemoteLocalMetadata {
				uid: input.u32()?,
				gid: input.u32()?,
			};
			markers(input, [ONE; 2])?;
			let omissions = SftpDataOnlyV1::omissions();
			array(input, omissions.len() as u64)?;
			for omission in omissions {
				markers(input, [omission.code()])?;
			}
			Body::Metadata(local)
		}
		FrameKind::PublishIntent => {
			array(input, 10)?;
			let seal = read_head(input)?;
			let verification = read_head(input)?;
			let witness = read_head(input)?;
			let directory = native(input)?;
			let target = read_target(input)?;
			let qualification = fixed(input)?;
			let grant = fixed(input)?;
			markers(input, [ONE; 3])?;
			Body::Intent {
				seal,
				verification,
				witness,
				directory,
				target,
				qualification,
				grant,
			}
		}
		FrameKind::PublishObserved => Body::Observed(read_outcome(input)?),
		FrameKind::DurabilityRecorded => {
			array(input, 9)?;
			let metadata = read_head(input)?;
			let directory = native(input)?;
			let target_parent = native(input)?;
			let job_directory = native(input)?;
			let qualification = fixed(input)?;
			markers(input, [ONE; 4])?;
			Body::Durability {
				metadata,
				directory,
				target_parent,
				job_directory,
				qualification,
			}
		}
		FrameKind::ReceiptCommitted => {
			array(input, 4)?;
			let digest = fixed(input)?;
			let inode = native(input)?;
			markers(input, [ONE; 2])?;
			Body::CommittedReceipt { digest, inode }
		}
		FrameKind::RemoteCaptureRetired => {
			array(input, 9)?;
			let directory = native(input)?;
			let target = read_target(input)?;
			let qualification = fixed(input)?;
			let grant = fixed(input)?;
			let reason = match input.u8()? {
				ONE => RemoteWitnessRetirementReason::FreshSelection,
				TWO => RemoteWitnessRetirementReason::RetainedReuseRefused,
				_ => return Err(Error::Shape),
			};
			let retained = read_retained(input)?;
			markers(input, [ONE; 3])?;
			Body::Retire {
				directory,
				target,
				qualification,
				grant,
				reason,
				retained,
			}
		}
		_ => return Err(Error::UnsupportedVersion),
	})
}

pub(super) fn write<W: Write>(
	out: &mut Encoder<W>,
	body: RemoteWitnessCloseoutBody<'_>,
) -> Result<(), encode::Error<W::Error>> {
	use RemoteWitnessCloseoutBody as Body;
	match body {
		Body::Seal {
			directory,
			extent,
			witness,
			job_directory,
			name,
		} => {
			out.array(9)?;
			write_identity(out, directory)?;
			out.u64(extent.get())?;
			write_head(out, witness)?;
			write_identity(out, job_directory)?;
			out.bytes(&name)?;
			write_markers(out, [ONE, ONE, ONE, TWO])?;
		}
		Body::Verify {
			extent,
			source,
			stage,
		} => {
			out.array(7)?
				.u64(extent.get())?
				.bytes(source.as_bytes())?
				.bytes(stage.as_bytes())?;
			write_markers(out, [ONE; 4])?;
		}
		Body::Metadata(local) => {
			out.array(7)?
				.bytes(&SftpDataOnlyV1::digest())?
				.u16(SftpDataOnlyV1::LOCAL_MODE)?
				.u32(local.uid)?
				.u32(local.gid)?;
			write_markers(out, [ONE; 2])?;
			let omissions = SftpDataOnlyV1::omissions();
			out.array(omissions.len() as u64)?;
			for omission in omissions {
				out.u8(omission.code())?;
			}
		}
		Body::Intent {
			seal,
			verification,
			witness,
			directory,
			target,
			qualification,
			grant,
		} => {
			out.array(10)?;
			write_head(out, seal)?;
			write_head(out, verification)?;
			write_head(out, witness)?;
			write_identity(out, directory)?;
			write_target(out, target)?;
			out.bytes(&qualification)?.bytes(&grant)?;
			write_markers(out, [ONE; 3])?;
		}
		Body::Observed(observed) => write_outcome(out, observed)?,
		Body::Durability {
			metadata,
			directory,
			target_parent,
			job_directory,
			qualification,
		} => {
			out.array(9)?;
			write_head(out, metadata)?;
			write_identity(out, directory)?;
			write_identity(out, target_parent)?;
			write_identity(out, job_directory)?;
			out.bytes(&qualification)?;
			write_markers(out, [ONE; 4])?;
		}
		Body::CommittedReceipt { digest, inode } => {
			out.array(4)?.bytes(&digest)?;
			write_identity(out, inode)?;
			write_markers(out, [ONE; 2])?;
		}
		Body::Retire {
			directory,
			target,
			qualification,
			grant,
			reason,
			retained,
		} => {
			out.array(9)?;
			write_identity(out, directory)?;
			write_target(out, target)?;
			out.bytes(&qualification)?.bytes(&grant)?.u8(match reason {
				RemoteWitnessRetirementReason::FreshSelection => ONE,
				RemoteWitnessRetirementReason::RetainedReuseRefused => TWO,
			})?;
			write_retained(out, retained)?;
			write_markers(out, [ONE; 3])?;
		}
	}
	Ok(())
}

fn read_outcome(input: &mut Decoder<'_>) -> Result<RemoteWitnessedOutcome, Error> {
	use RemoteWitnessedOutcome as Outcome;
	Ok(match (input.array()?, input.u8()?) {
		(Some(3), ONE) => {
			let target = native(input)?;
			markers(input, [ONE])?;
			Outcome::Submitted(target)
		}
		(Some(1), TWO) => Outcome::Conflict,
		(Some(4), THREE) => Outcome::Uncertain {
			target: read_name_state(input)?,
			stage: read_name_state(input)?,
			witness: read_name_state(input)?,
		},
		(Some(6), FOUR) => {
			let target = native(input)?;
			let witness = read_head(input)?;
			markers(input, [ONE, ONE, TWO])?;
			Outcome::Recovered { target, witness }
		}
		_ => return Err(Error::Shape),
	})
}

fn write_outcome<W: Write>(
	out: &mut Encoder<W>,
	value: RemoteWitnessedOutcome,
) -> Result<(), encode::Error<W::Error>> {
	use RemoteWitnessedOutcome as Outcome;
	match value {
		Outcome::Submitted(target) => {
			out.array(3)?.u8(ONE)?;
			write_identity(out, target)?;
			out.u8(ONE)?;
		}
		Outcome::Conflict => {
			out.array(1)?.u8(TWO)?;
		}
		Outcome::Uncertain {
			target,
			stage,
			witness,
		} => {
			out.array(4)?.u8(THREE)?;
			for observation in [target, stage, witness] {
				write_name_state(out, observation)?;
			}
		}
		Outcome::Recovered { target, witness } => {
			out.array(6)?.u8(FOUR)?;
			write_identity(out, target)?;
			write_head(out, witness)?;
			write_markers(out, [ONE, ONE, TWO])?;
		}
	}
	Ok(())
}

fn read_retained(input: &mut Decoder<'_>) -> Result<RemoteRetainedWitness, Error> {
	use RemoteRetainedWitness as Witness;
	Ok(match (input.array()?, input.u8()?) {
		(Some(1), 0) => Witness::NoIntent,
		(Some(2), ONE) => Witness::AbsentAfterIntent(read_head(input)?),
		(Some(4), TWO) => Witness::Preserved {
			intent: read_head(input)?,
			job_directory: native(input)?,
			name: fixed(input)?,
		},
		_ => return Err(Error::Shape),
	})
}

fn write_retained<W: Write>(
	out: &mut Encoder<W>,
	value: RemoteRetainedWitness,
) -> Result<(), encode::Error<W::Error>> {
	use RemoteRetainedWitness as Witness;
	match value {
		Witness::NoIntent => {
			out.array(1)?.u8(0)?;
		}
		Witness::AbsentAfterIntent(intent) => {
			out.array(2)?.u8(ONE)?;
			write_head(out, intent)?;
		}
		Witness::Preserved {
			intent,
			job_directory,
			name,
		} => {
			out.array(4)?.u8(TWO)?;
			write_head(out, intent)?;
			write_identity(out, job_directory)?;
			out.bytes(&name)?;
		}
	}
	Ok(())
}

fn read_name_state(input: &mut Decoder<'_>) -> Result<NamespaceObservation, Error> {
	Ok(match (input.array()?, input.u8()?) {
		(Some(1), 0) => NamespaceObservation::Unobserved,
		(Some(1), ONE) => NamespaceObservation::Absent,
		(Some(2), TWO) => NamespaceObservation::Present(native(input)?),
		_ => return Err(Error::Shape),
	})
}

fn write_name_state<W: Write>(
	out: &mut Encoder<W>,
	value: NamespaceObservation,
) -> Result<(), encode::Error<W::Error>> {
	match value {
		NamespaceObservation::Unobserved => {
			out.array(1)?.u8(0)?;
		}
		NamespaceObservation::Absent => {
			out.array(1)?.u8(ONE)?;
		}
		NamespaceObservation::Present(identity) => {
			out.array(2)?.u8(TWO)?;
			write_identity(out, identity)?;
		}
	}
	Ok(())
}

fn read_target<'frame>(input: &mut Decoder<'frame>) -> Result<RemotePublishTarget<'frame>, Error> {
	array(input, 3)?;
	Ok(RemotePublishTarget {
		root: RootCapabilityId::from_bytes(fixed(input)?).map_err(|_| Error::Binding)?,
		parent: native(input)?,
		component: UnixComponent::new(input.bytes()?).map_err(|_| Error::Scope)?,
	})
}

fn write_target<W: Write>(
	out: &mut Encoder<W>,
	target: RemotePublishTarget<'_>,
) -> Result<(), encode::Error<W::Error>> {
	out.array(3)?.bytes(target.root.as_bytes())?;
	write_identity(out, target.parent)?;
	out.bytes(target.component.as_bytes())?;
	Ok(())
}

fn length(input: &mut Decoder<'_>) -> Result<StreamLength, Error> {
	StreamLength::new(input.u64()?).map_err(|_| Error::Length)
}

fn markers<const N: usize>(input: &mut Decoder<'_>, expected: [u8; N]) -> Result<(), Error> {
	for value in expected {
		if input.u8()? != value {
			return Err(Error::Shape);
		}
	}
	Ok(())
}

fn write_markers<W: Write, const N: usize>(
	out: &mut Encoder<W>,
	markers: [u8; N],
) -> Result<(), encode::Error<W::Error>> {
	for marker in markers {
		out.u8(marker)?;
	}
	Ok(())
}
