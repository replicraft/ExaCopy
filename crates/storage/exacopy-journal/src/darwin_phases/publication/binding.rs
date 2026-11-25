use core::num::NonZeroU64;

use minicbor::Decoder;

use crate::darwin_phases::codec::{PayloadEncoder, PayloadWriteError};
use crate::darwin_phases::{DarwinPhaseBinding, DarwinPhaseError, DarwinPublishIntent};
use crate::darwin_prepared::wire::{read_effect_header, write_effect_header};
use crate::frame::{ChainHead, Frame};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{JournalContext, PublishIntentContext};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ActiveIntent {
	pub(super) binding: DarwinPhaseBinding,
	pub(super) effect: NonZeroU64,
	pub(super) reference: ChainHead,
}

impl ActiveIntent {
	pub(super) fn new(frame: &Frame, intent: DarwinPublishIntent<'_>) -> Self {
		Self {
			binding: intent.binding(),
			effect: intent.effect_sequence(),
			reference: frame.head(),
		}
	}

	pub(super) fn validate(
		self,
		frame: &Frame,
	) -> Result<DarwinPublishIntent<'_>, DarwinPhaseError> {
		if self.reference != frame.head() {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		let intent = DarwinPublishIntent::from_frame(frame)?;
		if self != Self::new(frame, intent) {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		Ok(intent)
	}

	pub(super) fn write_header(
		self,
		encoder: &mut PayloadEncoder,
	) -> Result<(), PayloadWriteError> {
		let context = self.binding.context;
		write_effect_header(
			encoder,
			&PublishIntentContext {
				job: context.job,
				epoch: context.epoch,
				entry: self.binding.entry,
				effect_sequence: self.effect.get(),
				plan_digest: context.plan_digest,
			},
		)
	}

	pub(super) fn write(self, encoder: &mut PayloadEncoder) -> Result<(), PayloadWriteError> {
		encoder.map(2)?.u8(0)?;
		write_reference(encoder, self.reference)?;
		encoder.u8(1)?;
		self.binding.write(encoder)
	}

	pub(super) fn read(
		decoder: &mut Decoder<'_>,
		header: PublishIntentContext,
	) -> Result<Self, DarwinPhaseError> {
		let effect = NonZeroU64::new(header.effect_sequence)
			.ok_or(DarwinPhaseError::InvalidEffectSequence)?;
		let context = JournalContext {
			job: header.job,
			epoch: header.epoch,
			plan_digest: header.plan_digest,
		};
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		let reference = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let binding = DarwinPhaseBinding::read(decoder, context, header.entry)?;
		Ok(Self {
			binding,
			effect,
			reference,
		})
	}

	pub(super) fn read_header(
		decoder: &mut Decoder<'_>,
	) -> Result<PublishIntentContext, DarwinPhaseError> {
		Ok(read_effect_header(decoder)?)
	}
}

pub(super) fn write_reference(
	encoder: &mut PayloadEncoder,
	head: ChainHead,
) -> Result<(), PayloadWriteError> {
	encoder
		.array(2)?
		.u64(head.sequence())?
		.bytes(&head.digest())?;
	Ok(())
}

pub(super) fn read_reference(decoder: &mut Decoder<'_>) -> Result<ChainHead, DarwinPhaseError> {
	if decoder.array()? != Some(2) {
		return Err(DarwinPhaseError::InvalidCbor);
	}
	let sequence = decoder.u64()?;
	let digest = read_fixed(decoder)?;
	ChainHead::after(sequence, digest).ok_or(DarwinPhaseError::InvalidReference)
}

pub(super) fn require_before(earlier: ChainHead, later: ChainHead) -> Result<(), DarwinPhaseError> {
	if earlier.sequence() >= later.sequence() {
		return Err(DarwinPhaseError::InvalidFrameOrder);
	}
	Ok(())
}
