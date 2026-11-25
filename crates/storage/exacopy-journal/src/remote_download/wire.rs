use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use crate::LinuxFileIdentity;
use crate::frame::ChainHead;

use super::RemoteDownloadError as Error;

const LINUX: u8 = 1;

pub(super) fn key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), Error> {
	(decoder.u8()? == expected)
		.then_some(())
		.ok_or(Error::Shape)
}

pub(super) fn array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), Error> {
	(decoder.array()? == Some(expected))
		.then_some(())
		.ok_or(Error::Shape)
}

pub(super) fn map(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), Error> {
	(decoder.map()? == Some(expected))
		.then_some(())
		.ok_or(Error::Shape)
}

pub(super) fn fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], Error> {
	decoder.bytes()?.try_into().map_err(|_| Error::Length)
}

pub(super) fn read_version(decoder: &mut Decoder<'_>, version: [u64; 3]) -> Result<(), Error> {
	array(decoder, 3)?;
	for expected in version {
		if decoder.u64()? != expected {
			return Err(Error::UnsupportedVersion);
		}
	}
	Ok(())
}

pub(super) fn write_version<W: Write>(
	encoder: &mut Encoder<W>,
	version: [u64; 3],
) -> Result<(), encode::Error<W::Error>> {
	encoder.array(3)?;
	for value in version {
		encoder.u64(value)?;
	}
	Ok(())
}

pub(super) fn read_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, Error> {
	map(decoder, 4)?;
	key(decoder, 0)?;
	if decoder.u8()? != LINUX {
		return Err(Error::Binding);
	}
	key(decoder, 1)?;
	let device = u64::from_le_bytes(fixed(decoder)?);
	key(decoder, 2)?;
	let inode = u64::from_le_bytes(fixed(decoder)?);
	key(decoder, 3)?;
	decoder.null()?;
	Ok(LinuxFileIdentity::new(device, inode))
}

pub(super) fn write_identity<W: Write>(
	encoder: &mut Encoder<W>,
	identity: LinuxFileIdentity,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(4)?
		.u8(0)?
		.u8(LINUX)?
		.u8(1)?
		.bytes(&identity.device().to_le_bytes())?
		.u8(2)?
		.bytes(&identity.inode().to_le_bytes())?
		.u8(3)?
		.null()?;
	Ok(())
}

pub(super) fn read_head(decoder: &mut Decoder<'_>) -> Result<ChainHead, Error> {
	array(decoder, 2)?;
	ChainHead::after(decoder.u64()?, fixed(decoder)?).ok_or(Error::FrameBinding)
}

pub(super) fn write_head<W: Write>(
	encoder: &mut Encoder<W>,
	head: ChainHead,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.array(2)?
		.u64(head.sequence())?
		.bytes(&head.digest())?;
	Ok(())
}
