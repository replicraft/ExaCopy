use std::{error::Error, fmt};

use minicbor::encode::{self, write::EndOfArray};

use crate::OwnerError;

/// Reasons for refusing a bounded remote-download declaration or payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteDownloadError {
	/// A variable or fixed field exceeds its encoding bound.
	Length,
	/// A CBOR value, discriminator or field order is invalid.
	Shape,
	/// The encoded version or required features are unsupported.
	UnsupportedVersion,
	/// A complete projection is noncanonical or followed by trailing bytes.
	NonCanonical,
	/// The signed endpoint scope contains an unsupported route or name.
	Scope,
	/// An identifier, phase field, scalar bound or related identity is invalid.
	Binding,
	/// A journal frame or its relative reference disagrees with the payload.
	FrameBinding,
	/// The selected key or signed owner envelope was refused.
	Owner(OwnerError),
}

impl fmt::Display for RemoteDownloadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Length => {
				f.write_str("remote download field or payload length exceeds its bound")
			}
			Self::Shape => f.write_str("invalid remote download CBOR shape"),
			Self::UnsupportedVersion => {
				f.write_str("unsupported remote download version or required features")
			}
			Self::NonCanonical => f.write_str("remote download bytes are not canonical"),
			Self::Scope => f.write_str("unsupported remote download endpoint scope"),
			Self::Binding => f.write_str("invalid remote download identity or evidence"),
			Self::FrameBinding => f.write_str("remote download journal frame binding disagrees"),
			Self::Owner(cause) => write!(f, "remote download owner refused ({cause})"),
		}
	}
}

impl Error for RemoteDownloadError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Owner(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<OwnerError> for RemoteDownloadError {
	fn from(cause: OwnerError) -> Self {
		Self::Owner(cause)
	}
}

impl From<minicbor::decode::Error> for RemoteDownloadError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Shape
	}
}

impl From<encode::Error<EndOfArray>> for RemoteDownloadError {
	fn from(_: encode::Error<EndOfArray>) -> Self {
		Self::Length
	}
}
