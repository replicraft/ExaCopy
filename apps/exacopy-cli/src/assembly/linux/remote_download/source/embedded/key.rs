use std::path::Path;

use base64ct::{Base64, Encoding};
use exacopy_platform::read_protected_snapshot_into;
use exacopy_wireguard::protocol::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::EmbeddedConnectError;

const ENCODED_BYTES: usize = 44;
const SECRET_BYTES: usize = 32;

pub(super) fn read_private(
	path: &Path,
	expected_public: [u8; SECRET_BYTES],
) -> Result<StaticSecret, EmbeddedConnectError> {
	let mut encoded = Zeroizing::new([0; ENCODED_BYTES + 1]);
	let mut reread = Zeroizing::new([0; ENCODED_BYTES + 1]);
	let size = read_protected_snapshot_into(path, &mut encoded[..], &mut reread[..])
		.map_err(|_| EmbeddedConnectError::KeyProfile)?;
	let mut decoded = Zeroizing::new([0; SECRET_BYTES]);
	decode(&encoded[..size], &mut decoded).ok_or(EmbeddedConnectError::KeyProfile)?;
	if *decoded == [0; SECRET_BYTES] {
		return Err(EmbeddedConnectError::KeyProfile);
	}
	let private = StaticSecret::from(*decoded);
	if PublicKey::from(&private).to_bytes() != expected_public {
		return Err(EmbeddedConnectError::KeyProfile);
	}
	Ok(private)
}

fn decode(input: &[u8], output: &mut [u8; SECRET_BYTES]) -> Option<()> {
	let key: &[u8; ENCODED_BYTES] = input.strip_suffix(b"\n").unwrap_or(input).try_into().ok()?;
	let count = Base64::decode(key, output).ok()?.len();
	(count == SECRET_BYTES).then_some(())
}

#[cfg(test)]
mod tests {
	use super::decode;

	#[test]
	fn accepts_only_the_canonical_wireguard_key_with_optional_single_lf() {
		let encoded = b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
		let mut output = [0; 32];
		assert!(decode(encoded, &mut output).is_some());
		assert_eq!(output, std::array::from_fn(|n| u8::try_from(n).unwrap()));
		assert!(decode(&[encoded.as_slice(), b"\n"].concat(), &mut output).is_some());
		assert!(decode(&[encoded.as_slice(), b"\r\n"].concat(), &mut output).is_none());
		assert!(decode(&[&encoded[..42], b"9="].concat(), &mut output).is_none());
		assert!(decode(&[&encoded[..42], b"_="].concat(), &mut output).is_none());
		assert!(decode(&encoded[..43], &mut output).is_none());
	}
}
