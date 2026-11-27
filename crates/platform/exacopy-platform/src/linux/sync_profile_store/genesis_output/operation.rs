/// Independent, nonzero operation ID selecting all three exact output names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncGenesisOperation([u8; 16]);

impl SyncGenesisOperation {
	/// Selects a nonzero operation ID without opening or changing any resource.
	#[must_use]
	pub fn new(bytes: [u8; 16]) -> Option<Self> {
		(bytes != [0; 16]).then_some(Self(bytes))
	}

	/// Returns the selected operation bytes.
	#[must_use]
	pub const fn bytes(self) -> [u8; 16] {
		self.0
	}

	/// Derives the single immutable publication basename.
	#[must_use]
	pub fn final_name(self) -> Vec<u8> {
		self.name(b"genesis-")
	}

	/// Derives the private staging directory basename.
	#[must_use]
	pub fn stage_name(self) -> Vec<u8> {
		self.name(b".exacopy-genesis-stage-")
	}

	/// Derives the private intent basename.
	#[must_use]
	pub fn intent_name(self) -> Vec<u8> {
		let mut name = self.name(b".exacopy-genesis-intent-");
		name.extend_from_slice(b".v1");
		name
	}

	fn name(self, prefix: &[u8]) -> Vec<u8> {
		const HEX: &[u8; 16] = b"0123456789abcdef";
		let mut name = Vec::with_capacity(prefix.len() + 32);
		name.extend_from_slice(prefix);
		for byte in self.0 {
			name.push(HEX[usize::from(byte >> 4)]);
			name.push(HEX[usize::from(byte & 0x0f)]);
		}
		name
	}
}

#[cfg(test)]
mod tests {
	use super::SyncGenesisOperation;

	#[test]
	fn zero_refuses_and_names_do_not_overlap() {
		assert!(SyncGenesisOperation::new([0; 16]).is_none());
		let mut operation = [0xab; 16];
		operation[0] = 0;
		let operation = SyncGenesisOperation::new(operation).unwrap();
		assert_eq!(
			operation.final_name(),
			b"genesis-00ababababababababababababababab"
		);
		assert_eq!(
			operation.stage_name(),
			b".exacopy-genesis-stage-00ababababababababababababababab"
		);
		assert_eq!(
			operation.intent_name(),
			b".exacopy-genesis-intent-00ababababababababababababababab.v1"
		);
		assert_eq!(operation.bytes()[0], 0);
	}
}
