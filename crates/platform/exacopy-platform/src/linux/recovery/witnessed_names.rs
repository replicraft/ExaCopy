use super::WitnessReceiptNames;

pub(super) fn matches_names(names: &WitnessReceiptNames, witness: &[u8; 40]) -> bool {
	let (Some(pending), Some(final_name), Some(nonce)) = (
		names.pending.strip_prefix(b"rw-receipt.pending."),
		names.final_name.strip_prefix(b"rw-receipt.final."),
		witness.strip_prefix(b"witness."),
	) else {
		return false;
	};
	if pending != final_name || pending.len() != 82 {
		return false;
	}
	let hex = |byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
	pending[32] == b'.'
		&& pending[49] == b'.'
		&& pending[..32].iter().copied().all(hex)
		&& pending[33..49].iter().copied().all(hex)
		&& pending[33..49].iter().any(|&byte| byte != b'0')
		&& nonce.iter().copied().all(hex)
		&& &pending[50..] == nonce
}
