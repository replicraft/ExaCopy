//! Wrong host bytes with matching independent pins in both actual approval ingress paths.

use exacopy_cli::assembly::linux::CopyRoots;
use exacopy_cli::assembly::linux::managed_sync::activation::{
	ApprovalError, ApprovalInput, ApprovalOperation, ApprovalSelection, PreparedApprovalInput,
	PreparedRecreate, prepare_recreate_approval, with_scoped_prepared_recreate,
};
use exacopy_plan::UnixTimestamp;

pub(super) fn exercise(
	selection: &ApprovalSelection<'_>,
	input: &PreparedApprovalInput<'_>,
	roots: CopyRoots<'_>,
	scratch: &mut [u8],
) {
	let host = input.approval.host;
	assert_eq!(host.len(), 838);
	let mut trailing = host.to_vec();
	trailing.push(0);
	let mut swapped_roles = host.to_vec();
	let (prefix, suffix) = swapped_roles.split_at_mut(636);
	prefix[604..].swap_with_slice(&mut suffix[..32]);

	let flipped = |offset: usize| {
		let mut bytes = host.to_vec();
		bytes[offset] ^= 1;
		bytes
	};
	let candidates = [
		("selection", flipped(12)),
		("magic", flipped(0)),
		("major", flipped(8)),
		("minor", flipped(9)),
		("features", flipped(10)),
		("short", host[..837].to_vec()),
		("trailing", trailing),
		("swapped roles", swapped_roles),
	];
	for (case, wrong) in candidates {
		let digest = blake3::derive_key("ExaCopy Linux managed approval host selection v1", &wrong);
		assert_ne!(digest, input.approval.host_digest, "{case}");
		for (pin_mode, expected_pin) in [
			("original pin", input.approval.host_digest),
			("recomputed pin", digest),
		] {
			let selected_input = || ApprovalInput {
				host: &wrong,
				host_digest: expected_pin,
				review: input.approval.review,
			};
			assert!(
				matches!(
					prepare_recreate_approval(
						selection,
						selected_input(),
						ApprovalOperation::Preview,
						roots,
						scratch,
						unexpected_clock,
					),
					Err(ApprovalError::Artifact)
				),
				"standalone accepted wrong H: {case}, {pin_mode}",
			);
			let scoped = PreparedApprovalInput {
				approval: selected_input(),
				slot: input.slot,
				grant: input.grant,
				parent: input.parent,
				activation: input.activation,
				activation_digest: input.activation_digest,
			};
			assert!(
				matches!(
					with_scoped_prepared_recreate(
						selection,
						scoped,
						roots,
						scratch,
						unexpected_clock,
						|_: PreparedRecreate<'_>| -> Result<(), ApprovalError> {
							panic!("wrong H reached the prepared callback: {case}, {pin_mode}");
						},
					),
					Err(ApprovalError::Artifact)
				),
				"scoped accepted wrong H: {case}, {pin_mode}",
			);
		}
	}
}

fn unexpected_clock() -> Option<UnixTimestamp> {
	panic!("wrong H reached the approval clock")
}
