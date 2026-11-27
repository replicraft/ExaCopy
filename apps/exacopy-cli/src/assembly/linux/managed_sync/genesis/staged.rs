use std::io::{self, Cursor};

use exacopy_manifest::sync_baseline::SideEvidence;
use exacopy_plan::workflow_sync::WorkflowRef;
use exacopy_transfer::sync_genesis::{
	ExpectedSyncGenesis, SyncGenesisResolver, verify_sync_genesis,
};

pub(super) fn verify(
	[root, left, right, leaf]: [&[u8]; 4],
	expected: &ExpectedSyncGenesis<'_>,
	references: [WorkflowRef; 3],
	measured: &[SideEvidence; 2],
) -> io::Result<()> {
	let mut staged = StagedMembers {
		references,
		bytes: [left, right, leaf],
	};
	let verified = verify_sync_genesis(root, expected, &mut staged).map_err(io::Error::other)?;
	if verified.sides() != measured {
		return Err(io::Error::other(
			"staged genesis differs from the held measurement",
		));
	}
	Ok(())
}

struct StagedMembers<'bytes> {
	references: [WorkflowRef; 3],
	bytes: [&'bytes [u8]; 3],
}

impl SyncGenesisResolver for StagedMembers<'_> {
	type Member<'resolver>
		= Cursor<&'resolver [u8]>
	where
		Self: 'resolver;

	fn open(&mut self, reference: WorkflowRef) -> io::Result<Self::Member<'_>> {
		let index = self
			.references
			.iter()
			.position(|expected| *expected == reference)
			.ok_or_else(|| io::Error::other("unselected staged genesis resource"))?;
		Ok(Cursor::new(self.bytes[index]))
	}
}
