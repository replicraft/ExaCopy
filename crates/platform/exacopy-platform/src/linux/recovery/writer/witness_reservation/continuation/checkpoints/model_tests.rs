use exacopy_model::retained_prefix::{
	Continuation, Guard, History, Live, Pass, PrefixProof, Prior,
};

use super::{ADOPTED_END, Frames, SOURCE_END, boundary, hex, nonzero};

pub(super) fn continued_model(frames: &Frames) -> (Continuation, Pass, Live) {
	let guard = Guard {
		authority: [1; 32],
		stage: [2; 32],
		lease: [3; 32],
	};
	let pass = Pass {
		run: nonzero(2),
		source: nonzero(9),
	};
	let prior = Prior {
		guard,
		head: frames.prior,
		preparation: boundary(4, 1339, &frames.journal[..1339]),
		pass: Pass {
			run: nonzero(1),
			source: nonzero(7),
		},
		checkpoint_end: 2,
		authorized_end: ADOPTED_END,
		history: History::CleanCapture,
		writer_quiesced: true,
	};
	let proof = PrefixProof {
		local_end: ADOPTED_END,
		compared_end: ADOPTED_END,
		rehashed_end: 2,
		digest: hex("f3dd21f0f2a842321e46fd8656d154b5eb1edda694a962399b683b9fb21a58df")
			.try_into()
			.unwrap(),
	};
	let mut state = Continuation::begin(prior, pass, proof, SOURCE_END).unwrap();
	let live = Live {
		guard,
		head: frames.prior,
		source: pass.source,
		local_end: ADOPTED_END,
	};
	state.prefix_barrier(live, state.basis()).unwrap();
	let live = Live {
		head: frames.continued,
		..live
	};
	state
		.continued(live, state.basis(), frames.continued)
		.unwrap();
	(state, pass, live)
}
