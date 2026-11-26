use std::sync::MutexGuard;
use std::time::Instant;

use super::{RouteState, RouteTask};

pub(in crate::assembly::linux) struct HeldRouteEffect<'guard> {
	_route: MutexGuard<'guard, RouteState>,
}

impl RouteTask {
	pub(in super::super) fn enter_after_approval(&self) -> Option<HeldRouteEffect<'_>> {
		let active = self.lease.activity.active.lock().ok()?;
		active
			.current(Instant::now())
			.then_some(HeldRouteEffect { _route: active })
	}
}
