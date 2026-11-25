//! Deterministic, in-memory storage fixtures for ExaCopy tests.
#![forbid(unsafe_code)]

mod fault;
mod namespace;
mod simulator;

pub use fault::{
	EffectError, EffectFault, EffectOperation, Failure, Rejection, TransferFault, TransferOperation,
};
pub use namespace::{Area, DiskId, Entry, FileView, ObjectId, Snapshot, WritableArea};
pub use simulator::{QuiescedStage, ReadHandle, Simulator, StageWriter};
