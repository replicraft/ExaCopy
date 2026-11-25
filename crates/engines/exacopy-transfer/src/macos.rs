//! Operation policies, records, and capability contracts for managed APFS copies.

pub mod inspection;
pub mod job;
pub mod plan;
pub mod receipt;
pub mod replay;

#[cfg(test)]
mod journal_fixture;
