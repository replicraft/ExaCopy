use serde::Serialize;

use super::JobReport;
#[cfg(feature = "experimental-verified-prefix-resume")]
use super::RetainedWitnessReport;
#[cfg(feature = "experimental-verified-prefix-resume")]
use crate::assembly::linux::ArchivedWitnessedSelection;

#[derive(Serialize)]
pub(super) struct PublishedReceipt {
	#[serde(flatten)]
	pub(super) job: JobReport,
	pub(super) length: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) blake3: Option<String>,
	pub(super) receipt_digest: String,
	pub(super) qualification_digest: String,
	pub(super) metadata_policy: &'static str,
	pub(super) omissions: Vec<&'static str>,
	#[cfg(feature = "experimental-verified-prefix-resume")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) retained_witness: Option<RetainedWitnessReport>,
	#[cfg(feature = "experimental-verified-prefix-resume")]
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_archive"
	)]
	pub(super) archive_selection: Option<Box<ArchivedWitnessedSelection>>,
}

#[cfg(feature = "experimental-verified-prefix-resume")]
fn serialize_archive<S: serde::Serializer>(
	selection: &Option<Box<ArchivedWitnessedSelection>>,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	match selection {
		Some(selection) => {
			crate::witness_archive::report_selection(selection).serialize(serializer)
		}
		None => serializer.serialize_none(),
	}
}
