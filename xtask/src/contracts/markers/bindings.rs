use super::{Binding, Marker};

pub(in crate::contracts) const BINDINGS: &[Binding] = &[
	Binding::new(
		"workflow-sync-recreate-plan",
		"crates/formats/exacopy-plan/src/workflow_sync/recreate.rs",
		Marker::Workflow {
			features: "REQUIRED_FEATURES",
		},
	),
	Binding::new(
		"workflow-sync-recreate-actions",
		"crates/formats/exacopy-plan/src/workflow_sync/recreate.rs",
		Marker::NamedDocumentPage {
			version: "ACTION_PAGE_VERSION",
		},
	),
	Binding::new(
		"exacopy.cli.remote_download",
		"apps/exacopy-cli/src/remote_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.witnessed_remote_download",
		"apps/exacopy-cli/src/remote_report/witness.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.witnessed_remote_inspection",
		"apps/exacopy-cli/src/remote_inspect_witness/report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.apfs_recovery_inspection",
		"apps/exacopy-cli/src/apfs_inspect/report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.managed_sync_recreate_plan",
		"apps/exacopy-cli/src/sync_preview/managed_command/recreate.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.windows_bootstrap_inspection",
		"apps/exacopy-cli/src/windows_bootstrap_inspect.rs",
		Marker::Report,
	),
	Binding::new(
		"workflow-local-sync-endpoint",
		"crates/formats/exacopy-plan/src/workflow_sync/wire.rs",
		Marker::Workflow {
			features: "ENDPOINT_REQUIRED_FEATURES",
		},
	),
	Binding::new(
		"workflow-sync-genesis-root",
		"crates/formats/exacopy-plan/src/workflow_sync/wire.rs",
		Marker::Workflow {
			features: "ROOT_REQUIRED_FEATURES",
		},
	),
	Binding::new(
		"exacopy.cli.verify",
		"apps/exacopy-cli/src/manifest_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.diff",
		"apps/exacopy-cli/src/report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.cli.copy",
		"apps/exacopy-cli/src/copy_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.local_recovery_inspection",
		"apps/exacopy-cli/src/recovery_report.rs",
		Marker::Report,
	),
	Binding::new(
		"exacopy.public_stage_inspection",
		"apps/exacopy-cli/src/public_stage_inspect.rs",
		Marker::Report,
	),
	Binding::new(
		"portable-manifests",
		"crates/formats/exacopy-manifest/src/manifest/json.rs",
		Marker::Manifest,
	),
	Binding::new(
		"public-plan-entries-page",
		"crates/formats/exacopy-plan/src/plan_entries/wire.rs",
		Marker::DocumentPage,
	),
	Binding::new(
		"workflow-paired-baseline-leaf",
		"crates/formats/exacopy-manifest/src/sync_baseline/wire.rs",
		Marker::DocumentPage,
	),
	Binding::new(
		"public-plan-body",
		"crates/formats/exacopy-plan/src/plan/wire.rs",
		Marker::PlanBody,
	),
	Binding::new(
		"public-plan-json",
		"crates/formats/exacopy-plan/src/plan/json.rs",
		Marker::PlanJson,
	),
	Binding::new(
		"local-journal-frame",
		"crates/storage/exacopy-journal/src/frame.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: Some("MAGIC"),
		},
	),
	Binding::new(
		"windows-fixed-ntfs-bootstrap",
		"crates/storage/exacopy-journal/src/windows_bootstrap/codec.rs",
		Marker::pair("VERSION_MAJOR", "VERSION_MINOR", "ROLE_BINDING_REQUIRED"),
	),
	Binding::new(
		"windows-fresh-capture-journal",
		"crates/storage/exacopy-journal/src/windows_capture/codec.rs",
		Marker::array("VERSION", 2),
	),
	Binding::new(
		"linux-owner",
		"crates/storage/exacopy-journal/src/owner/codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-owner",
		"crates/storage/exacopy-journal/src/owner/apply_codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-copy-plan",
		"crates/engines/exacopy-transfer/src/linux/plan/wire.rs",
		Marker::array("VERSION", 2),
	),
	Binding::new(
		"linux-prepared",
		"crates/storage/exacopy-journal/src/prepared/wire.rs",
		Marker::pair("VERSION_MAJOR", "VERSION_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-publication-intent",
		"crates/storage/exacopy-journal/src/intent.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-intent",
		"crates/storage/exacopy-journal/src/intent/public_apply.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-range-page",
		"crates/storage/exacopy-journal/src/verification_records/ranges.rs",
		Marker::Scalar {
			version: "PAGE_FORMAT_VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-copy-receipt",
		"crates/engines/exacopy-transfer/src/linux/receipt.rs",
		Marker::pair("MAJOR_VERSION", "MINOR_VERSION", "REQUIRED_FEATURES"),
	),
	Binding::new(
		"linux-public-apply-receipt",
		"crates/engines/exacopy-transfer/src/linux/receipt/public_apply.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-resolved-direct-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("RESOLVED_DIRECT_VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-absolute-path-owner",
		"crates/storage/exacopy-journal/src/remote_download/owner.rs",
		Marker::array("ABSOLUTE_PATH_VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-records",
		"crates/storage/exacopy-journal/src/remote_download/records/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-download-finalization",
		"crates/storage/exacopy-journal/src/remote_download/finalization/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-capture-retirement",
		"crates/storage/exacopy-journal/src/remote_download/retirement/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-capture-continuation",
		"crates/storage/exacopy-journal/src/remote_download/continuation/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-local-public-apply-qualification",
		"apps/exacopy-cli/src/assembly/linux/public_stage/qualification/record.rs",
		Marker::MagicSuffix {
			magic: "MAGIC",
			width: 2,
		},
	),
	Binding::new(
		"linux-remote-destination-qualification",
		"crates/storage/exacopy-journal/src/remote_download/qualification/wire.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-remote-continued-checkpoint",
		"crates/storage/exacopy-journal/src/remote_download/continuation/checkpoint.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-continuation-qualification",
		"crates/storage/exacopy-journal/src/remote_download/qualification/continuation/wire.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"linux-remote-download-receipt",
		"crates/storage/exacopy-journal/src/remote_download/finalization/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-witness-intent",
		"crates/storage/exacopy-journal/src/remote_download/witness/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-witness-receipt-ready",
		"crates/storage/exacopy-journal/src/remote_download/witness/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-witness-closeout-phases",
		"crates/storage/exacopy-journal/src/remote_download/witness/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"linux-remote-stage-directory-bootstrap",
		"crates/storage/exacopy-journal/src/remote_download/bootstrap.rs",
		Marker::Scalar {
			version: "VERSION",
			magic: None,
		},
	),
	Binding::new(
		"darwin-managed-apfs-owner",
		"crates/storage/exacopy-journal/src/owner/darwin_codec.rs",
		Marker::pair("FORMAT_MAJOR", "FORMAT_MINOR", "MANAGED_APFS_REQUIRED"),
	),
	Binding::new(
		"darwin-managed-apfs-copy-plan",
		"crates/engines/exacopy-transfer/src/macos/plan/wire.rs",
		Marker::array("VERSION", 3),
	),
	Binding::new(
		"darwin-managed-apfs-prepared",
		"crates/storage/exacopy-journal/src/darwin_prepared/wire.rs",
		Marker::pair("VERSION_MAJOR", "VERSION_MINOR", "MANAGED_APFS_REQUIRED"),
	),
	Binding::new(
		"darwin-managed-apfs-copy-receipt",
		"crates/engines/exacopy-transfer/src/macos/receipt/wire.rs",
		Marker::array("VERSION", 3),
	),
];
