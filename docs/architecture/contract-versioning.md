# Contract versioning and migration

This document defines compatibility admission and migration policy. The
[contract inventory](../specs/contracts/versions.toml) records current
identifiers and version markers. The owning codec or interface specification
defines the exact representation and valid values. A crate or binary
version never substitutes for a contract marker.

Run the source and inventory gate with
`cargo run --locked -p xtask -- check-contracts`. The aggregate
`xtask check` also runs it. It validates the inventory schema, checks
the status and owner of each required entry, and reads the version,
required-feature and magic literals from the owning Rust syntax.
Adding, moving or retiring a contract requires updating its binding
and the inventory in the same change. The gate covers declared markers.
Serializer and decoder tests establish field-level behavior. The implemented
portable manifest profile covers one unsigned single-file manifest with one
unnamed BLAKE3 stream. The gate binds its JSON schema version to the owning
source literal. The codec's golden vectors exercise its canonical CBOR version.

On Linux, run the CLI probe against a native build.

```sh
cargo build --locked -p exacopy-cli
python3 -B tools/contracts/check_cli.py target/debug/exacopy
```

The probe compares emitted diff, copy and recovery inspection markers
against the inventory. It generates a disposable file pair, a private
profile and a retained job in an isolated temporary directory. The
profile seed is generated for the fixture and removed with it. The probe
also checks the source and copied bytes. The managed APFS comparison
report is exercised by the macOS CLI tests.

The [Linux compatibility run](migration-evidence.md) exercises retained
jobs in both directions between two native builds and includes refusal controls.

## Contract boundaries

| Contract | Policy |
| --- | --- |
| CLI machine-readable results | Version each report schema independently. A compatible change preserves existing field shapes, units, result meanings and exit-code meanings. A consumer may ignore optional additions only where its schema permits them. Select a new major/report schema for incompatible changes. |
| Configuration and saved connection profiles | Give each persisted schema a distinct marker and validate configuration before application. Keep credentials outside transferable settings and preserve explicit authority when importing. The current local owner seed has its own private fixed-size layout. |
| Transfer journals and job artifacts | Version framing and each changeable record family separately. Bind owner, plan, journal, ranges and receipts to the same physical identity, attempt, profile and content evidence. Reconcile unsupported or inconsistent artifacts without changing them. Private scope does not remove recovery obligations. |
| Backup repositories | Version root, object and index families explicitly. Advertise required features before write admission. A repository is only readable when its committed root and required reachable data can be authenticated and decoded. Migration must preserve a restorable committed root and required keys. |
| Portable manifests | Version schema and canonical integrity domain independently of private recovery state. Validate required features, exact units, identity and path rules before using a manifest to authorize effects. |
| IPC, MCP and native remote messages | Version each interface, select only a mutually supported protocol and explicitly negotiate required features. Bind selected versions and capability claims to authorization. Unsupported peers receive an error before data or effect admission. |
| Public library APIs | Use the published crate's semantic version for the Rust API and list exact supported persisted and wire contract versions independently. Coordinate breaking changes with affected consumers. Workspace crate versions currently identify development packages. |

For extensible contracts, a major marks compatibility boundaries and the
contract defines how a reader may accept later minor versions and optional
fields. A required feature must be understood and enabled by both parties
where applicable. Closed formats accept only explicitly implemented
versions and feature combinations. Invalid, corrupt or unsupported formats
must produce a typed diagnostic before mutation. Preserve a safe read-only
diagnostic path where the relevant prefix can be identified without
assuming the format's meaning. A recognized prefix is insufficient to
replay an effect.

## Recoverable migration procedure

A migration needs an explicit source-version, target-version, platform and
feature profile. Its qualified procedure must satisfy these steps.

1. Inspect under the required ownership and exclusion controls. Authenticate
   the original artifacts and establish their identity and latest recoverable
   state. Reconcile any uncertain publication before considering conversion.
   Refuse if any required format, feature or key is unavailable.
2. Retain the exact original committed representation and its recovery
   material. Build the candidate in an owned, isolated namespace. Carry
   forward job identity, limits, provenance and last confirmed state. A
   conversion cannot create verification, publication or durability evidence.
3. Read back the candidate with the target reader and independently check
   semantic equivalence. For a repository this includes reachable objects
   and restoration of representative fixtures. Bind the target artifacts to
   the original identities and the selected versions.
4. Publish the candidate only after the required barriers and durable
   migration intent, using the contract's qualified publication primitive.
   Record a migration receipt. On interruption, reopen the artifacts and
   reconcile before taking a further effect. Re-running must be idempotent.
5. Keep the original representation, keys and a usable reader available
   through the declared rollback window. Clean-up requires a separate,
   reviewed policy after the successor is verified and retained recovery
   paths have been checked.

A release must publish an upgrade and downgrade compatibility table
for every affected format and profile. An upgrade must either retain a
qualified reader and recovery path for existing jobs and repositories or
refuse the change while the current release can still recover them. A
downgrade may reopen the retained compatible generation or refuse writable
access and preserve the newer store for its qualified reader. If the
newer generation contains subsequent jobs or backups, rollback must preserve
those generations and make their recovery path explicit. Never let an older
binary reinitialize an unsupported store.

Test unchanged-format upgrade and downgrade, golden old-reader/new-reader
fixtures, unknown versions and required features, wrong profile or keys,
disk or flush failure, a crash before and after each persistent boundary,
a second crash during reconciliation, and idempotent repeated recovery.
Test recovery as well as successful conversion. Scope the qualification to
the tested format, operation and filesystem profile.

The current implementation provides profile-bound job replay within the
documented formats. Automated cross-version migration, a supported
upgrade/downgrade matrix, and the planned format families in the inventory
remain open.
