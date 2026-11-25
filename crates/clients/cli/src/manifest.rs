use std::io::Write;
use std::path::Path;

use crate::args::Format;
use crate::manifest_report::{ErrorCode, Failure, Outcome};

pub(crate) fn create(path: &Path, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
	let result = create_manifest(path).and_then(|json| {
		stdout
			.write_all(&json)
			.and_then(|()| writeln!(stdout))
			.and_then(|()| stdout.flush())
			.map_err(|error| {
				Failure::new(ErrorCode::Io, "could not write the manifest baseline")
					.with_source(error)
			})
	});
	match result {
		Ok(()) => 0,
		Err(error) => {
			let _ = error.write_human(stderr);
			error.exit_code()
		}
	}
}

pub(crate) fn verify(
	path: &Path,
	baseline: &Path,
	format: Format,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let outcome =
		verify_manifest(path, baseline).unwrap_or_else(|error| Outcome::Inconclusive { error });
	match outcome.write(format, stdout, &mut *stderr) {
		Ok(()) => outcome.exit_code(),
		Err(error) => {
			let _ = error.write_human(stderr);
			error.exit_code()
		}
	}
}

#[cfg(target_os = "linux")]
use linux::{create_manifest, verify_manifest};

#[cfg(not(target_os = "linux"))]
fn create_manifest(_: &Path) -> Result<Vec<u8>, Failure> {
	Err(Failure::new(
		ErrorCode::Unsupported,
		"manifest creation requires Linux",
	))
}

#[cfg(not(target_os = "linux"))]
fn verify_manifest(_: &Path, _: &Path) -> Result<Outcome, Failure> {
	Err(Failure::new(
		ErrorCode::Unsupported,
		"manifest verification requires Linux",
	))
}

#[cfg(target_os = "linux")]
mod linux {
	use std::error::Error;
	use std::fmt;
	use std::path::Path;

	use exacopy_codec::{MAX_MANIFEST_JSON_BYTES, ManifestError, SingleFileManifest};
	use exacopy_content::{MeasureError, StreamInputError};
	use exacopy_endpoint::{IoError, ReadView, UnixComponent};
	use exacopy_engine::linux::NamedReadView;
	use exacopy_platform::linux::{ReadError, ReadRoot};
	use exacopy_transfer::manifest::{self, VerifyDecision};
	use rustix::io::Errno;
	use uuid::{Builder, Uuid};

	use crate::linux_path::{open_directory, split};
	use crate::manifest_report::{Difference, ErrorCode, Failure, Observation, Outcome};
	use crate::profile::{ProfileError, kernel_random};

	const MEASUREMENT_BUFFER_BYTES: usize = 256 * 1024;

	pub(super) fn create_manifest(path: &Path) -> Result<Vec<u8>, Failure> {
		let (root, name) = select(path, Input::Target)?;
		let view = open(&root, name, Input::Target)?;
		let manifest_id = random_uuid()?;
		let root_id = random_uuid()?;

		let mut scratch = vec![0; MEASUREMENT_BUFFER_BYTES];
		let observed = manifest::measure(&view, &mut scratch).map_err(measurement_failure)?;
		SingleFileManifest::new(
			manifest_id,
			root_id,
			name.as_bytes(),
			observed.length,
			observed.digest,
		)
		.map_err(|error| {
			Failure::new(ErrorCode::Unsupported, "file exceeds the manifest profile")
				.with_source(error)
		})?
		.to_json()
		.map_err(|error| {
			Failure::new(ErrorCode::Io, "could not encode the manifest baseline").with_source(error)
		})
	}

	pub(super) fn verify_manifest(path: &Path, baseline: &Path) -> Result<Outcome, Failure> {
		with_baseline(baseline, |expected| verify_target(path, expected))
	}

	fn with_baseline(
		path: &Path,
		verify: impl FnOnce(&SingleFileManifest) -> Result<Outcome, Failure>,
	) -> Result<Outcome, Failure> {
		let (root, name) = select(path, Input::Baseline)?;
		let view = open(&root, name, Input::Baseline)?;
		let expected = read_baseline(&view)?;
		let outcome = verify(&expected)?;

		// The transfer policy checks the source after measurement. Keep the
		// baseline bound through that observation before reporting its result.
		view.recheck_observation()
			.map_err(|error| read_failure(Input::Baseline, error))?;
		Ok(outcome)
	}

	fn verify_target(path: &Path, expected: &SingleFileManifest) -> Result<Outcome, Failure> {
		let (parent, name) =
			split(path).map_err(|error| Input::Target.invalid().with_source(error))?;
		// The recorded root ID is a logical label. Only the explicit CLI
		// argument selects the local parent and exact basename bytes.
		if name.as_bytes() != expected.basename() {
			return Err(Failure::new(
				ErrorCode::BaselineScope,
				"selected file basename differs from the manifest baseline",
			));
		}

		let root = bind(parent, Input::Target)?;
		let view = open(&root, name, Input::Target)?;
		let mut scratch = vec![0; MEASUREMENT_BUFFER_BYTES];
		let decision =
			manifest::verify(&view, expected, &mut scratch).map_err(measurement_failure)?;
		Ok(comparison(expected, decision))
	}

	fn read_baseline(view: &NamedReadView<'_>) -> Result<SingleFileManifest, Failure> {
		let length = usize::try_from(view.length())
			.ok()
			.filter(|length| *length <= MAX_MANIFEST_JSON_BYTES)
			.ok_or_else(|| {
				Failure::new(
					ErrorCode::InvalidBaseline,
					"manifest baseline exceeds the JSON byte limit",
				)
			})?;
		let mut bytes = vec![0; length];
		view.recheck_observation()
			.and_then(|()| view.read_exact_at(0, &mut bytes))
			.and_then(|()| view.recheck_observation())
			.map_err(|error| read_failure(Input::Baseline, error))?;
		SingleFileManifest::from_json(&bytes).map_err(baseline_failure)
	}

	fn comparison(expected: &SingleFileManifest, decision: VerifyDecision) -> Outcome {
		match decision {
			VerifyDecision::Match(observed) => Outcome::Verified {
				observation: Observation::new(observed.length),
			},
			VerifyDecision::LengthMismatch(observed) => Outcome::Mismatch {
				observation: Observation::new(observed.length),
				difference: Difference::Length {
					expected: expected.length().to_string(),
					observed: observed.length.to_string(),
				},
			},
			VerifyDecision::DigestMismatch(observed) => Outcome::Mismatch {
				observation: Observation::new(observed.length),
				difference: Difference::Digest {
					expected: digest_hex(expected.content_digest()),
					observed: digest_hex(observed.digest),
				},
			},
		}
	}

	fn digest_hex(digest: [u8; 32]) -> String {
		use std::fmt::Write as _;

		let mut hex = String::with_capacity(64);
		for byte in digest {
			let _ = write!(hex, "{byte:02x}");
		}
		hex
	}

	#[derive(Clone, Copy)]
	enum Input {
		Target,
		Baseline,
	}

	impl Input {
		const fn invalid(self) -> Failure {
			match self {
				Self::Target => Failure::new(
					ErrorCode::InvalidInput,
					"input file path is invalid or missing",
				),
				Self::Baseline => Failure::new(
					ErrorCode::InvalidBaseline,
					"manifest baseline path is invalid or missing",
				),
			}
		}

		const fn stale(self) -> Failure {
			let message = match self {
				Self::Target => "input file observation changed while it was held",
				Self::Baseline => "manifest baseline observation changed while it was held",
			};
			Failure::new(ErrorCode::Stale, message)
		}

		const fn unsupported(self) -> Failure {
			let message = match self {
				Self::Target => "input file is outside the supported Linux read profile",
				Self::Baseline => "manifest baseline is outside the supported Linux read profile",
			};
			Failure::new(ErrorCode::Unsupported, message)
		}

		const fn io(self) -> Failure {
			let message = match self {
				Self::Target => "could not observe or read the input file",
				Self::Baseline => "could not observe or read the manifest baseline",
			};
			Failure::new(ErrorCode::Io, message)
		}
	}

	fn select(path: &Path, input: Input) -> Result<(ReadRoot, UnixComponent<'_>), Failure> {
		let (parent, name) = split(path).map_err(|error| input.invalid().with_source(error))?;
		Ok((bind(parent, input)?, name))
	}

	fn bind(parent: &std::ffi::OsStr, input: Input) -> Result<ReadRoot, Failure> {
		let directory = open_directory(parent)
			.map_err(|error| system_failure(input, Some(error)).with_source(error))?;
		ReadRoot::from_directory(directory).map_err(|error| read_failure(input, error))
	}

	fn open<'root>(
		root: &'root ReadRoot,
		name: UnixComponent<'root>,
		input: Input,
	) -> Result<NamedReadView<'root>, Failure> {
		NamedReadView::open(root, name).map_err(|error| read_failure(input, error))
	}

	fn read_failure(input: Input, error: ReadError) -> Failure {
		classify_read_failure(input, &error).with_source(error)
	}

	fn classify_read_failure(input: Input, error: &ReadError) -> Failure {
		match error {
			ReadError::IdentityChanged
			| ReadError::SourceChanged
			| ReadError::UnexpectedDataAfterEnd
			| ReadError::Io(IoError::UnexpectedEof { .. }) => input.stale(),
			ReadError::NotRegularFile
			| ReadError::UnsupportedProcfs
			| ReadError::InvalidLength
			| ReadError::InvalidTimestamp => input.unsupported(),
			ReadError::NotDirectory => input.invalid(),
			ReadError::System(error) => system_failure(input, Errno::from_io_error(error)),
			_ => input.io(),
		}
	}

	fn system_failure(input: Input, error: Option<Errno>) -> Failure {
		match error {
			Some(Errno::NOENT | Errno::NOTDIR | Errno::NAMETOOLONG) => input.invalid(),
			Some(Errno::LOOP | Errno::XDEV | Errno::NOSYS | Errno::NOTSUP) => input.unsupported(),
			_ => input.io(),
		}
	}

	fn baseline_failure(error: ManifestError) -> Failure {
		let failure = match error {
			ManifestError::Unsupported(_) => Failure::new(
				ErrorCode::Unsupported,
				"manifest baseline requires an unsupported version or feature",
			),
			ManifestError::Integrity => Failure::new(
				ErrorCode::BaselineIntegrity,
				"manifest baseline body digest does not match",
			),
			ManifestError::Invalid(_) => {
				Failure::new(ErrorCode::InvalidBaseline, "manifest baseline is invalid")
			}
		};
		failure.with_source(error)
	}

	fn measurement_failure(error: manifest::Error<ReadError>) -> Failure {
		let failure = match &error {
			manifest::Error::InitialObservation(error)
			| manifest::Error::Measure(MeasureError::Read { source: error, .. })
			| manifest::Error::FinalObservation(error) => classify_read_failure(Input::Target, error),
			manifest::Error::Measure(MeasureError::InvalidInput(
				StreamInputError::FileTooLong { .. },
			)) => Input::Target.unsupported(),
			manifest::Error::Measure(MeasureError::InvalidInput(_)) => Input::Target.io(),
		};
		failure.with_source(error)
	}

	// ProfileError predates the standard error chain. Retain the error value
	// while exposing only its native I/O cause through this boundary.
	#[derive(Debug)]
	struct EntropyError(ProfileError);

	impl fmt::Display for EntropyError {
		fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			formatter.write_str("kernel entropy unavailable")
		}
	}

	impl Error for EntropyError {
		fn source(&self) -> Option<&(dyn Error + 'static)> {
			match &self.0 {
				ProfileError::Io(error) => Some(error),
				_ => None,
			}
		}
	}

	fn random_uuid() -> Result<Uuid, Failure> {
		let mut bytes = [0; 16];
		kernel_random(&mut bytes).map_err(entropy_failure)?;
		Ok(Builder::from_random_bytes(bytes).into_uuid())
	}

	fn entropy_failure(error: ProfileError) -> Failure {
		Failure::new(
			ErrorCode::Io,
			"could not obtain manifest identifier entropy",
		)
		.with_source(EntropyError(error))
	}

	#[cfg(test)]
	mod tests {
		use std::fs::{self, File};
		use std::path::PathBuf;

		use super::*;

		#[test]
		fn invalid_body_digest_never_admits_the_target_reader() {
			let manifest = SingleFileManifest::new(
				random_uuid().unwrap(),
				random_uuid().unwrap(),
				b"file",
				0,
				[0; 32],
			)
			.unwrap();
			let mut body: serde_json::Value =
				serde_json::from_slice(&manifest.to_json().unwrap()).unwrap();
			body["digest"] = serde_json::Value::String("00".repeat(32));

			let path = std::env::temp_dir().join(random_uuid().unwrap().to_string());
			let mut output = File::create_new(&path).unwrap();
			let baseline = TempBaseline(path);
			serde_json::to_writer(&mut output, &body).unwrap();
			drop(output);

			let failure = with_baseline(&baseline.0, |_| panic!("target reader admitted"))
				.err()
				.expect("baseline integrity failure");
			assert_eq!(failure.exit_code(), 5);
			assert_eq!(
				failure.source().and_then(|cause| cause.downcast_ref()),
				Some(&ManifestError::Integrity),
			);
		}

		#[test]
		fn measurement_failure_keeps_offset_phase_and_native_errno() {
			let error = manifest::Error::Measure(MeasureError::Read {
				offset: 4096,
				source: ReadError::Io(IoError::System {
					offset: 4097,
					source: Errno::IO.into(),
				}),
			});
			let failure = measurement_failure(error);
			assert_eq!(failure.exit_code(), 4);
			let retained = failure
				.source()
				.and_then(|error| error.downcast_ref::<manifest::Error<ReadError>>());
			assert!(matches!(
				retained,
				Some(manifest::Error::Measure(MeasureError::Read {
					offset: 4096,
					source: ReadError::Io(IoError::System { offset: 4097, .. }),
				}))
			));
			let json = serde_json::to_value(failure).unwrap();
			assert_eq!(json["os_code"], Errno::IO.raw_os_error().to_string());
		}

		struct TempBaseline(PathBuf);

		impl Drop for TempBaseline {
			fn drop(&mut self) {
				let _ = fs::remove_file(&self.0);
			}
		}
	}
}
