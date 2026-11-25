use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_ssh::{ReadOnlySftp, RemotePositionedRead};

use super::{FixtureResult, Reference, protected_file, run_fixture};

const FILE_NAME: &str = "sparse.bin";
const SUFFIX_OFFSET: u64 = (1 << 32) + 123;
const PREFIX: &[u8] = b"prefix";
const SUFFIX: &[u8] = b"positioned OpenSSH";
const FILE_LENGTH: u64 = SUFFIX_OFFSET + SUFFIX.len() as u64;
const MAX_ALLOCATED_BLOCKS: u64 = 2048;
const SPARSE_PROBE_OFFSET: u64 = 2 * 1024 * 1024;

#[tokio::test]
#[ignore = "requires a private OpenSSH daemon with loopback and sparse fixture storage"]
async fn reads_sparse_positioned_windows_from_a_private_openssh_subsystem() {
	run_fixture(Reference::Positioned).await;
}

pub(super) fn create(directory: &Path) -> FixtureResult<()> {
	let mut file = protected_file(&directory.join(FILE_NAME))?;
	file.write_all(PREFIX)?;
	file.seek(SeekFrom::Start(SPARSE_PROBE_OFFSET))?;
	file.write_all(&[0])?;
	ensure_sparse(&file)?;
	file.set_len(PREFIX.len() as u64)?;
	file.seek(SeekFrom::Start(SUFFIX_OFFSET))?;
	file.write_all(SUFFIX)?;
	let metadata = file.metadata()?;
	assert_eq!(metadata.len(), FILE_LENGTH);
	ensure_sparse(&file)?;
	Ok(())
}

fn ensure_sparse(file: &File) -> io::Result<()> {
	if file.metadata()?.blocks() > MAX_ALLOCATED_BLOCKS {
		return Err(io::Error::other(
			"fixture profile must support sparse files",
		));
	}
	Ok(())
}

pub(super) async fn check(sftp: &mut ReadOnlySftp) -> FixtureResult<()> {
	let path = [UnixComponent::new(FILE_NAME.as_bytes())?];
	let mut source = sftp.open_positioned(&path).await?;
	assert_eq!(source.observation().length, FILE_LENGTH);
	check_window(&mut source, SUFFIX_OFFSET, SUFFIX).await?;
	check_window(&mut source, 0, PREFIX).await?;
	check_window(&mut source, SUFFIX_OFFSET - 8, &[0; 8]).await?;
	let observed = source.observation();
	assert_eq!(source.finish().await?, observed);
	assert_eq!(sftp.stat(&path).await?, observed);
	Ok(())
}

async fn check_window(
	source: &mut RemotePositionedRead<'_>,
	offset: u64,
	expected: &[u8],
) -> FixtureResult<()> {
	let file = source.observation();
	let mut window = source.begin_window(offset, expected.len() as u64).await?;
	let mut chunk = [0; 8];
	let mut remaining = expected;
	while !remaining.is_empty() {
		let count = window.read_next(&mut chunk).await?;
		assert!(count > 0);
		assert_eq!(chunk[..count], remaining[..count]);
		remaining = &remaining[count..];
	}
	assert_eq!(window.read_next(&mut chunk).await?, 0);
	let completed = window.finish().await?;
	assert_eq!(
		(completed.offset(), completed.length(), completed.file()),
		(offset, expected.len() as u64, file)
	);
	Ok(())
}
