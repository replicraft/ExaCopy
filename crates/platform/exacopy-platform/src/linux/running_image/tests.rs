use exacopy_endpoint::ReadView as _;

use super::RunningExecutable;

#[test]
fn pins_the_running_elf_and_refuses_reads_outside_its_observed_extent() {
	let image = RunningExecutable::open().unwrap();
	let mut magic = [0; 4];
	image.read_exact_at(0, &mut magic).unwrap();
	assert_eq!(magic, *b"\x7fELF");
	let mut byte = [0];
	image.read_exact_at(image.length() - 1, &mut byte).unwrap();
	assert!(image.read_exact_at(image.length(), &mut byte).is_err());
	assert!(image.read_exact_at(u64::MAX, &mut byte).is_err());
	image.read_exact_at(image.length(), &mut []).unwrap();
	image.recheck_observation().unwrap();
}

#[path = "../../../tests/unit/running_image.rs"]
mod size_admission;
