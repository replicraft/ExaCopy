use super::*;

#[test]
fn pages_open_refuses_an_incumbent_symlink() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let path = fixture.output.join("pages");
	let target = fixture.scratch.path("source");
	symlink(&target, &path).expect("create fixture pages alias to protected input");
	assert!(matches!(
		bundle.open_pages(),
		Err(PlanBundleError::Unsafe(Some(error)))
			if error.raw_os_error() == Some(Errno::LOOP.raw_os_error())
				|| error.raw_os_error() == Some(Errno::NOTDIR.raw_os_error())
	));
	assert_eq!(
		fs::read_link(&path).expect("observe preserved pages alias"),
		target
	);
	assert_absent(&target.join(PAGE_NAME));
	assert_absent(&fixture.output.join(OUTPUT_NAME));
	fixture.assert_inputs_preserved();
}

#[test]
fn detached_directories_propagate_creation_errors_without_rebinding() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let path = fixture.output.join("pages");
	let pages = bundle.open_pages().expect("create and hold empty pages");
	fs::remove_dir(&path).expect("detach empty pages while its descriptor is held");
	assert!(matches!(
		bundle.create_page(&pages, component(PAGE_NAME), PAGE),
		Err(PlanBundleError::Io(error)) if error.raw_os_error() == Some(Errno::NOENT.raw_os_error())
	));
	assert_absent(&path);
	assert_absent(&fixture.output.join(OUTPUT_NAME));

	fs::remove_dir(&fixture.output).expect("detach empty bundle while its descriptor is held");
	assert!(matches!(
		bundle.open_pages(),
		Err(PlanBundleError::Io(error)) if error.raw_os_error() == Some(Errno::NOENT.raw_os_error())
	));
	assert_absent(&fixture.output);
	fixture.assert_inputs_preserved();
}

#[test]
fn retained_records_refuse_same_byte_replacements_by_name() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let pages = bundle.open_pages().expect("hold pages");
	let page_name = component(PAGE_NAME);
	let page = require_created(
		bundle
			.create_page(&pages, page_name, PAGE)
			.expect("create page before substitution"),
	);
	let output = bundle
		.create_output(OUTPUT)
		.expect("create envelope before substitution");

	for (path, bytes) in [
		(fixture.output.join("pages").join(PAGE_NAME), PAGE),
		(fixture.output.join(OUTPUT_NAME), OUTPUT),
	] {
		let saved = path.with_extension("saved");
		fs::rename(&path, &saved).expect("retain original under another fixture name");
		fs::write(&path, bytes).expect("install byte-identical fixture replacement");
		fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
			.expect("match original permissions on fixture replacement");
		assert_ne!(identity(&path), identity(&saved));
		assert_eq!(
			fs::read(&saved).expect("read moved original fixture record"),
			bytes
		);
	}

	assert!(matches!(
		bundle.check_page(&pages, page_name, &page),
		Err(PlanBundleError::Conflict)
	));
	assert!(matches!(
		bundle.check_output(&output),
		Err(PlanBundleError::Conflict)
	));
	assert_eq!(
		fs::read(fixture.output.join("pages").join(PAGE_NAME)).expect("read replacement page"),
		PAGE
	);
	assert_eq!(
		fs::read(fixture.output.join(OUTPUT_NAME)).expect("read replacement envelope"),
		OUTPUT
	);
	fixture.assert_inputs_preserved();
}
