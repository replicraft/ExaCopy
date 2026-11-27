use super::*;

pub(super) fn inspect_retained_stage_and_unrelated_destination() {
	let fixture = Fixture::new();
	fs::create_dir(&fixture.destination).unwrap();
	let private = fixture.stage.join("stage");
	let public = fixture.destination.join("public");
	let identity = create_bytes(&private, DATA);

	let directory_id =
		|path: &Path| observe(open_parent(path, 0).as_handle(), Kind::Directory).unwrap();
	let root_identity = directory_id(&fixture.scope);
	let destination_name = WindowsComponent::new(DESTINATION).unwrap();
	let binding = WindowsPublicationBinding {
		model: model(2),
		stage_parent: directory_id(&fixture.stage),
		stage: identity,
		destination_parent: directory_id(&fixture.destination),
		stage_name: WindowsComponent::new(STAGE).unwrap(),
		target_name: WindowsComponent::new(PUBLIC).unwrap(),
	};

	let root_file = open_parent(&fixture.scope, 0);
	let stage_file = open_parent(&fixture.stage, 0);
	let stage_directory =
		WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
	assert_eq!(
		observe(stage_file.as_handle(), Kind::Directory).unwrap(),
		binding.stage_parent
	);
	let retained = stage_directory
		.inspect_retained(binding.stage_name, binding.stage, DATA.len() as u64)
		.unwrap();
	let mut verified = [0; DATA.len()];
	retained.read_exact_at(0, &mut verified).unwrap();
	retained.recheck_observation().unwrap();
	assert_eq!(verified, DATA);

	let inspect = |expected_root, binding: &WindowsPublicationBinding<'_>| {
		inspect_windows_publication_target(
			root_file.as_handle(),
			expected_root,
			destination_name,
			binding,
		)
	};
	assert_eq!(
		inspect(root_identity, &binding).unwrap(),
		WindowsPublicationTargetObservation::Absent
	);
	assert!(matches!(
		inspect(binding.stage_parent, &binding),
		Err(WindowsPublicationError::ParentChanged)
	));
	let wrong_parent = WindowsPublicationBinding {
		destination_parent: binding.stage,
		..binding
	};
	assert!(matches!(
		inspect(root_identity, &wrong_parent),
		Err(WindowsPublicationError::ParentChanged)
	));
	let missing_parent_name: Vec<_> = "missing".encode_utf16().collect();
	assert!(
		inspect_windows_publication_target(
			root_file.as_handle(),
			root_identity,
			WindowsComponent::new(&missing_parent_name).unwrap(),
			&binding
		)
		.is_err()
	);

	fs::create_dir(&public).unwrap();
	let wrong_kind = directory_id(&public);
	assert!(matches!(
		inspect(root_identity, &binding),
		Err(WindowsPublicationError::Stage(WindowsStageError::Native(_)))
	));
	assert_eq!(directory_id(&public), wrong_kind);
	fs::remove_dir(&public).unwrap();

	let incumbent = create_bytes(&public, INCUMBENT);
	assert_ne!(incumbent, binding.stage);
	assert_eq!(
		inspect(root_identity, &binding).unwrap(),
		WindowsPublicationTargetObservation::Unrelated(incumbent)
	);
	let exclusive_reader = OpenOptions::new()
		.read(true)
		.share_mode(0)
		.open(&public)
		.unwrap();
	assert!(matches!(
		inspect(root_identity, &binding),
		Err(WindowsPublicationError::Stage(WindowsStageError::Native(_)))
	));
	drop(exclusive_reader);

	let alias: Vec<_> = "PUBLIC".encode_utf16().collect();
	assert_eq!(
		file_identity(&fixture.destination.join("PUBLIC")),
		incumbent
	);
	let alias_binding = WindowsPublicationBinding {
		target_name: WindowsComponent::new(&alias).unwrap(),
		..binding
	};
	assert!(inspect(root_identity, &alias_binding).is_err());
	retained.recheck_observation().unwrap();
	drop(retained);
	drop(stage_file);
	drop(root_file);
	assert_bytes(&private, identity, DATA);
	assert_bytes(&public, incumbent, INCUMBENT);
	fixture.clean([(private, identity), (public, incumbent)]);
}

pub(super) fn inspect_reopened_publication(
	fixture: &Fixture,
	root_identity: ObjectId,
	binding: WindowsPublicationBinding<'_>,
) {
	let reopened = open_parent(&fixture.scope, 0);
	let observed = inspect_windows_publication_target(
		reopened.as_handle(),
		root_identity,
		WindowsComponent::new(DESTINATION).unwrap(),
		&binding,
	)
	.unwrap();
	assert_eq!(observed, WindowsPublicationTargetObservation::ExactStage);
}
