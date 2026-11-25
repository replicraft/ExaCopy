# Private owner-scoped store and reversible pre-publication operations.

empty_sequence_hash=0000000000000000000000000000000000000000000000000000000000000000

owner_record() {
	printf 'schema=exacopy-posix-owner-v1\nuid=%s\nroot=%s\ntarget=%s\npublisher_sha256=%s\n' \
		"$owner" "$root" "$target" "$publisher_pin"
}

transaction_record() {
	printf 'schema=exacopy-posix-intent-v1\nversion=%s\nsequence=%s\nmanifest_sha256=%s\nartifact_sha256=%s\n' \
		"$version" "$sequence" "$manifest_hash" "$artifact_hash"
}

owned_regular() {
	regular_file "$1" && [ "$(file_stat %u %u "$1")" = "$owner" ] &&
		[ "$(file_stat %Lp %a "$1")" = "$2" ]
}

private_directory() {
	check_directory "$1"
	[ "$(file_stat %u %u "$1")" = "$owner" ] &&
		[ "$(file_stat %Lp %a "$1")" = 700 ] || fail "directory must be owner-private: $1"
}

open_store() {
	if [ ! -e "$root" ] && [ ! -L "$root" ]; then
		[ "$operation" = install ] || fail 'no owned install store'
		[ "$dry_run" = no ] || return 0
		walk_directories "${root%/*}" create
		mkdir -m 700 "$root" || fail 'cannot create a new owned install store'
		private_directory "$root"
		owner_record > "$root/.owner" || fail 'cannot write install ownership record'
		printf '0\n0.0.0\n%s\n' "$empty_sequence_hash" > "$high_water" ||
			fail 'cannot initialize release sequence'
	else
		private_directory "$root"
	fi
	owned_regular "$root/.owner" 600 && owner_record | cmp -s - "$root/.owner" ||
		fail 'pre-existing store has no matching ownership record'
	if [ "$dry_run" = no ]; then
		mkdir -m 700 "$root/.lifecycle-lock" 2>/dev/null ||
			fail 'lifecycle lock is held or requires owner reconciliation'
		locked=yes
	elif [ -e "$root/.lifecycle-lock" ] || [ -L "$root/.lifecycle-lock" ]; then
		fail 'lifecycle lock is held or requires owner reconciliation'
	fi
	load_sequence
	if [ ! -e "$version_store" ] && [ ! -L "$version_store" ]; then
		[ "$operation" = install ] || fail 'no owned versions directory'
		[ "$dry_run" = no ] || return 0
		mkdir -m 700 "$version_store" || fail 'cannot create owned versions directory'
	fi
	private_directory "$version_store"
	[ ! -e "$version_store/.remove-$version" ] && [ ! -L "$version_store/.remove-$version" ] ||
		fail 'an interrupted removal requires owner reconciliation'
}

exact_contents() (
	set +f
	for member in "$1"/* "$1"/.[!.]* "$1"/..?*; do
		[ -e "$member" ] || [ -L "$member" ] || continue
		case ${member##*/}:$2 in
			exacopy:*|release.manifest:*|release.sig:*|intent:version) : ;;
			*) exit 1 ;;
		esac
	done
)

load_release() {
	manifest=$scratch/release.manifest
	signature=$scratch/release.sig
	snapshot "$1/release.manifest" "$manifest" 4096
	snapshot "$1/release.sig" "$signature" 1024
	verify_signature
	check_manifest
	manifest_hash=$(hash_file "$manifest") || fail 'cannot hash verified manifest'
}

verify_artifact() {
	regular_file "$1" || fail 'artifact is not a single-link regular file'
	check_access "$1"
	[ "$(file_bytes "$1")" = "$artifact_size" ] || fail 'artifact size mismatch'
	publication_hash=$(hash_file "$1") || fail 'cannot hash artifact'
	[ "$publication_hash" = "$artifact_hash" ] || fail 'artifact SHA-256 mismatch'
}

verify_installed() {
	private_directory "$version_dir"
	[ "$(file_stat %d %d "$version_dir")" = "$(file_stat %d %d "$version_store")" ] ||
		fail 'version and store must be on the same volume'
	exact_contents "$version_dir" version || fail 'version directory contains unexpected entries'
	owned_regular "$version_dir/exacopy" 700 &&
		owned_regular "$version_dir/release.manifest" 600 &&
		owned_regular "$version_dir/release.sig" 600 &&
		owned_regular "$version_dir/intent" 600 ||
		fail 'version files do not match installer ownership'
	[ "$(file_bytes "$version_dir/intent")" -le 1024 ] || fail 'invalid version ownership record'
	load_release "$version_dir"
	transaction_record | cmp -s - "$version_dir/intent" || fail 'version ownership record mismatch'
	verify_artifact "$version_dir/exacopy"
}

load_sequence() {
	owned_regular "$high_water" 600 && [ "$(file_bytes "$high_water")" -le 1024 ] ||
		fail 'invalid release sequence record'
	{
		IFS= read -r previous_sequence &&
			IFS= read -r previous_version &&
			IFS= read -r previous_hash &&
			! IFS= read -r unexpected && [ -z "$unexpected" ]
	} < "$high_water" || fail 'invalid release sequence record'
	printf '%s\n%s\n%s\n' "$previous_sequence" "$previous_version" "$previous_hash" |
		cmp -s - "$high_water" || fail 'invalid release sequence record'
	if [ "$previous_sequence" = 0 ]; then
		[ "$previous_version" = 0.0.0 ] && [ "$previous_hash" = "$empty_sequence_hash" ] ||
			fail 'invalid initial release sequence record'
	else
		positive_decimal "$previous_sequence" 10 && [ "$previous_sequence" -le 2147483647 ] &&
			valid_version "$previous_version" && hex_pin "$previous_hash" ||
			fail 'invalid release sequence record'
	fi
}

check_sequence() {
	[ -n "${previous_sequence:-}" ] || return 0
	if [ "$sequence" -eq "$previous_sequence" ]; then
		[ "$version" = "$previous_version" ] && [ "$manifest_hash" = "$previous_hash" ] ||
			fail 'release sequence already binds different signed metadata'
	else
		[ "$sequence" -gt "$previous_sequence" ] &&
			numeric_version_at_least "$version" "$previous_version" ||
			fail 'release downgrade or rollback refused'
	fi
}

install_file() {
	walk_directories "$bundle" require
	exact_contents "$bundle" bundle || fail 'offline bundle must contain only the signed manifest, signature and CLI'
	load_release "$bundle"
	regular_file "$bundle/exacopy" || fail 'artifact is not a single-link regular file'
	[ "$(file_bytes "$bundle/exacopy")" = "$artifact_size" ] || fail 'artifact size mismatch'
	snapshot "$bundle/exacopy" "$scratch/exacopy" "$artifact_size"
	verify_artifact "$scratch/exacopy"
	open_store
	check_sequence
	if [ -e "$version_dir" ] || [ -L "$version_dir" ]; then
		requested_hash=$manifest_hash
		verify_installed
		[ "$requested_hash" = "$manifest_hash" ] || fail 'version already binds a different signed release'
		printf 'Already installed: %s\n' "$version_dir/exacopy"
		return
	fi
	if [ "$dry_run" = yes ]; then
		printf 'Verified release. Would install: %s\n' "$version_dir/exacopy"
		return
	fi

	stage=$(mktemp -d "$version_store/.stage.XXXXXXXX") || fail 'cannot create a private install stage'
	private_directory "$stage"
	snapshot "$scratch/exacopy" "$stage/exacopy" "$artifact_size"
	verify_artifact "$stage/exacopy"
	cp "$manifest" "$stage/release.manifest" && cp "$signature" "$stage/release.sig" ||
		fail 'cannot store verified release metadata'
	chmod 700 "$stage/exacopy" || fail 'cannot set installed executable permissions'
	transaction_record > "$stage/intent" || fail 'cannot write install intent'
	record_stage=$(mktemp "$root/.sequence.XXXXXXXX") || fail 'cannot stage release sequence'
	printf '%s\n%s\n%s\n' "$sequence" "$version" "$manifest_hash" > "$record_stage" ||
		fail 'cannot write release sequence'
	sync || fail 'cannot flush staged install'
	mv "$record_stage" "$high_water" || fail 'cannot publish release sequence'
	record_stage=
	sync || fail 'cannot flush release sequence'
	[ ! -e "$version_dir" ] && [ ! -L "$version_dir" ] || fail 'version path became occupied'
	mv "$stage" "$version_dir" || fail 'cannot publish version directory'
	stage=
	sync || fail 'version was published but flush failed; reconcile the reported path'
	printf 'Installed: %s\n' "$version_dir/exacopy"
}

verify_removal_resource_forks() {
	[ "$host_os" = Darwin ] || return 0
	for installed_path do
		# Inspect names only, without copying data from an independently attached fork.
		(ulimit -f 64 && /usr/bin/xattr -s "$installed_path") > "$scratch/attribute-names" ||
			fail 'cannot inspect installed resource fork'
		if grep -Fqx 'com.apple.ResourceFork' "$scratch/attribute-names"; then
			fail 'version has a resource fork; preserve it before removal'
		elif [ "$?" -ne 1 ]; then
			fail 'cannot inspect installed resource fork'
		fi
	done
}

uninstall_file() {
	open_store
	if [ ! -e "$version_dir" ] && [ ! -L "$version_dir" ]; then
		[ -r "$version_store" ] && [ -x "$version_store" ] ||
			fail 'cannot inspect owned versions directory'
		[ "$previous_sequence" -gt 0 ] && [ "$previous_version" = "$version" ] ||
			fail 'absent version does not match retained release history'
		verify_publisher_pin
		printf 'Already absent: %s\n' "$version_dir"
		return
	fi
	verify_installed
	[ "$sequence" -le "$previous_sequence" ] || fail 'history is inconsistent with installed version'
	if [ "$sequence" = "$previous_sequence" ]; then
		[ "$version" = "$previous_version" ] && [ "$manifest_hash" = "$previous_hash" ] ||
			fail 'history is inconsistent with installed version'
	fi
	verify_removal_resource_forks "$version_dir" "$version_dir/exacopy" \
		"$version_dir/release.manifest" "$version_dir/release.sig" "$version_dir/intent"
	if [ "$dry_run" = yes ]; then
		printf 'Verified ownership. Would remove: %s\n' "$version_dir"
		return
	fi

	retired=$version_store/.remove-$version
	mv "$version_dir" "$retired" || fail 'cannot withdraw version directory'
	rm "$retired/exacopy" "$retired/release.manifest" "$retired/release.sig" "$retired/intent" &&
		rmdir "$retired" || fail 'interrupted removal requires owner reconciliation'
	sync || fail 'version was removed but flush failed; reconcile the reported path'
	printf 'Removed: %s\n' "$version_dir"
	printf 'The owner record and release sequence history remain at %s\n' "$root"
}
