# The checked public symlink is the selector. The store holds its before/after intent.

no_selection='-|-|-|-'

launcher_paths() {
	launcher_bin=$HOME/.local/bin
	launcher=$launcher_bin/exacopy
	launcher_record=$root/.launcher
	launcher_lock=$launcher_bin/.exacopy-lifecycle-lock
	launcher_locked=no launcher_stage='' launcher_record_stage='' launcher_check_scratch=''
}

launcher_absent() {
	[ ! -e "$1" ] && [ ! -L "$1" ]
}

launcher_identity() {
	file_stat '%d:%i' '%d:%i' "$1"
}

valid_selection() (
	if [ "$1" = "$no_selection" ]; then
		exit 0
	fi
	IFS='|' read -r selected_version selected_manifest selected_artifact selected_identity <<EOF_SELECTION
$1
EOF_SELECTION
	[ "$1" = "$selected_version|$selected_manifest|$selected_artifact|$selected_identity" ] &&
		valid_version "$selected_version" && hex_pin "$selected_manifest" &&
		hex_pin "$selected_artifact" &&
		positive_decimal "${selected_identity%:*}" 20 &&
		positive_decimal "${selected_identity#*:}" 20 &&
		[ "${selected_identity%:*}" != "$selected_identity" ]
)

write_launcher_record() {
	printf 'schema=exacopy-posix-launcher-v1\nroot=%s\npublisher_sha256=%s\nlauncher=%s\n%s\n%s\n' \
		"$root" "$publisher_pin" "$launcher" "$1" "$2"
}

matches_selection() {
	if [ "$1" = "$no_selection" ]; then
		launcher_absent "$launcher"
		return
	fi
	[ -L "$launcher" ] && [ "$(file_stat %u %u "$launcher")" = "$owner" ] &&
		[ "$(launcher_identity "$launcher")" = "${1##*|}" ] &&
		printf '%s\n' "$version_store/${1%%|*}/exacopy" | cmp -s - "$2"
}

load_launcher_record() {
	launcher_current=$no_selection
	launcher_record_identity=''
	if launcher_absent "$launcher_record"; then
		launcher_absent "$launcher" || fail "unowned launcher path is occupied: $launcher"
		return
	fi
	owned_regular "$launcher_record" 600 && check_access "$launcher_record" &&
		[ "$(file_bytes "$launcher_record")" -le 16384 ] ||
		fail 'invalid launcher transaction record'
	launcher_record_identity=$(launcher_identity "$launcher_record") ||
		fail 'cannot inspect launcher transaction identity'
	snapshot "$launcher_record" "$launcher_check_scratch/record" 16384
	confirm_launcher_record
	{
		IFS= read -r launcher_schema &&
			IFS= read -r launcher_root &&
			IFS= read -r launcher_authority &&
			IFS= read -r launcher_path &&
			IFS= read -r launcher_before &&
			IFS= read -r launcher_after &&
			! IFS= read -r launcher_extra && [ -z "$launcher_extra" ]
	} < "$launcher_check_scratch/record" || fail 'invalid launcher transaction record'
	valid_selection "$launcher_before" && valid_selection "$launcher_after" &&
		[ "$launcher_before" != "$launcher_after" ] &&
		write_launcher_record "$launcher_before" "$launcher_after" | cmp -s - "$launcher_check_scratch/record" ||
		fail 'invalid launcher transaction record'

	if [ -L "$launcher" ]; then
		[ -n "$launcher_check_scratch" ] || fail 'launcher observation has no scratch directory'
		readlink "$launcher" > "$launcher_check_scratch/target" || fail 'cannot observe launcher target'
	fi
	if matches_selection "$launcher_after" "$launcher_check_scratch/target"; then
		launcher_current=$launcher_after
	elif matches_selection "$launcher_before" "$launcher_check_scratch/target"; then
		launcher_current=$launcher_before
	else
		fail 'launcher does not match either recorded selector state. Reconcile before retry'
	fi
}

inspect_launcher_paths() {
	walk_directories "$launcher_bin" optional
	if [ -d "$launcher_bin" ]; then
		[ "$(file_stat %u %u "$launcher_bin")" = "$owner" ] &&
			[ -r "$launcher_bin" ] && [ -x "$launcher_bin" ] ||
			fail 'launcher directory must be accessible and belong to the installation owner'
	fi
	launcher_absent "$launcher_lock" || fail 'launcher lifecycle lock is held or requires owner reconciliation'
}

lock_launcher() {
	walk_directories "$launcher_bin" create
	[ "$(file_stat %u %u "$launcher_bin")" = "$owner" ] ||
		fail 'launcher directory must belong to the installation owner'
	mkdir -m 700 "$launcher_lock" 2>/dev/null ||
		fail 'launcher lifecycle lock is held or requires owner reconciliation'
	launcher_locked=yes
}

launcher_resolved_path() (
	case $1 in
		/*) candidate=$1 ;;
		*) candidate=./$1 ;;
	esac
	[ "${candidate##*/}" = exacopy ] && [ -L "$candidate" ] && [ -L "$launcher" ] || exit 1
	candidate_parent=${candidate%/*}
	candidate_parent=$(cd -P "${candidate_parent:-/}" && pwd -P) || exit 1
	[ "$candidate_parent" = "$launcher_bin" ] || exit 1
	candidate_identity=$(launcher_identity "$candidate") || exit 1
	current_identity=$(launcher_identity "$launcher") || exit 1
	[ "$candidate_identity" = "$current_identity" ]
)

launcher_path_check() {
	resolved_launcher=$(PATH=$caller_path command -v exacopy) || return 0
	launcher_resolved_path "$resolved_launcher" ||
		fail "an existing exacopy command takes precedence or would be shadowed: $resolved_launcher"
}

launcher_preflight() {
	inspect_launcher_paths
	if launcher_absent "$launcher_record"; then
		launcher_absent "$launcher" || fail "unowned launcher path is occupied: $launcher"
	fi
	launcher_path_check
}

launcher_open() {
	inspect_launcher_paths
	if [ "$dry_run" = no ] && { [ "$operation" = install ] || [ -d "$launcher_bin" ]; }; then
		lock_launcher
	fi
	launcher_check_scratch=$scratch/selector
	mkdir -m 700 "$launcher_check_scratch" || fail 'cannot create launcher verification scratch'
	if [ -d "$launcher_bin" ]; then
		launcher_bin_identity=$(launcher_identity "$launcher_bin") ||
			fail 'cannot inspect launcher directory identity'
	else
		launcher_bin_identity=''
	fi
	load_launcher_record
	verify_selected_release
}

launcher_for_removal() {
	if launcher_absent "$launcher_record"; then
		# Older version-only stores own no public launcher. Preserve other commands.
		launcher_current=$no_selection
		inspect_launcher_paths
		if [ -L "$launcher" ]; then
			launcher_check_scratch=$scratch/selector
			mkdir -m 700 "$launcher_check_scratch" || fail 'cannot create launcher verification scratch'
			readlink "$launcher" > "$launcher_check_scratch/target" || fail 'cannot observe launcher target'
			if printf '%s\n' "$version_dir/exacopy" | cmp -s - "$launcher_check_scratch/target"; then
				fail 'launcher points to this version without an ownership record'
			fi
		fi
		return
	fi
	launcher_open
}

verify_selected_release() {
	[ "$launcher_current" != "$no_selection" ] || return 0
	(
		IFS='|' read -r version selected_manifest selected_artifact selected_identity <<EOF_SELECTION
$launcher_current
EOF_SELECTION
		version_dir=$version_store/$version
		[ "$previous_sequence" -gt 0 ] || fail 'launcher has no retained release history'
		[ ! -e "$version_store/.remove-$version" ] && [ ! -L "$version_store/.remove-$version" ] ||
			fail 'current launcher version has an interrupted removal'
		cp "$scratch/publisher.der" "$launcher_check_scratch/publisher.der" ||
			fail 'cannot stage historical launcher verification'
		scratch=$launcher_check_scratch
		# Existing activation is historical. New installs still require live metadata.
		operation=uninstall
		verify_installed
		[ "$manifest_hash" = "$selected_manifest" ] && [ "$artifact_hash" = "$selected_artifact" ] &&
			[ "$sequence" -le "$previous_sequence" ] ||
			fail 'launcher release does not match its recorded verification'
		if [ "$sequence" -eq "$previous_sequence" ]; then
			[ "$version" = "$previous_version" ] && [ "$manifest_hash" = "$previous_hash" ] ||
				fail 'launcher release conflicts with retained history'
		fi
	)
}

confirm_launcher_record() {
	if [ -z "$launcher_record_identity" ]; then
		launcher_absent "$launcher_record" || fail 'launcher transaction appeared during operation'
	else
		owned_regular "$launcher_record" 600 &&
			[ "$(launcher_identity "$launcher_record")" = "$launcher_record_identity" ] &&
			cmp -s "$launcher_record" "$launcher_check_scratch/record" ||
			fail 'launcher transaction changed during operation'
	fi
}

confirm_launcher_state() {
	[ -d "$launcher_bin" ] && [ ! -L "$launcher_bin" ] &&
		[ "$(launcher_identity "$launcher_bin")" = "$launcher_bin_identity" ] ||
		fail 'launcher directory changed during operation'
	confirm_launcher_record
	if [ -L "$launcher" ]; then
		readlink "$launcher" > "$launcher_check_scratch/target" || fail 'cannot reobserve launcher target'
	fi
	matches_selection "$launcher_current" "$launcher_check_scratch/target" ||
		fail 'launcher changed during transaction. Reconcile before retry'
}

publish_launcher_intent() {
	launcher_record_stage=$(mktemp "$root/.launcher-record.XXXXXXXX") ||
		fail 'cannot stage launcher transaction'
	write_launcher_record "$launcher_current" "$1" > "$launcher_record_stage" ||
		fail 'cannot write launcher transaction'
	sync || fail 'cannot flush launcher transaction'
	confirm_launcher_state
	next_record_identity=$(launcher_identity "$launcher_record_stage") ||
		fail 'cannot inspect staged launcher transaction'
	if [ "$host_os" = Darwin ]; then
		mv -fh "$launcher_record_stage" "$launcher_record" || fail 'cannot publish launcher transaction'
	else
		mv -fT "$launcher_record_stage" "$launcher_record" || fail 'cannot publish launcher transaction'
	fi
	launcher_record_stage=
	launcher_record_identity=$next_record_identity
	write_launcher_record "$launcher_current" "$1" > "$launcher_check_scratch/record" ||
		fail 'cannot retain expected launcher transaction. Reconcile before retry'
	sync || fail 'cannot flush published launcher transaction'
}

verify_launcher_metadata() {
	if ! launcher_absent "$launcher_record"; then
		verify_removal_resource_forks "$launcher_record"
	fi
	if [ "$launcher_current" != "$no_selection" ]; then
		verify_removal_resource_forks "$launcher"
	fi
}

activate_launcher() {
	if [ "${launcher_current%%|*}" = "$version" ]; then
		confirm_launcher_state
		return
	fi

	launcher_stage=$(mktemp -d "$launcher_bin/.exacopy-selector.XXXXXXXX") ||
		fail 'cannot stage launcher in its destination directory'
	ln -s "$version_dir/exacopy" "$launcher_stage/link" || fail 'cannot stage launcher target'
	new_launcher_identity=$(launcher_identity "$launcher_stage/link") ||
		fail 'cannot inspect staged launcher'
	[ "${new_launcher_identity%:*}" = "${launcher_bin_identity%:*}" ] ||
		fail 'launcher stage must share the launch directory volume'
	next_launcher=$version"|"$manifest_hash"|"$artifact_hash"|"$new_launcher_identity
	valid_selection "$next_launcher" || fail 'cannot represent staged launcher'
	confirm_launcher_state
	publish_launcher_intent "$next_launcher"
	confirm_launcher_state
	if [ "$launcher_current" = "$no_selection" ]; then
		# Link the staged symlink inode exclusively so the write-ahead identity still applies.
		if [ "$host_os" = Darwin ]; then
			ln -hP "$launcher_stage/link" "$launcher" || fail 'cannot exclusively publish launcher'
		else
			ln -PT "$launcher_stage/link" "$launcher" || fail 'cannot exclusively publish launcher'
		fi
	elif [ "$host_os" = Darwin ]; then
		mv -fh "$launcher_stage/link" "$launcher" || fail 'cannot switch launcher'
	else
		mv -fT "$launcher_stage/link" "$launcher" || fail 'cannot switch launcher'
	fi
	launcher_current=$next_launcher
	sync || fail 'launcher changed but flush failed. Reconcile the reported path'
	confirm_launcher_state
}

withdraw_launcher() {
	[ "${launcher_current%%|*}" = "$version" ] || return 0
	confirm_launcher_state
	publish_launcher_intent "$no_selection"
	confirm_launcher_state
	rm "$launcher" || fail 'cannot withdraw owned launcher'
	launcher_current=$no_selection
	sync || fail 'launcher was withdrawn but flush failed. Reconcile the reported path'
	confirm_launcher_state
	printf 'Removed launcher: %s\n' "$launcher"
}

report_launcher() {
	printf 'Launcher: %s\n' "$launcher"
	resolved_launcher=$(PATH=$caller_path command -v exacopy) || resolved_launcher=''
	if launcher_resolved_path "$resolved_launcher"; then
		return
	fi
	case :$caller_path: in
		*:"$launcher_bin":*) : ;;
		*) printf 'Run the launcher by its printed path, or add %s to your PATH.\n' "$launcher_bin" ;;
	esac
}

cleanup_launcher() {
	if [ -n "$launcher_stage" ]; then
		rm -f "$launcher_stage/link" || :
		rmdir "$launcher_stage" 2>/dev/null || :
	fi
	if [ -n "$launcher_record_stage" ]; then
		rm -f "$launcher_record_stage" || :
	fi
	if [ -n "$launcher_check_scratch" ]; then
		rm -f "$launcher_check_scratch/target" "$launcher_check_scratch/publisher.der" \
			"$launcher_check_scratch/publisher.pem" "$launcher_check_scratch/release.manifest" \
			"$launcher_check_scratch/release.sig" "$launcher_check_scratch/record" || :
		rmdir "$launcher_check_scratch" 2>/dev/null || :
	fi
	if [ "$launcher_locked" = yes ]; then
		rmdir "$launcher_lock" 2>/dev/null || :
	fi
}
