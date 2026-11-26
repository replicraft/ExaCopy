#!/usr/bin/env bash
set -euo pipefail

# Standard hosted runners only. Keep the owned fixture and private wrapper build
# away from checkout state and allow uploads of diagnostics separately.
runner_root=$(realpath -- "${RUNNER_TEMP:?}")
evidence="$runner_root/exacopy-hosted-native-remote"
mkdir -m 700 -- "$evidence"
work=
build="$evidence/exacopy-remote-build-target"
marker="$evidence/cleanup-unconfirmed.txt"
identity=
evidence_identity=
interrupted=0

owned_identity() {
	python3 -B -c '
import os, stat, sys
details = os.stat(sys.argv[1], follow_symlinks=False)
if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
    raise SystemExit(1)
print(f"{details.st_dev}:{details.st_ino}")
' "$1"
}

confirmed_absent() {
	python3 -B -c '
import os, sys
try:
    os.lstat(sys.argv[1])
except FileNotFoundError:
    pass
else:
    raise SystemExit(1)
' "$1"
}

cleanup() {
	local result=$?
	trap - EXIT INT TERM
	if (( interrupted != 0 )); then
		printf 'Hosted diagnostic interrupted; retaining the cleanup marker and any fixture.\n' >&2
	elif [[ -z "$work" || -z "$identity" || -z "$evidence_identity" ]] ||
		[[ "$(owned_identity "$evidence")" != "$evidence_identity" ]] ||
		! confirmed_absent "$build" ||
		[[ "$(owned_identity "$work")" != "$identity" ]] ||
		! rmdir -- "$work"; then
		printf 'Hosted diagnostic fixture or build cleanup remained unconfirmed.\n' >&2
		if (( result == 0 )); then result=77; fi
	elif ! rm -- "$marker"; then
		printf 'Could not confirm removal of the hosted cleanup marker.\n' >&2
		if (( result == 0 )); then result=77; fi
	fi
	exit "$result"
}
trap cleanup EXIT
trap 'interrupted=130; exit 130' INT
trap 'interrupted=143; exit 143' TERM

# Record the private parent before mktemp so the marker identifies its
# ownership scope even when a signal prevents the shell from assigning work.
printf 'cleanup=unconfirmed\nfixture_parent=%s\nbuild_target=%s\n' "$evidence" "$build" > "$marker"
evidence_identity=$(owned_identity "$evidence")
work=$(mktemp -d "$evidence/fixture.XXXXXX")
printf 'fixture=%s\n' "$work" >> "$marker"
identity=$(owned_identity "$work")
bash .github/ci/capture.sh hosted-fixture-filesystem findmnt -T "$work" -o FSTYPE,FSROOT,OPTIONS
bash .github/ci/capture.sh native-hosted python3 -B .github/ci/remote_qualification.py hosted \
	--route direct-pinned-tcp-v1 --destination "$work" --evidence "$evidence/diagnostic"
