# User-scoped POSIX installer support.

caller_path=${PATH-}
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset CDPATH OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES PERL5LIB PERL5OPT
set -f
umask 077

# shellcheck source=tools/installer/manifest.sh
. "$script_dir/tools/installer/manifest.sh"
# shellcheck source=tools/installer/store.sh
. "$script_dir/tools/installer/store.sh"
# shellcheck source=tools/installer/launcher.sh
. "$script_dir/tools/installer/launcher.sh"

fail() {
	printf 'exacopy %s: %s\n' "$operation" "$1" >&2
	exit 1
}

usage() {
	if [ "$operation" = install ]; then
		printf 'Usage: install.sh --publisher-cert FILE --publisher-sha256 HASH [--latest] [--version N.N.N]\n'
		printf '       install.sh --publisher-cert FILE --publisher-sha256 HASH --version N.N.N --offline-bundle DIR\n'
	else
		printf 'Usage: uninstall.sh --version N.N.N --publisher-cert FILE --publisher-sha256 HASH --quiesced\n'
	fi
	printf '       [--install-root DIR] [--scope user] [--cli-only] [--non-interactive] [--dry-run]\n'
}

read_flags() {
	version='' publisher_cert='' publisher_pin='' bundle='' root='' dry_run=no quiesced=no latest=no
	while [ "$#" -gt 0 ]; do
		case $1 in
			--version|--publisher-cert|--publisher-sha256|--offline-bundle|--install-root|--scope)
				[ "$#" -ge 2 ] && [ -n "$2" ] || fail "missing value for $1"
				case $1 in
					--version) [ -z "$version" ] || fail 'duplicate --version'; version=$2 ;;
					--publisher-cert) [ -z "$publisher_cert" ] || fail 'duplicate --publisher-cert'; publisher_cert=$2 ;;
					--publisher-sha256) [ -z "$publisher_pin" ] || fail 'duplicate --publisher-sha256'; publisher_pin=$2 ;;
					--offline-bundle) [ -z "$bundle" ] || fail 'duplicate --offline-bundle'; bundle=$2 ;;
					--install-root) [ -z "$root" ] || fail 'duplicate --install-root'; root=$2 ;;
					--scope) [ "$2" = user ] || fail 'only explicit user scope is supported' ;;
				esac
				shift 2
				;;
			--latest) latest=yes; shift ;;
			--cli-only|--non-interactive) shift ;;
			--dry-run) dry_run=yes; shift ;;
			--quiesced) quiesced=yes; shift ;;
			-h|--help) usage; exit 0 ;;
			*) fail "unsupported argument: $1" ;;
		esac
	done
	if [ "$operation" != install ] || [ -n "$bundle" ] || [ -n "$version" ]; then
		valid_version "$version" || fail 'provide exact --version N.N.N'
	fi
	hex_pin "$publisher_pin" || fail 'provide independently trusted lowercase --publisher-sha256'
	[ -n "$publisher_cert" ] || fail 'provide independently trusted --publisher-cert'
	if [ "$operation" = install ]; then
		[ "$quiesced" = no ] || fail '--quiesced applies to uninstall'
		if [ -z "$bundle" ]; then
			latest=yes
		else
			[ "$latest" = no ] || fail '--latest and --offline-bundle are mutually exclusive'
		fi
	else
		[ "$latest" = no ] || fail '--latest applies to install'
		if [ -n "$bundle" ] || { [ "$quiesced" != yes ] && [ "$dry_run" != yes ]; }; then
			fail 'uninstall requires --quiesced after the owner stops all uses of this version'
		fi
	fi
}

valid_version() {
	printf '%s\n' "$1" | awk '
		NR == 1 && /^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$/ {
			n = split($0, fields, ".")
			valid = n == 3
			for (i = 1; i <= 3; i++) if (length(fields[i]) > 6) valid = 0
		}
		END { if (NR != 1 || !valid) exit 1 }
	'
}

host_profile() {
	owner=$(id -u) || fail 'cannot determine current user'
	[ "$owner" != 0 ] || fail 'run as the installation owner without elevation'
	host_os=$(uname -s) || fail 'cannot identify host OS'
	arch=$(uname -m) || fail 'cannot identify host architecture'
	case $arch in
		arm64|aarch64) arch=aarch64 ;;
		x86_64) : ;;
		*) fail 'unsupported host architecture' ;;
	esac
	case $host_os in
		Darwin)
			translated=$(sysctl -in sysctl.proc_translated 2>/dev/null || :)
			[ "$translated" != 1 ] || fail 'use a native shell instead of Rosetta'
			target=$arch-apple-darwin
			temp_base=/private/tmp
			;;
		Linux) target=$arch-unknown-linux-gnu; temp_base=/tmp ;;
		*) fail 'unsupported host OS' ;;
	esac
}

file_stat() {
	if [ "$host_os" = Darwin ]; then
		stat -f "$1" "$3"
	else
		stat -c "$2" "$3"
	fi
}

file_bytes() { file_stat %z %s "$1"; }

check_path() {
	case $1 in
		/|*/|*//*|*/./*|*/../*|*/.|*/..|*[[:cntrl:]]*) fail 'pathname must be absolute and lexically canonical' ;;
		/*) : ;;
		*) fail 'pathname must be absolute and lexically canonical' ;;
	esac
}

check_directory() {
	[ -d "$1" ] && [ ! -L "$1" ] || fail "unsafe or missing directory: $1"
	check_access "$1"
}

check_access() {
	dir_owner=$(file_stat %u %u "$1") || fail "cannot inspect directory: $1"
	[ "$dir_owner" = 0 ] || [ "$dir_owner" = "$owner" ] || fail "untrusted directory owner: $1"
	dir_mode=$(file_stat %Sp %A "$1") || fail "cannot inspect directory mode: $1"
	case $dir_mode in
		?????w*|????????w*)
			case $1:$dir_owner:$dir_mode in
				/private/tmp:0:*t|/tmp:0:*t) : ;;
				*) fail "directory permits unrelated writers: $1" ;;
			esac ;;
	esac
	if [ "$host_os" = Darwin ]; then
		acl_listing=$(ls -lde "$1") || fail "cannot inspect ACL: $1"
		# Inherited or explicit grants can exceed the mode bits on Darwin.
		if printf '%s\n' "$acl_listing" | awk 'NR > 1 && / allow / { grant=1 } END { exit !grant }'; then
			fail "ACL grants additional access: $1"
		fi
	fi
}

walk_directories() {
	check_path "$1"
	walk_remaining=${1#/}
	walk_prefix=
	while [ -n "$walk_remaining" ]; do
		walk_component=${walk_remaining%%/*}
		walk_prefix=$walk_prefix/$walk_component
		if [ ! -e "$walk_prefix" ] && [ ! -L "$walk_prefix" ]; then
			if [ "$2" = create ]; then
				mkdir -m 700 "$walk_prefix" || fail "cannot create directory: $walk_prefix"
			elif [ "$2" = optional ]; then
				return
			else
				fail "missing directory: $walk_prefix"
			fi
		fi
		check_directory "$walk_prefix"
		[ "$walk_remaining" != "$walk_component" ] || break
		walk_remaining=${walk_remaining#*/}
	done
}

regular_file() {
	[ -f "$1" ] && [ ! -L "$1" ] && [ "$(file_stat %l %h "$1")" = 1 ]
}

snapshot() {
	regular_file "$1" || fail "expected single-link regular file: $1"
	check_access "$1"
	snapshot_size=$(file_bytes "$1") || fail "cannot determine file size: $1"
	[ "$snapshot_size" -gt 0 ] && [ "$snapshot_size" -le "$3" ] ||
		fail "file size outside limit: $1"
	# The validated owner path excludes unrelated writers. Bound the copy even if
	# the installing owner accidentally changes the offline bundle during staging.
	dd if="$1" of="$2" bs=65536 count=$((($3 + 65535) / 65536 + 1)) 2>/dev/null ||
		fail "cannot copy file: $1"
	[ "$(file_bytes "$2")" = "$snapshot_size" ] || fail "file changed during copy: $1"
}

cleanup() {
	cleanup_launcher
	if [ -n "$stage" ]; then
		rm -f "$stage/exacopy" "$stage/release.manifest" "$stage/release.sig" "$stage/intent" || :
		rmdir "$stage" 2>/dev/null || :
	fi
	if [ -n "$record_stage" ]; then
		rm -f "$record_stage" || :
	fi
	if [ "$locked" = yes ]; then
		rmdir "$root/.lifecycle-lock" 2>/dev/null || :
	fi
	if [ -n "$scratch" ]; then
		rm -f "$scratch/exacopy" "$scratch/release.manifest" "$scratch/release.sig" \
			"$scratch/publisher.der" "$scratch/publisher-encoded.der" "$scratch/publisher.pem" \
			"$scratch/attribute-names" || :
		if [ "$latest" = yes ]; then
			rm -f "$scratch/redirect" "$scratch/checksums" "$scratch/archive.tar.gz" \
				"$scratch/bundle/exacopy" "$scratch/bundle/release.manifest" "$scratch/bundle/release.sig" || :
			rmdir "$scratch/bundle" 2>/dev/null || :
		fi
		rmdir "$scratch" 2>/dev/null || :
	fi
}

installer_main() {
	read_flags "$@"
	host_profile
	[ -n "${HOME:-}" ] || fail 'HOME is required'
	walk_directories "$HOME" require
	[ "$(file_stat %u %u "$HOME")" = "$owner" ] || fail 'HOME must belong to the installation owner'
	if [ -z "$root" ]; then
		if [ "$host_os" = Darwin ]; then
			root=$HOME/Library/Application\ Support/ExaCopy/install
		else
			root=${XDG_DATA_HOME:-$HOME/.local/share}/exacopy/install
		fi
	fi
	check_path "$root"
	case $root in
		"$HOME"/*/install|"$HOME"/install) : ;;
		*) fail 'install root must be under HOME and named install' ;;
	esac
	check_path "$publisher_cert"
	publisher_parent=${publisher_cert%/*}
	[ -n "$publisher_parent" ] || fail 'publisher certificate must reside in a trusted directory'
	walk_directories "$publisher_parent" require
	walk_directories "${root%/*}" optional

	scratch='' stage='' record_stage='' previous_sequence='' locked=no
	launcher_paths
	trap cleanup EXIT
	trap 'exit 1' HUP INT TERM
	scratch=$(mktemp -d "$temp_base/exacopy-release.XXXXXXXX") || fail 'cannot create verification directory'
	snapshot "$publisher_cert" "$scratch/publisher.der" 16384
	verify_publisher_certificate_framing
	if [ "$latest" = yes ]; then
		# shellcheck source=tools/installer/download.sh
		. "$script_dir/tools/installer/download.sh"
		download_release
	fi
	high_water=$root/.high-water
	version_store=$root/versions
	version_dir=$version_store/$version
	if [ "$operation" = install ]; then
		install_file
	else
		uninstall_file
	fi
}
