# Fetch one tag-scoped CLI bundle from the fixed GitHub release origin.

github_releases=https://github.com/replicraft/ExaCopy/releases
checksum_limit=4096
header_limit=16384
archive_limit=269484032 # 257 MiB compressed, including archive overhead.

release_http() (
	# Older curl versions can only precheck Content-Length. Also cap the
	# output file when the server omits it. File limit units vary by host
	# shell (512 or 1024 bytes); the exact byte limit is checked below.
	ulimit -f "$(( ($3 + 511) / 512 ))" || exit 1
	: > "$2" || exit 1
	head_option=''
	[ "${4:-}" != head ] || head_option=--head
	# The sentinel lets us detect control characters at the end of the
	# reported URL even though command substitution trims final newlines.
	metadata=$(/usr/bin/curl --disable --silent --show-error --fail --globoff \
		--proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 600 \
		--max-filesize "$3" ${head_option:+"$head_option"} --output "$2" \
		--write-out '%{size_header} %{http_code} %{redirect_url}!' "$1") || exit 1
	case $metadata in
		*[[:cntrl:]]*) exit 1 ;;
		*'!') metadata=${metadata%!} ;;
		*) exit 1 ;;
	esac
	response_headers=${metadata%% *}
	case $response_headers in
		''|*[!0-9]*) exit 1 ;;
	esac
	[ "${#response_headers}" -le 5 ] && [ "$response_headers" -le "$header_limit" ] &&
		[ "$(file_bytes "$2")" -le "$3" ] || exit 1
	printf '%s' "${metadata#* }"
)

resolve_latest() {
	latest_response=$(release_http "$github_releases/latest" "$scratch/redirect" "$header_limit" head) ||
		fail 'cannot resolve latest GitHub release'
	case $latest_response in
		"302 $github_releases/tag/v"*) release_tag=${latest_response#"302 $github_releases/tag/"} ;;
		*) fail 'latest release did not redirect to an ExaCopy release tag' ;;
	esac
	resolved_version=${release_tag#v}
	valid_version "$resolved_version" || fail 'latest release tag is not vN.N.N'
	[ -z "$version" ] || [ "$version" = "$resolved_version" ] ||
		fail 'latest release does not match --version'
	version=$resolved_version
}

fetch_asset() {
	asset_response=$(release_http "$github_releases/download/$release_tag/$1" "$2" "$3") ||
		fail "cannot download release asset: $1"
	case $asset_response in
		'200 ') : ;;
		'302 '*)
			asset_redirect=${asset_response#302 }
			case $asset_redirect in
				https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) : ;;
				*) fail 'release asset redirect is outside GitHub release storage' ;;
			esac
			case $asset_redirect in
				*[!a-zA-Z0-9/:._%?=+\&~,\;-]*) fail 'release asset redirect has invalid characters' ;;
			esac
			asset_response=$(release_http "$asset_redirect" "$2" "$3") ||
				fail "cannot download release asset from GitHub storage: $1"
			[ "$asset_response" = '200 ' ] || fail 'unexpected response from GitHub release storage'
			;;
		*) fail "unexpected release asset response: $1" ;;
	esac
}

archive_checksum() {
	checksum_bytes=$(file_bytes "$1") || return 1
	[ "$(tr -cd '\012\040-\176' < "$1" | wc -c | tr -d ' ')" = "$checksum_bytes" ] || return 1
	checksum_lines=$(wc -l < "$1") || return 1
	awk -v selected="$2" -v lines="$checksum_lines" '
		{
			hash = substr($0, 1, 64)
			file = substr($0, 67)
			if (length(hash) != 64 || hash ~ /[^0-9a-f]/ || substr($0, 65, 2) != "  ") bad=1
			if (file !~ /^exacopy-cli-(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu)[.]tar[.]gz$/ &&
			    file !~ /^exacopy-cli-(aarch64|x86_64)-pc-windows-msvc[.]zip$/) bad=1
			if (NR > 1 && file <= previous) bad=1
			previous = file
			if (file == selected) expected = hash
		}
		END {
			if (bad || NR != lines || expected == "") exit 1
			print expected
		}
	' "$1"
}

download_release() {
	verify_publisher_pin
	(
		unset PERLLIB PERLIO
		/usr/bin/perl -MIO::Uncompress::Gunzip -e 1
	) >/dev/null 2>&1 || fail 'online install requires host Perl with IO::Uncompress::Gunzip'
	[ -x /usr/bin/curl ] || fail 'online install requires /usr/bin/curl'
	resolve_latest
	archive_name=exacopy-cli-$target.tar.gz
	fetch_asset SHA256SUMS.txt "$scratch/checksums" "$checksum_limit"
	expected_archive_hash=$(archive_checksum "$scratch/checksums" "$archive_name") ||
		fail 'invalid release SHA256SUMS.txt or missing platform archive checksum'
	fetch_asset "$archive_name" "$scratch/archive.tar.gz" "$archive_limit"
	actual_archive_hash=$(hash_file "$scratch/archive.tar.gz") || fail 'cannot hash release archive'
	[ "$actual_archive_hash" = "$expected_archive_hash" ] || fail 'release archive SHA-256 mismatch'

	bundle=$scratch/bundle
	mkdir -m 700 "$bundle" || fail 'cannot create private release bundle directory'
	(
		unset PERLLIB PERLIO
		/usr/bin/perl "$script_dir/tools/installer/unpack_release.pl" "$scratch/archive.tar.gz" "$bundle"
	) || fail 'cannot unpack release archive'
}
