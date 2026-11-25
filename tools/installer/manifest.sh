# Exact offline release manifest v1 shared by the installer front ends.

hash_file() {
	if [ "$host_os" = Darwin ]; then
		hash_output=$(shasum -a 256 < "$1") || return
	else
		hash_output=$(sha256sum < "$1") || return
	fi
	printf '%s\n' "${hash_output%% *}"
}

hex_pin() {
	[ "${#1}" -eq 64 ] && case $1 in
		*[!0123456789abcdef]*) return 1 ;;
		*) return 0 ;;
	esac
}

numeric_version_at_least() {
	awk -v actual="$1" -v minimum="$2" '
		function valid(text) { return text ~ /^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)([.](0|[1-9][0-9]*))?([.](0|[1-9][0-9]*))?$/ }
		BEGIN {
			if (!valid(actual) || !valid(minimum)) exit 2
			split(actual, a, ".")
			split(minimum, b, ".")
			for (i = 1; i <= 4; i++) {
				if (length(a[i]) > 6 || length(b[i]) > 6) exit 2
			}
			for (i = 1; i <= 4; i++) {
				if (a[i]+0 != b[i]+0) exit (a[i]+0 < b[i]+0)
			}
		}
	'
}

offline_manifest() {
	printable_bytes=$(tr -cd '\012\040-\176' < "$1" | wc -c | tr -d ' ')
	[ "$printable_bytes" = "$(file_bytes "$1")" ] || fail 'manifest contains non-ASCII or control bytes'
	[ "$(wc -l < "$1" | tr -d ' ')" = 17 ] || fail 'manifest must contain 17 LF-terminated lines'
	awk -F= '
		BEGIN {
			split("schema version channel created expires sequence target variant format artifact size sha256 publisher_sha256 min_os min_abi sbom_sha256 provenance_sha256", keys, " ")
		}
		NF != 2 || $1 != keys[NR] || $2 !~ /^[a-zA-Z0-9._-]+$/ { bad = 1 }
		END { if (NR != 17 || bad) exit 1 }
	' "$1" || fail 'invalid manifest fields'
}

manifest_field() {
	awk -F= -v key="$1" '$1 == key { print $2 }' "$manifest"
}

check_manifest() {
	offline_manifest "$manifest"
	[ "$(manifest_field schema)" = exacopy-release-v1 ] || fail 'unsupported manifest schema'
	[ "$(manifest_field version)" = "$version" ] || fail 'release version mismatch'
	[ "$(manifest_field channel)" = stable ] || fail 'only the stable channel is supported'
	[ "$(manifest_field target)" = "$target" ] || fail 'release target mismatch'
	[ "$(manifest_field variant)" = cli ] || fail 'only the CLI variant is supported'
	[ "$(manifest_field format)" = raw ] || fail 'only single raw CLI artifacts are supported'
	[ "$(manifest_field artifact)" = exacopy ] || fail 'unexpected artifact name'
	[ "$(manifest_field publisher_sha256)" = "$publisher_pin" ] || fail 'publisher pin mismatch'
	artifact_hash=$(manifest_field sha256)
	hex_pin "$artifact_hash" && hex_pin "$(manifest_field sbom_sha256)" &&
		hex_pin "$(manifest_field provenance_sha256)" || fail 'invalid signed SHA-256 fields'

	artifact_size=$(manifest_field size)
	positive_decimal "$artifact_size" 9 && [ "$artifact_size" -le 268435456 ] ||
		fail 'artifact size is outside the profile'
	sequence=$(manifest_field sequence)
	positive_decimal "$sequence" 10 && [ "$sequence" -le 2147483647 ] || fail 'invalid release sequence'
	created=$(manifest_field created)
	expires=$(manifest_field expires)
	positive_decimal "$created" 10 && positive_decimal "$expires" 10 &&
		[ "${#created}" -eq 10 ] && [ "${#expires}" -eq 10 ] &&
		[ "$created" -lt "$expires" ] || fail 'invalid release validity interval'

	min_os=$(manifest_field min_os)
	min_abi=$(manifest_field min_abi)
	if [ "$host_os" = Darwin ]; then
		numeric_version_at_least "$min_os" 14.0 && [ "$min_abi" = native ] ||
			fail 'invalid signed macOS OS or ABI floor'
	else
		numeric_version_at_least "$min_os" 5.15 && numeric_version_at_least "$min_abi" 2.35 ||
			fail 'invalid signed Linux OS or ABI floor'
	fi

	if [ "$operation" = install ]; then
		now=$(date +%s) || fail 'cannot read the UTC clock'
		[ "$now" -ge "$created" ] && [ "$now" -lt "$expires" ] ||
			fail 'release is outside the signed validity interval'
		if [ "$host_os" = Darwin ]; then
			numeric_version_at_least "$(sw_vers -productVersion)" "$min_os" ||
				fail 'macOS host does not meet the signed OS floor'
		else
			kernel_release=$(uname -r)
			abi_name=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'GNU libc is required'
			case $abi_name in
				'glibc '*) host_abi=${abi_name#glibc } ;;
				*) fail 'GNU libc is required' ;;
			esac
			numeric_version_at_least "${kernel_release%%-*}" "$min_os" &&
				numeric_version_at_least "$host_abi" "$min_abi" ||
				fail 'Linux host does not meet the signed OS and glibc floors'
		fi
	fi
}

positive_decimal() {
	[ "${#1}" -le "$2" ] && case $1 in
		''|0*|*[!0123456789]*) return 1 ;;
		*) return 0 ;;
	esac
}

verify_publisher_pin() {
	actual_pin=$(hash_file "$scratch/publisher.der") || fail 'cannot hash publisher certificate'
	[ "$actual_pin" = "$publisher_pin" ] || fail 'publisher certificate does not match supplied pin'
}

verify_signature() {
	verify_publisher_pin
	/usr/bin/openssl x509 -inform DER -in "$scratch/publisher.der" -pubkey -noout > "$scratch/publisher.pem" ||
		fail 'cannot extract publisher public key'
	rsa=$(/usr/bin/openssl rsa -pubin -in "$scratch/publisher.pem" -modulus -noout 2>/dev/null) ||
		fail 'RSA publisher key is required'
	case $rsa in
		Modulus=*) rsa=${rsa#Modulus=} ;;
		*) fail 'invalid RSA publisher modulus' ;;
	esac
	case $rsa in
		''|*[!0123456789ABCDEFabcdef]*) fail 'invalid RSA publisher modulus' ;;
	esac
	[ "${#rsa}" -ge 768 ] && [ "${#rsa}" -le 2048 ] || fail 'RSA publisher key outside 3072–8192 bits'
	if [ "${#rsa}" -eq 768 ]; then
		case $rsa in
			[89ABCDEFabcdef]*) : ;;
			*) fail 'RSA publisher key below 3072 bits' ;;
		esac
	fi
	[ "$(file_bytes "$signature")" -eq $(( (${#rsa} + 1) / 2 )) ] || fail 'signature size mismatch'
	/usr/bin/openssl dgst -sha256 -sigopt rsa_padding_mode:pkcs1 -verify "$scratch/publisher.pem" -signature "$signature" "$manifest" >/dev/null ||
		fail 'release signature verification failed'
}
