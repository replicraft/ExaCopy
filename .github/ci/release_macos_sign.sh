#!/usr/bin/env bash
set -euo pipefail

directory=$1
binary="$directory/exacopy"
for setting in EXACOPY_MACOS_CERT_P12_B64 EXACOPY_MACOS_CERT_PASSWORD EXACOPY_MACOS_SIGNING_IDENTITY \
	EXACOPY_MACOS_TEAM_ID EXACOPY_APPLE_NOTARY_KEY_B64 EXACOPY_APPLE_NOTARY_KEY_ID EXACOPY_APPLE_NOTARY_ISSUER_ID; do
	if [[ -z ${!setting:-} ]]; then
		printf 'Production macOS signing requires %s\n' "$setting" >&2
		exit 1
	fi
done

umask 077
work=$(mktemp -d "${RUNNER_TEMP:?}/exacopy-apple-signing.XXXXXXXX")
keychain="$work/signing.keychain-db"
cleanup() {
	security delete-keychain "$keychain" >/dev/null 2>&1 || true
	rm -f "$work/certificate.p12" "$work/api-key.p8" "$work/exacopy.zip" \
		"$work/notary.json" "$work/signing.keychain-db"
	rmdir "$work"
}
trap cleanup EXIT

printf '%s' "$EXACOPY_MACOS_CERT_P12_B64" | /usr/bin/base64 -D > "$work/certificate.p12"
printf '%s' "$EXACOPY_APPLE_NOTARY_KEY_B64" | /usr/bin/base64 -D > "$work/api-key.p8"
certificate_password=$EXACOPY_MACOS_CERT_PASSWORD
unset EXACOPY_MACOS_CERT_P12_B64 EXACOPY_MACOS_CERT_PASSWORD EXACOPY_APPLE_NOTARY_KEY_B64

export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
xcodebuild -version
keychain_password=$(openssl rand -hex 32)
security create-keychain -p "$keychain_password" "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$work/certificate.p12" -k "$keychain" -P "$certificate_password" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain"
unset certificate_password keychain_password

codesign --force --keychain "$keychain" --sign "$EXACOPY_MACOS_SIGNING_IDENTITY" \
	--options runtime --timestamp "$binary"
report="$directory/native-signature.txt"
{
	codesign --verify --strict --verbose=2 "$binary"
	codesign -d --verbose=4 "$binary"
} > "$report" 2>&1
grep -Fqx "TeamIdentifier=$EXACOPY_MACOS_TEAM_ID" "$report"
grep -q '^Authority=Developer ID Application:' "$report"
grep -q '^Timestamp=' "$report"
[[ $(lipo -archs "$binary") == arm64 ]]
ditto -c -k --keepParent "$binary" "$work/exacopy.zip"
xcrun notarytool submit "$work/exacopy.zip" --key "$work/api-key.p8" \
	--key-id "$EXACOPY_APPLE_NOTARY_KEY_ID" --issuer "$EXACOPY_APPLE_NOTARY_ISSUER_ID" \
	--timeout 20m --wait --output-format json > "$work/notary.json"
cat "$work/notary.json"
jq -e '.status == "Accepted" and (.id | type == "string" and length > 0)' "$work/notary.json" > /dev/null
printf '\n' >> "$report"
cat "$work/notary.json" >> "$report"
