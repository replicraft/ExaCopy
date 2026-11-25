#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=.github/ci/common.sh
source "$(dirname "$0")/common.sh"

tool=$1
temp_dir=$(runner_temp)
install_dir="$temp_dir/exacopy-tools/$tool"
mkdir -p "$install_dir"
asset="$install_dir/download"

case "$tool" in
	rust)
		rustup toolchain install 1.100.0 --profile minimal --component rustfmt --component clippy
		rust_version=$(rustc +1.100.0 -vV)
		printf '%s\n' "$rust_version"
		if [[ -n ${EXPECTED_RUST_HOST:-} ]]; then
			grep -Fxq "host: $EXPECTED_RUST_HOST" <<< "$rust_version"
		fi
		cargo +1.100.0 -V
		;;
	nextest)
		executable=cargo-nextest
		case "${RUNNER_OS:-}" in
			Linux)
				platform=x86_64-unknown-linux-gnu
				digest=1d4ce302b820c41f4b89c5fb9bce45f0f0c94882c1cf08fc360caf08be6e7df4
				;;
			macOS)
				platform=universal-apple-darwin
				digest=d1d7d025d4bfc9fb154cd76aea3949bd78534829a0589abefa6e5dd4edb135dd
				;;
			Windows)
				platform=x86_64-pc-windows-msvc
				digest=e51bdb4b5883df48f335381b287378edb244318fac65ae0adaf6b9e69298246b
				executable=cargo-nextest.exe
				;;
			*)
				printf 'No pinned nextest asset for runner %s\n' "${RUNNER_OS:-unknown}" >&2
				exit 1
				;;
		esac
		version=0.9.151
		fetch "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/cargo-nextest-$version-$platform.tar.gz" "$digest" "$asset"
		tar -xzf "$asset" -C "$install_dir"
		"$install_dir/$executable" nextest --version
		add_path "$install_dir"
		;;
	lean)
		fetch https://github.com/pereq-dev/hax/releases/download/cargo-hax-v0.4.2/cargo-hax-x86_64-unknown-linux-gnu.tar.zst \
			64b15097c003919075c7e8cca845db0e29718c0683596b739677b159ceb138f4 "$asset"
		tar --zstd -xf "$asset" -C "$install_dir"
		fetch https://github.com/leanprover/elan/releases/download/v4.4.0/elan-x86_64-unknown-linux-gnu.tar.gz \
			0e8250aa2be86c7af929ade68db617af9edc8b9ccf6eaf5ece228250d0d032e2 "$asset"
		tar -xzf "$asset" -C "$install_dir"
		"$install_dir/elan-init" -y --no-modify-path --default-toolchain none
		"$HOME/.elan/bin/elan" --version
		add_path "$HOME/.elan/bin"
		add_path "$install_dir"
		;;
	kani)
		lock=crates/core/model/verification/kani/toolchain.lock.json
		platform=x86_64-unknown-linux-gnu
		version=$(jq -er '.kani.version' "$lock")
		archive_url=$(jq -er --arg platform "$platform" '.kani.archives[$platform].url' "$lock")
		archive_digest=$(jq -er --arg platform "$platform" '.kani.archives[$platform].sha256' "$lock")
		nightly=$(jq -er '.rust.toolchain' "$lock")
		fetch "$archive_url" "$archive_digest" "$asset"
		tar -xzf "$asset" -C "$install_dir"
		rustup toolchain install "$nightly" --profile minimal
		kani_rustc=$(rustup which --toolchain "$nightly" rustc)
		ln -s "$(dirname "$(dirname "$kani_rustc")")" "$install_dir/kani-$version/toolchain"
		ln -s kani-driver "$install_dir/kani-$version/bin/cargo-kani"
		"$install_dir/kani-$version/bin/cargo-kani" kani --version --verbose
		add_path "$install_dir/kani-$version/bin"
		;;
	miri)
		rustup toolchain install nightly-2026-11-04 --profile minimal --component miri --component rust-src
		rustc +nightly-2026-11-04 -vV
		cargo +nightly-2026-11-04 miri --version
		;;
	coverage)
		rustup toolchain install nightly-2026-11-04 --profile minimal --component llvm-tools
		rustc +nightly-2026-11-04 -vV
		fetch https://github.com/taiki-e/cargo-llvm-cov/releases/download/v0.9.1/cargo-llvm-cov-x86_64-unknown-linux-gnu.tar.gz \
			b3f68e625481fed9b16444174f3fa5ebcdbde4a1878803a35eabe2dcefcdc41a "$asset"
		tar -xzf "$asset" -C "$install_dir"
		"$install_dir/cargo-llvm-cov" llvm-cov --version
		add_path "$install_dir"
		;;
	mutation)
		fetch https://github.com/sourcefrog/cargo-mutants/releases/download/v27.1.0/cargo-mutants-x86_64-unknown-linux-gnu.tar.gz \
			dfe6dc37d0342c891d2829b5a695aa57c2d0edecef7e7d0399a30cc6e206411e "$asset"
		tar -xzf "$asset" -C "$install_dir"
		"$install_dir/cargo-mutants" mutants --version
		add_path "$install_dir"
		;;
	tlc)
		fetch 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.8%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.8_9.tar.gz' \
			f2dc5418092c43003db8f9005c4a286e1c0104fea96ccdd49e8ebd037cac9219 "$asset"
		mkdir -p "$install_dir/java"
		tar -xzf "$asset" --strip-components=1 -C "$install_dir/java"
		"$install_dir/java/bin/java" -version
		add_path "$install_dir/java/bin"
		lock=crates/core/model/verification/tla/toolchain.lock.json
		jar_url=$(jq -er '.tlc.url' "$lock")
		jar_digest=$(jq -er '.tlc.sha256' "$lock")
		fetch "$jar_url" "$jar_digest" "$install_dir/tla2tools.jar"
		printf 'TLA2TOOLS_JAR=%s\n' "$install_dir/tla2tools.jar" >> "$GITHUB_ENV"
		;;
	deny)
		fetch https://github.com/EmbarkStudios/cargo-deny/releases/download/0.22.1/cargo-deny-0.22.1-x86_64-unknown-linux-musl.tar.gz \
			13f7e825e9cb811c2f8de63f29b0f45851dfb53004029f0f2501af524728364d "$asset"
		tar -xzf "$asset" --strip-components=1 -C "$install_dir"
		"$install_dir/cargo-deny" --version
		add_path "$install_dir"
		;;
	audit)
		fetch https://github.com/RustSec/rustsec/releases/download/cargo-audit/v0.23.0/cargo-audit-x86_64-unknown-linux-gnu-v0.23.0.tgz \
			b77993532b253fcbf550996d7716465ec3d734d4e74e7f87bfb65a19add0fb59 "$asset"
		tar -xzf "$asset" --strip-components=1 -C "$install_dir"
		"$install_dir/cargo-audit" --version
		add_path "$install_dir"
		;;
	vet)
		fetch https://github.com/mozilla/cargo-vet/releases/download/v0.10.4/cargo-vet-x86_64-unknown-linux-gnu.tar.xz \
			e367f8ac156208711511274abab0c309e19ed0f11ef2bbe8a7b0294f824cb032 "$asset"
		tar -xJf "$asset" --strip-components=1 -C "$install_dir"
		"$install_dir/cargo-vet" --version
		add_path "$install_dir"
		;;
	gitleaks)
		fetch https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
			551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$asset"
		tar -xzf "$asset" -C "$install_dir" gitleaks
		"$install_dir/gitleaks" version
		add_path "$install_dir"
		;;
	trivy)
		fetch https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz \
			bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf "$asset"
		tar -xzf "$asset" -C "$install_dir" trivy
		"$install_dir/trivy" --version
		add_path "$install_dir"
		;;
	*)
		printf 'Unknown CI tool: %s\n' "$tool" >&2
		exit 1
		;;
esac
