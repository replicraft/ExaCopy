#!/bin/sh
set -eu

case $0 in
	*/*) script_dir=${0%/*} ;;
	*) script_dir=. ;;
esac
operation=install
# shellcheck source=tools/installer/posix.sh
. "$script_dir/tools/installer/posix.sh"
installer_main "$@"
