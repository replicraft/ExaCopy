#!/bin/sh
set -eu

model_dir=$(cd "$(dirname "$0")" && pwd -P)
python3 -B "$model_dir/managed_action_runner_test.py"
exec python3 -B "$model_dir/check-managed-action.py"
