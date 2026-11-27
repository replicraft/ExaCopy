"""Run the closed native production managed-sync profile."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "crates/platform/exacopy-platform/verification/sync_history_ext4"))
from run import MANAGED, main


if __name__ == "__main__":
    raise SystemExit(main(MANAGED))
