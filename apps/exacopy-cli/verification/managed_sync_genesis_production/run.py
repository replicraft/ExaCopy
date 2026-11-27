"""Run the closed native production managed-sync genesis profile."""

from pathlib import Path
import sys

import oracle

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "crates/platform/exacopy-platform/verification/sync_history_ext4"))
from run import GENESIS, main


if __name__ == "__main__":
    raise SystemExit(main(GENESIS, genesis_oracle=oracle))
