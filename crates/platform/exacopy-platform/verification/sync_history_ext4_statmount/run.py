"""Run the closed, feature-qualified ext4 statmount profile."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sync_history_ext4"))
from run import STATMOUNT, main


if __name__ == "__main__":
    raise SystemExit(main(STATMOUNT))
