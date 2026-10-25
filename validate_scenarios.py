"""
RedSim – Adversary Simulation Platform
Standalone scenario validation script.
"""

import sys
import os

# Ensure the root is in the path for standalone execution
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from utils.bulk_validator import run_bulk_validation # type: ignore


if __name__ == "__main__":
    # Execute the core validation logic moved strictly to the utils package
    sys.exit(run_bulk_validation())
