"""Make the repo root and ``scripts/`` importable for staging tests.

``scripts/`` is not an installed package, so the tests import the staging
tooling by putting both directories on ``sys.path``.  No test mutates the
repository: materialization tests always target ``tmp_path``.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"

for _entry in (str(REPO_ROOT), str(SCRIPTS)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)
