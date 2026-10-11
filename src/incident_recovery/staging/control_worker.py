"""Entrypoint for the isolated staging recovery worker container.

Run as ``python -m incident_recovery.staging.control_worker``; the worker binds
the fixed staging profile and the staging observation adapter.
"""

from __future__ import annotations

from .control import main_worker

if __name__ == "__main__":
    main_worker()
