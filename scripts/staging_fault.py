#!/usr/bin/env python
"""Materialize the isolated *faulty* staging tenant API build context.

The faulty image is built from an **isolated copy** of the pinned pristine
snapshot with the reviewed fault patch applied.  The pinned snapshot (and the
parent-supplied archive it came from) is never modified: this script copies it,
applies ``staging/faults/broken-revision.patch`` to the copy only, verifies the
patch applied with no fuzz or rejects, and records the patch/tree hashes.

The fault deliberately breaks a real authenticated business endpoint handler in
the actual tenant API binary (the tenant-scoped project listing).  It is not a
fake health or proxy response, and it is applied only to the faulty build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGING = REPO_ROOT / "staging"
PRISTINE = STAGING / "vendor" / "tenant-api-platform"
FAULTY = STAGING / "vendor" / "tenant-api-faulty"
PATCH = STAGING / "faults" / "broken-revision.patch"
RESOLVED_NAME = "faulty-manifest.resolved.json"
FAULTY_LABEL = "injected-fault"
_APPLIED_MARKER = "Injected staging fault (broken revision)"


class FaultError(RuntimeError):
    """The faulty build context could not be prepared safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _patch_argv(patch_file: Path, target: Path) -> list[str]:
    resolved = shutil.which("patch") or "patch"
    return [resolved, "-p1", "--forward", "--no-backup-if-mismatch", "-i", str(patch_file)]


def apply_patch(pristine: Path, target: Path, patch_file: Path) -> list[str]:
    """Apply the reviewed patch to a copy of ``pristine``; return changed files."""

    if not pristine.is_dir():
        raise FaultError(
            f"pristine snapshot not found at {pristine}; run scripts/staging_source.py first"
        )
    if not patch_file.is_file():
        raise FaultError(f"fault patch not found: {patch_file}")

    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".staging-faulty-", dir=str(target.parent)))
    dest = work / "tenant-api"
    try:
        shutil.copytree(pristine, dest)
        result = subprocess.run(
            _patch_argv(patch_file, dest),
            cwd=str(dest),
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            raise FaultError(f"fault patch failed to apply: {output.strip()}")
        if re.search(r"\bFAILED\b|\breject\b|Offset \d+ lines|with fuzz", output):
            raise FaultError(f"fault patch applied with fuzz/rejects: {output.strip()}")

        handler = dest / "internal/httpx/handlers_projects.go"
        if _APPLIED_MARKER not in handler.read_text(encoding="utf-8"):
            raise FaultError("fault patch did not inject the expected marker")

        changed = sorted(
            str(path.relative_to(dest)).replace(os.sep, "/")
            for path in dest.rglob("*")
            if path.is_file() and sha256_file(path) != _pristine_hash(pristine, path, dest)
        )
        # A rename-free diff: only files whose bytes changed are reported.
        if FAULTY.exists():
            shutil.rmtree(FAULTY)
        dest.rename(FAULTY)
        shutil.rmtree(work, ignore_errors=True)
        return changed
    except BaseException:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        raise


def _pristine_hash(pristine: Path, path: Path, dest: Path) -> str:
    relative = path.relative_to(dest)
    original = pristine / relative
    return sha256_file(original) if original.is_file() else ""


def write_resolved(changed: list[str]) -> dict:
    files = {
        str(path.relative_to(FAULTY)).replace(os.sep, "/"): sha256_file(path)
        for path in sorted(FAULTY.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "label": FAULTY_LABEL,
        "note": (
            "isolated faulty build copy; pristine snapshot and pinned archive are "
            "unmodified; a deliberate labelled staging fault, not an upstream regression"
        ),
        "patch": str(PATCH.relative_to(REPO_ROOT)).replace(os.sep, "/"),
        "patch_sha256": sha256_file(PATCH),
        "pristine": str(PRISTINE.relative_to(REPO_ROOT)).replace(os.sep, "/"),
        "dest": str(FAULTY.relative_to(REPO_ROOT)).replace(os.sep, "/"),
        "changed_files": changed,
        "materialized_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
    }
    (FAULTY.parent / RESOLVED_NAME).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def prepare() -> dict:
    changed = apply_patch(PRISTINE, FAULTY, PATCH)
    if not changed:
        raise FaultError("fault patch changed no files; refusing a no-op faulty build")
    return write_resolved(changed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate inputs only")
    args = parser.parse_args(argv)
    try:
        if args.check:
            if not PRISTINE.is_dir():
                raise FaultError(f"pristine snapshot missing: {PRISTINE}")
            if not PATCH.is_file():
                raise FaultError(f"fault patch missing: {PATCH}")
            print("faulty build inputs present")
            return 0
        manifest = prepare()
    except FaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"faulty dest:   {manifest['dest']}")
    print(f"changed files: {manifest['changed_files']}")
    print(f"patch sha256:  {manifest['patch_sha256']}")
    print(f"provenance:    {FAULTY.parent / RESOLVED_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
