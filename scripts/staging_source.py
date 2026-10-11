#!/usr/bin/env python
"""Materialize the pinned tenant-api-platform source snapshot safely.

The staging stack builds the *real* tenant API from a parent-supplied pinned
git archive (``.hermes/tenant-api-a6f715a.tar``).  This script is the only
thing allowed to unpack that archive into the gitignored build context
(``staging/vendor/tenant-api-platform``).  It refuses, before extracting a
single byte:

* a source SHA that does not match the reviewed pin,
* an archive whose SHA-256 does not match the pinned archive hash,
* an archive whose embedded git commit id (the pax ``comment`` header written by
  ``git archive``) does not match the pinned SHA,
* any member with an absolute path, a drive-letter path, a ``..`` traversal
  component, a NUL byte, or a link/unsupported type.

For future reproducibility the same code path can regenerate the archive from an
explicit source repository and SHA (``--source-repo``); that path performs the
same member/provenance checks and is intended for the orchestrator only.

The archive is a *metadata input* supplied by the parent, not evidence produced
here.  The script records exactly what it consumed (archive hash, commit id,
per-file hashes) in a resolved manifest next to the snapshot so provenance is
reproducible without trusting a sibling checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "staging" / "source-manifest.json"
DEFAULT_DEST = REPO_ROOT / "staging" / "vendor" / "tenant-api-platform"
RESOLVED_NAME = "source-manifest.resolved.json"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_UNSAFE_PARTS_RE = re.compile(r"[\\/]+")


class SourceError(RuntimeError):
    """A refusal to use unsafe or unpinned source material."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_sha(value: str) -> str:
    text = (value or "").strip()
    if not _SHA_RE.match(text):
        raise SourceError(
            f"not a full 40-character lowercase git SHA: {value!r}"
        )
    return text


def load_manifest(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise SourceError(f"source manifest not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SourceError(f"source manifest is not valid JSON: {exc}") from exc
    for key in ("source_sha", "archive", "archive_sha256"):
        if not data.get(key):
            raise SourceError(f"source manifest is missing {key!r}")
    data["source_sha"] = normalize_sha(data["source_sha"])
    data["archive_sha256"] = data["archive_sha256"].strip().lower()
    return data


def unsafe_member_reason(name: str) -> str | None:
    """Return a human-readable reason if ``name`` is unsafe to extract."""

    if not name:
        return "empty member name"
    if "\x00" in name:
        return "NUL byte in member name"
    if _DRIVE_RE.match(name):
        return f"drive-letter path {name!r}"
    if name.startswith(("/", "\\")):
        return f"absolute path {name!r}"
    parts = [part for part in _UNSAFE_PARTS_RE.split(name) if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return f"path traversal in {name!r}"
    return None


def inspect_members(members) -> list[str]:
    """Return the reasons the given tar members must not be extracted."""

    reasons: list[str] = []
    for member in members:
        reason = unsafe_member_reason(member.name)
        if reason is not None:
            reasons.append(reason)
            continue
        if member.issym() or member.islnk():
            reasons.append(
                f"link member {member.name!r} -> {member.linkname!r} is not allowed"
            )
        elif not (member.isfile() or member.isdir()):
            reasons.append(f"unsupported member type for {member.name!r} ({member.type!r})")
    return reasons


def archive_commit(path: Path) -> str | None:
    """Return the git commit id embedded by ``git archive``, if present."""

    with tarfile.open(path, "r:*") as tar:
        comment = (tar.pax_headers or {}).get("comment")
        if comment:
            return comment.strip().lower()
        for member in tar.getmembers():
            candidate = (member.pax_headers or {}).get("comment")
            if candidate:
                return candidate.strip().lower()
    return None


def verify_archive_pin(archive: Path, manifest: dict) -> str:
    archive = Path(archive)
    if not archive.exists():
        raise SourceError(f"pinned archive not found: {archive}")
    actual = sha256_file(archive)
    expected = manifest["archive_sha256"]
    if actual != expected:
        raise SourceError(
            f"archive sha256 mismatch: got {actual}, expected {expected}"
        )
    return actual


def _assert_within(root: Path, candidate: Path) -> None:
    root_real = root.resolve()
    candidate_real = candidate.resolve()
    if root_real not in candidate_real.parents and candidate_real != root_real:
        raise SourceError(f"extracted path {candidate_real} escapes {root_real}")


def _git_archive(source_repo: str, sha: str, target: Path) -> None:
    resolved = shutil.which("git") or "git"
    result = subprocess.run(
        [resolved, "-C", source_repo, "archive", "--format=tar", f"--output={target}", sha],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SourceError(
            f"git archive failed for {sha} in {source_repo}: {result.stderr.strip()}"
        )


def materialize(
    archive: Path,
    dest: Path,
    manifest: dict,
    *,
    sha: str | None = None,
    source_repo: str | None = None,
) -> dict:
    """Verify, extract and record the pinned source. Returns resolved provenance."""

    pinned = normalize_sha(sha or manifest["source_sha"])
    if pinned != manifest["source_sha"]:
        raise SourceError(
            f"unexpected source SHA {pinned}; the reviewed pin is {manifest['source_sha']}"
        )

    archive = Path(archive)
    dest = Path(dest)
    if source_repo:
        tmp_dir = Path(tempfile.mkdtemp(prefix="staging-src-"))
        tmp_archive = tmp_dir / "source.tar"
        try:
            _git_archive(source_repo, pinned, tmp_archive)
            _materialize_from(tmp_archive, dest, pinned)
            return _write_resolved(dest, manifest, pinned, sha256_file(tmp_archive), True)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    archive_hash = verify_archive_pin(archive, manifest)
    _materialize_from(archive, dest, pinned)
    return _write_resolved(dest, manifest, pinned, archive_hash, False)


def _materialize_from(archive: Path, dest: Path, pinned: str) -> None:
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        reasons = inspect_members(members)
        if reasons:
            raise SourceError("unsafe archive members: " + "; ".join(reasons[:10]))

        embedded = archive_commit(archive)
        if embedded is None:
            raise SourceError("archive does not embed a git commit id; refusing")
        if embedded != pinned:
            raise SourceError(
                f"archive embeds commit {embedded}, not the pinned {pinned}"
            )

        dest.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(
            tempfile.mkdtemp(prefix=".staging-src-", dir=str(dest.parent))
        )
        try:
            tar.extractall(path=staging_dir, filter="data")
            for path in staging_dir.rglob("*"):
                _assert_within(staging_dir, path)
            if dest.exists():
                shutil.rmtree(dest)
            staging_dir.rename(dest)
        except BaseException:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
            raise


def _write_resolved(
    dest: Path,
    manifest: dict,
    pinned: str,
    archive_hash: str,
    regenerated: bool,
) -> dict:
    files: dict[str, str] = {}
    for path in sorted(dest.rglob("*")):
        if path.is_file():
            files[path.relative_to(dest).as_posix()] = sha256_file(path)
    provenance = {
        "manifest_version": manifest.get("manifest_version", 1),
        "component": manifest.get("component", "tenant-api-platform"),
        "source_sha": pinned,
        "archive": None if regenerated else manifest["archive"],
        "archive_sha256": archive_hash,
        "archive_regenerated_from_source_repo": regenerated,
        "materialized_at": datetime.now(timezone.utc).isoformat(),
        "dest": dest.as_posix(),
        "file_count": len(files),
        "files": files,
    }
    resolved_path = dest.parent / RESOLVED_NAME
    resolved_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--archive",
        type=Path,
        default=None,
        help="pinned archive path (defaults to the manifest's archive, repo-relative)",
    )
    parser.add_argument(
        "--sha", default=None, help="expected full source SHA (validated against the pin)"
    )
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument(
        "--source-repo",
        default=None,
        help="orchestrator-only: regenerate the archive from this repo at --sha",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        archive = args.archive or (REPO_ROOT / manifest["archive"])
        provenance = materialize(
            archive,
            args.dest,
            manifest,
            sha=args.sha,
            source_repo=args.source_repo,
        )
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Summary only; never prints secrets (there are none in a source archive).
    print(f"source_sha:      {provenance['source_sha']}")
    print(f"archive_sha256:  {provenance['archive_sha256']}")
    print(f"files:           {provenance['file_count']}")
    print(f"dest:            {provenance['dest']}")
    print(f"provenance:      {(args.dest.parent / RESOLVED_NAME)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
