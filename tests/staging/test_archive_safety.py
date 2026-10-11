"""Archive-safety and provenance tests for ``scripts/staging_source.py``.

The staging snapshot is materialized from a parent-supplied pinned git archive.
These tests prove the materializer refuses the classes of input that make
archive extraction dangerous (path traversal, absolute paths, drive-letter
paths, links that escape the destination) and that it binds the extracted tree
to the pinned commit and archive hash before any byte reaches the build
context.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

import staging_source

REPO_ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = REPO_ROOT / ".hermes" / "tenant-api-a6f715a.tar"
MANIFEST = REPO_ROOT / "staging" / "source-manifest.json"


def _manifest() -> dict:
    return staging_source.load_manifest(MANIFEST)


def test_required_archive_present() -> None:
    # Required prerequisite: fail loudly (never skip) when the parent-supplied
    # pin is missing, because provenance cannot be proven without it.
    assert ARCHIVE.exists(), f"missing pinned archive {ARCHIVE}"


def test_sha_validation_rejects_malformed() -> None:
    for bad in ("a6f715a", "ZZZ", "", "a6f715aac1d4e46b2ef30e12fb42d4719672f7f", "A" * 40):
        with pytest.raises(staging_source.SourceError):
            staging_source.normalize_sha(bad)


def test_sha_validation_accepts_full_lowercase() -> None:
    sha = "a6f715aac1d4e46b2ef30e12fb42d4719672f7f5"
    assert staging_source.normalize_sha(sha) == sha


def test_archive_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    fake = tmp_path / "wrong.tar"
    fake.write_bytes(b"not the pinned archive")
    with pytest.raises(staging_source.SourceError):
        staging_source.verify_archive_pin(fake, _manifest())


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/etc/passwd",
        "a/../../b",
        "C:/Windows/system32",
        "c:\\windows\\system32",
        "foo/..",
        "..",
    ],
)
def test_unsafe_member_names_are_rejected(name: str) -> None:
    assert staging_source.unsafe_member_reason(name) is not None


def test_safe_member_names_are_accepted() -> None:
    for name in ("cmd/api/main.go", "internal/platform/db/role.go", "go.mod"):
        assert staging_source.unsafe_member_reason(name) is None


def test_symlink_members_are_rejected() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        tar.addfile(info)
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        members = tar.getmembers()
    reasons = staging_source.inspect_members(members)
    assert reasons, "a symlink member must be reported as unsafe"


def test_real_archive_passes_member_inspection() -> None:
    with tarfile.open(ARCHIVE, "r:*") as tar:
        reasons = staging_source.inspect_members(tar.getmembers())
    assert reasons == [], f"pinned archive contains unsafe members: {reasons}"


def test_real_archive_binds_to_pinned_commit() -> None:
    commit = staging_source.archive_commit(ARCHIVE)
    assert commit == _manifest()["source_sha"], (
        "the archive's embedded git commit id does not match the pinned SHA"
    )


def test_materialize_verifies_sha_and_hash(tmp_path: Path) -> None:
    manifest = _manifest()
    with pytest.raises(staging_source.SourceError):
        staging_source.materialize(
            ARCHIVE, tmp_path / "dest", manifest, sha="0" * 40
        )


def test_materialize_writes_expected_tree_and_provenance(tmp_path: Path) -> None:
    manifest = _manifest()
    dest = tmp_path / "tenant-api-platform"
    provenance = staging_source.materialize(ARCHIVE, dest, manifest)

    assert (dest / "Dockerfile").is_file()
    assert (dest / "go.mod").is_file()
    assert (dest / "cmd" / "api" / "main.go").is_file()

    assert provenance["source_sha"] == manifest["source_sha"]
    assert provenance["archive_sha256"] == manifest["archive_sha256"]
    assert provenance["file_count"] == len(provenance["files"])

    # Every recorded hash must describe the file actually on disk.
    for rel, digest in provenance["files"].items():
        data = (dest / rel).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, f"hash mismatch for {rel}"


def test_materialize_is_idempotent(tmp_path: Path) -> None:
    manifest = _manifest()
    dest = tmp_path / "tenant-api-platform"
    first = staging_source.materialize(ARCHIVE, dest, manifest)
    second = staging_source.materialize(ARCHIVE, dest, manifest)
    assert first["files"] == second["files"]


def test_materialize_rejects_traversal_archive(tmp_path: Path) -> None:
    malicious = tmp_path / "evil.tar"
    with tarfile.open(malicious, "w") as tar:
        payload = b"owned"
        info = tarfile.TarInfo("../../escaped.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    manifest = dict(_manifest())
    # Force the pin checks to pass by recording the malicious archive's hash;
    # the member inspection must still refuse it.
    manifest["archive"] = str(malicious)
    manifest["archive_sha256"] = hashlib.sha256(malicious.read_bytes()).hexdigest()

    dest = tmp_path / "dest"
    with pytest.raises(staging_source.SourceError):
        staging_source.materialize(malicious, dest, manifest)
    assert not (tmp_path / "escaped.txt").exists()
