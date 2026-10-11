"""The committed staging source pin and its binding to the supplied archive."""

from __future__ import annotations

import json
from pathlib import Path

import staging_source

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "staging" / "source-manifest.json"
ARCHIVE = REPO_ROOT / ".hermes" / "tenant-api-a6f715a.tar"

PINNED_SHA = "a6f715aac1d4e46b2ef30e12fb42d4719672f7f5"
ARCHIVE_SHA256 = "3837fb8bf2bf06080af068a75a6cfd2e22d1f4e15e5b104b73dacd015c5ca48c"


def test_manifest_is_valid_json() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["source_sha"] == PINNED_SHA
    assert data["short_sha"] == "a6f715a"
    assert data["archive_sha256"] == ARCHIVE_SHA256
    assert data["archive"] == ".hermes/tenant-api-a6f715a.tar"


def test_manifest_sha_equals_archive_embedded_commit() -> None:
    manifest = staging_source.load_manifest(MANIFEST)
    assert staging_source.archive_commit(ARCHIVE) == manifest["source_sha"]


def test_manifest_archive_hash_matches_archive() -> None:
    manifest = staging_source.load_manifest(MANIFEST)
    assert staging_source.sha256_file(ARCHIVE) == manifest["archive_sha256"]


def test_manifest_does_not_claim_parent_verification() -> None:
    text = MANIFEST.read_text(encoding="utf-8").lower()
    # The pin is a parent-supplied input, not something this repo verified.
    assert "parent-supplied" in text
