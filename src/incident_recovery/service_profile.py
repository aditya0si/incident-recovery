"""Explicit, validated service profiles for the recovery control plane.

The control plane is the *same* reviewed workflow for every workload, but a
workload is never allowed to be arbitrary.  A :class:`ServiceProfile` fixes, in
one reviewed place:

* the service identity every record (incident, evidence, proposal, approval,
  reservation, operation, tool target) is bound to,
* the closed set of revisions the traffic gateway may route to, and
* the immutable revision -> fixed destination map (compose DNS names only).

Only two profiles exist and they are constructed from constants, never from
request input or from a caller-supplied URL.  :func:`load_service_profile`
selects one by the ``SERVICE_PROFILE`` environment value and *fails closed* on
anything it does not recognise, so a misconfigured deployment can never invent
a service identity or a routing destination.

The default profile is the original demo (``demo-api`` with ``healthy-v1`` /
``broken-v2``); existing demo behaviour and contracts are therefore unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

DEMO_SERVICE_ID = "demo-api"
DEMO_HEALTHY_REVISION = "healthy-v1"
DEMO_FAULTY_REVISION = "broken-v2"

STAGING_SERVICE_ID = "tenant-api-staging"
STAGING_HEALTHY_REVISION = "tenant-api-healthy-a6f715a"
STAGING_FAULTY_REVISION = "tenant-api-faulty-a6f715a"


class ProfileError(ValueError):
    """An unknown or malformed service profile was requested."""


@dataclass(frozen=True)
class ServiceProfile:
    """A fixed, closed workload identity and routing set.

    ``revision_targets`` maps a revision to a single fixed destination.  The
    destinations are compose service DNS names, never caller-supplied URLs.
    """

    name: str
    service_id: str
    healthy_revision: str
    faulty_revision: str
    revision_targets: Mapping[str, str]

    def revisions(self) -> tuple[str, ...]:
        return (self.healthy_revision, self.faulty_revision)

    def known_good_revision(self) -> str:
        """The recorded predecessor a recovery is allowed to roll back to."""

        return self.healthy_revision

    def broken_revision(self) -> str:
        return self.faulty_revision

    def target_for(self, revision: str) -> Optional[str]:
        """Fixed destination for a known revision; ``None`` for anything else."""

        return self.revision_targets.get(revision)

    def validate_revision(self, revision: str) -> bool:
        return revision in self.revision_targets

    def __post_init__(self) -> None:
        if not self.name or not self.service_id:
            raise ProfileError("profile name and service_id are required")
        if self.healthy_revision == self.faulty_revision:
            raise ProfileError("healthy and faulty revisions must differ")
        if set(self.revision_targets) != set(self.revisions()):
            raise ProfileError(
                "revision_targets must map exactly the healthy and faulty revisions"
            )
        for revision, target in self.revision_targets.items():
            if not revision or not target:
                raise ProfileError("revision and target must be non-empty")
            if not target.startswith(("http://", "https://")):
                raise ProfileError(f"target for {revision!r} must be an http(s) URL")


DEMO_PROFILE = ServiceProfile(
    name="demo",
    service_id=DEMO_SERVICE_ID,
    healthy_revision=DEMO_HEALTHY_REVISION,
    faulty_revision=DEMO_FAULTY_REVISION,
    revision_targets={
        DEMO_HEALTHY_REVISION: "http://demo-healthy-v1:8000",
        DEMO_FAULTY_REVISION: "http://demo-broken-v2:8000",
    },
)

# Fixed destinations are the compose service names of the two isolated tenant
# API deployments.  The healthy image is the pinned pristine source; the faulty
# image is the same source with an isolated, transparently-labelled patch.
STAGING_PROFILE = ServiceProfile(
    name="staging",
    service_id=STAGING_SERVICE_ID,
    healthy_revision=STAGING_HEALTHY_REVISION,
    faulty_revision=STAGING_FAULTY_REVISION,
    revision_targets={
        # ``api`` is the pinned pristine healthy tenant API; ``tenant-api-faulty``
        # is the same source built with the isolated, labelled fault patch.
        STAGING_HEALTHY_REVISION: "http://api:8080",
        STAGING_FAULTY_REVISION: "http://tenant-api-faulty:8080",
    },
)

_PROFILES: Mapping[str, ServiceProfile] = {
    "demo": DEMO_PROFILE,
    "staging": STAGING_PROFILE,
}


def load_service_profile(env: Optional[Mapping[str, str]] = None) -> ServiceProfile:
    """Select the fixed profile named by ``SERVICE_PROFILE`` (default demo)."""

    import os

    source = os.environ if env is None else env
    raw = str(source.get("SERVICE_PROFILE", "demo") or "demo").strip().lower()
    profile = _PROFILES.get(raw)
    if profile is None:
        raise ProfileError(
            f"unknown SERVICE_PROFILE {raw!r}; expected one of {sorted(_PROFILES)}"
        )
    return profile
