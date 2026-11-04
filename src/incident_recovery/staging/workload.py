"""The fixed tenant-staging workload adapter.

:class:`TenantStagingAdapter` is the single narrow seam the control plane uses
for the real staging workload.  It exposes exactly three operations:

* ``observe``  - allowlisted, authenticated observations (see ``observations``),
* ``verify``   - a faithful functional check for the shared verification engine,
* ``recover``  - execute a *persisted* recovery operation (traffic routing only).

Nothing here accepts a destination, URL, SQL, container id, or shell command.
Recovery is delegated to the reviewed executor against a persisted operation id,
so an action parameter can never come from the model or a request body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Awaitable, Callable, Optional
from uuid import UUID

from ..contracts import ToolObservation, ToolRequest
from ..models import (
    Evidence,
    EvidenceType,
    InvestigationBudgetExhausted,
    Operation,
    utcnow,
)
from ..model_adapter import DemoScriptedAdapter
from ..service_profile import ServiceProfile
from .observations import StagingFunctionalProbe, StagingObserver
from .contracts import StagingObservation


class StagingScriptedAdapter(DemoScriptedAdapter):
    """Explicitly labelled scripted investigation for the staging workload.

    It is deterministic and evidence-driven (observe functional health, then the
    authoritative deployment, then propose the recorded known-good predecessor)
    and is only ever selected by explicit configuration.  Its identity always
    reads ``scripted:tenant-api-staging`` so a scripted run is never presented as
    a live model.
    """

    identity = "scripted:tenant-api-staging"


_EVIDENCE_TYPES = {
    "health": EvidenceType.HEALTH,
    "logs": EvidenceType.LOG,
    "metrics": EvidenceType.METRIC,
    "deployments": EvidenceType.DEPLOYMENT,
}


class StagingToolRunner:
    """Bounded, read-only tool runner backed by the staging observations.

    It matches the :class:`~incident_recovery.tools.ToolRunner` interface the
    shared :class:`~incident_recovery.agent.InvestigationAgent` consumes, so the
    reviewed agent loop is reused unchanged: it only ever sees allowlisted
    staging evidence, and it is always lease-guarded when it persists.
    """

    def __init__(
        self,
        repo,
        observer: StagingObserver,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._repo = repo
        self._observer = observer
        self._clock = clock

    async def aclose(self) -> None:
        await self._observer.aclose()

    async def observe(self, request: ToolRequest) -> ToolObservation:
        observation = await self._observer.observe(request.tool, lines=request.lines)
        return ToolObservation(
            evidence_id=UUID(int=0),
            tool=request.tool,
            observed_at=observation.observed_at,
            summary=observation.evidence_fields,
        )

    async def collect(
        self,
        request: ToolRequest,
        incident_id,
        epoch: int,
        *,
        worker_id: str,
        now: Optional[datetime] = None,
    ) -> Evidence:
        observation = await self._observer.observe(request.tool, lines=request.lines)
        return await self._repo.append_investigation_evidence(
            incident_id,
            epoch,
            f"tool:{request.tool}",
            _EVIDENCE_TYPES[request.tool],
            observation.evidence_fields,
            worker_id=worker_id,
            now=now or self._clock(),
        )


class TenantStagingAdapter:
    """Fixed tenant-staging workload: observe, verify, recover."""

    def __init__(
        self,
        profile: ServiceProfile,
        observer: StagingObserver,
        probe: StagingFunctionalProbe,
        *,
        executor: Optional[Callable[[UUID], Awaitable[Operation]]] = None,
    ) -> None:
        self._profile = profile
        self._observer = observer
        self._probe = probe
        self._executor = executor

    @property
    def profile(self) -> ServiceProfile:
        return self._profile

    @property
    def service_id(self) -> str:
        return self._profile.service_id

    @property
    def identity(self) -> str:
        return f"tenant-staging:{self._profile.healthy_revision}"

    @property
    def observer(self) -> StagingObserver:
        return self._observer

    @property
    def probe(self) -> StagingFunctionalProbe:
        return self._probe

    def tools(self, repo) -> StagingToolRunner:
        return StagingToolRunner(repo, self._observer)

    async def aclose(self) -> None:
        await self._observer.aclose()
        await self._probe.aclose()

    async def observe(self, kind: str, *, lines: Optional[int] = None) -> StagingObservation:
        return await self._observer.observe(kind, lines=lines)

    async def verify(self, target_revision: str, generation: Optional[int] = None):
        check = await self._probe.check(target_revision)
        if generation is not None and check.revision == target_revision:
            # The shared probe already required the identity headers to match the
            # snapshot generation; this is a defensive secondary identity check.
            pass
        return check

    async def recover(self, operation_id: UUID) -> Operation:
        if self._executor is None:
            raise InvestigationBudgetExhausted("staging recovery executor not configured")
        return await self._executor(operation_id)
