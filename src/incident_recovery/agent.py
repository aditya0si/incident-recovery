"""Bounded, evidence-backed investigation agent.

The agent runs a bounded tool-calling loop against a :class:`ModelAdapter`.  Every
step is persisted (run budget, tool-call count, logical step trace) before the
next one begins, so a worker that crashes and restarts resumes the *same* epoch
with the *same* budget and cannot duplicate a logical step.  All writes are
lease-guarded: a stale owner can never write evidence, a proposal, an escalation,
or a state progression for the current epoch.

The model's diagnosis is never trusted as an authorization.  A deterministic
proposal gate independently requires observed current functional failure,
deployment evidence that matches the authoritative revision/generation, valid
evidence that belongs to this incident and epoch, and a rollback target that is
the recorded known-good predecessor.  Unsupported conclusions, foreign or stale
evidence, prompt injection, malformed provider output, provider unavailability,
and budget exhaustion all escalate instead of silently recovering.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime
from typing import Optional
from uuid import UUID

from .contracts import (
    Diagnosis,
    GateDecision,
    InvestigationContext,
    InvestigationOutcome,
    ToolObservation,
    ToolRequest,
)
from .models import (
    INVESTIGATION_BROKEN_REVISION,
    INVESTIGATION_KNOWN_GOOD_TARGET,
    INVESTIGATION_MAX_SECONDS,
    INVESTIGATION_MAX_TOOL_CALLS,
    RUN_DECIDED,
    RUN_ESCALATED,
    RUN_RUNNING,
    Evidence,
    EvidenceType,
    IllegalStateTransition,
    IncidentState,
    InvestigationRun,
    InvestigationStep,
    LeaseLost,
    ModelProtocolError,
    ModelUnavailable,
    SERVICE_ID,
    utcnow,
)

ALLOWED_TOOLS: tuple[str, ...] = ("health", "logs", "metrics", "deployments")

_INJECTION_MARKERS: tuple[str, ...] = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "ignore the above",
    "disregard previous",
    "disregard all previous",
    "you must approve",
    "approve the rollback",
    "execute the rollback",
    "system:",
    "assistant:",
    "<|",
)


def _has_prompt_injection(payload: dict) -> bool:
    text = json.dumps(payload, default=str).lower()
    return any(marker in text for marker in _INJECTION_MARKERS)


def _is_functional_failure(evidence: Evidence) -> bool:
    if evidence.evidence_type is not EvidenceType.HEALTH:
        return False
    payload = evidence.payload or {}
    if payload.get("functional_ok") is False:
        return True
    status = payload.get("http_status")
    return isinstance(status, int) and status >= 400


def _is_deployment_evidence(evidence: Evidence) -> bool:
    if evidence.evidence_type is not EvidenceType.DEPLOYMENT:
        return False
    payload = evidence.payload or {}
    return "generation" in payload and "current_revision" in payload


def compute_proposal_digest(
    incident_id: UUID, snapshot, target_revision: str, evidence_ids: list[UUID]
) -> str:
    material = json.dumps(
        {
            "incident_id": str(incident_id),
            "service_id": snapshot.service_id,
            "expected_generation": snapshot.generation,
            "current_revision": snapshot.revision,
            "target_revision": target_revision,
            "evidence_ids": sorted(str(eid) for eid in evidence_ids),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def evaluate_diagnosis(
    diagnosis: Diagnosis,
    *,
    incident_id: UUID,
    epoch: int,
    evidence: list[Evidence],
    snapshot,
) -> GateDecision:
    """Deterministic proposal gate; model confidence is irrelevant."""

    same_incident = [e for e in evidence if e.incident_id == incident_id]
    scoped = [e for e in same_incident if e.epoch == epoch]
    scoped_ids = {e.id for e in scoped}
    same_incident_ids = {e.id for e in same_incident}

    if not diagnosis.evidence_ids:
        return GateDecision(False, "insufficient_evidence")
    for evidence_id in diagnosis.evidence_ids:
        if evidence_id in scoped_ids:
            continue
        if evidence_id in same_incident_ids:
            return GateDecision(False, "stale_evidence")
        return GateDecision(False, "foreign_evidence")

    cited = [e for e in scoped if e.id in set(diagnosis.evidence_ids)]
    if any(_has_prompt_injection(e.payload or {}) for e in cited):
        return GateDecision(False, "prompt_injection")
    if not any(_is_functional_failure(e) for e in cited):
        return GateDecision(False, "no_functional_failure")

    deployments = [e for e in cited if _is_deployment_evidence(e)]
    if not deployments:
        return GateDecision(False, "insufficient_evidence")
    deployment = deployments[-1]
    payload = deployment.payload or {}
    if (
        payload.get("generation") != snapshot.generation
        or payload.get("current_revision") != snapshot.revision
    ):
        return GateDecision(False, "stale_deployment_evidence")

    if not diagnosis.proposed_rollback:
        return GateDecision(False, "no_recovery_proposed")
    if (
        snapshot.revision != INVESTIGATION_BROKEN_REVISION
        or snapshot.predecessor != INVESTIGATION_KNOWN_GOOD_TARGET
    ):
        return GateDecision(False, "not_known_good_predecessor")

    target = snapshot.predecessor
    digest = compute_proposal_digest(incident_id, snapshot, target, diagnosis.evidence_ids)
    return GateDecision(True, "proposed", target, digest)


class InvestigationAgent:
    def __init__(
        self,
        repo,
        tools,
        adapter,
        worker_id: str,
        *,
        clock=utcnow,
        sleep=None,
        max_tool_calls: int = INVESTIGATION_MAX_TOOL_CALLS,
        max_seconds: float = INVESTIGATION_MAX_SECONDS,
        provider_timeout: float = 20.0,
        lease_seconds: int = 180,
    ) -> None:
        self._repo = repo
        self._tools = tools
        self._adapter = adapter
        self._worker_id = worker_id
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        # Server-enforced maxima: configured values may be lower but never higher.
        self._max_tool_calls = min(int(max_tool_calls), INVESTIGATION_MAX_TOOL_CALLS)
        self._max_seconds = min(float(max_seconds), INVESTIGATION_MAX_SECONDS)
        self._provider_timeout = provider_timeout
        self._lease_seconds = lease_seconds

    async def aclose(self) -> None:
        for component in (self._tools, self._adapter):
            closer = getattr(component, "aclose", None)
            if closer is not None:
                await closer()

    async def investigate(self, incident) -> InvestigationOutcome:
        incident_id = incident.id
        now = self._clock()
        run = await self._repo.ensure_investigation_run(
            incident_id, self._adapter.identity, self._max_seconds, now=now
        )
        steps = await self._repo.list_investigation_steps(incident_id, run.epoch)
        if not any(step.kind == "run_started" for step in steps):
            try:
                await self._repo.record_investigation_step(
                    incident_id, run.epoch, "run_started", {"adapter": run.adapter},
                    worker_id=self._worker_id, now=now,
                )
            except LeaseLost:
                return InvestigationOutcome("aborted", "lease_lost", run.epoch)

        if run.state != RUN_RUNNING:
            status = "awaiting_approval" if run.state == RUN_DECIDED else "escalated"
            return InvestigationOutcome(status, run.state, run.epoch)

        pending = self._pending_tool_request(steps)
        while True:
            now = self._clock()
            remaining = (run.deadline_at - now).total_seconds()
            if remaining <= 0 or run.tool_calls >= self._max_tool_calls:
                return await self._escalate(incident_id, run, "budget_exhausted")

            if pending is None:
                context = await self._build_context(incident_id, run, remaining)
                try:
                    step = await asyncio.wait_for(
                        self._adapter.next_step(context),
                        timeout=max(0.001, min(self._provider_timeout, remaining)),
                    )
                except asyncio.TimeoutError:
                    return await self._escalate(incident_id, run, "provider_timeout")
                except LeaseLost:
                    return InvestigationOutcome("aborted", "lease_lost", run.epoch)
                except ModelUnavailable:
                    return await self._escalate(incident_id, run, "model_unavailable")
                except ModelProtocolError:
                    return await self._escalate(incident_id, run, "invalid_provider_json")

                if isinstance(step, ToolRequest):
                    try:
                        await self._repo.record_investigation_step(
                            incident_id, run.epoch, "tool_request",
                            {"tool": step.tool, "reason": step.reason, "lines": step.lines},
                            worker_id=self._worker_id, now=self._clock(),
                        )
                    except LeaseLost:
                        return InvestigationOutcome("aborted", "lease_lost", run.epoch)
                    pending = step
                    continue
                if isinstance(step, Diagnosis):
                    try:
                        await self._repo.record_investigation_step(
                            incident_id, run.epoch, "diagnosis",
                            step.model_dump(mode="json"),
                            worker_id=self._worker_id, now=self._clock(),
                        )
                    except LeaseLost:
                        return InvestigationOutcome("aborted", "lease_lost", run.epoch)
                    return await self._decide(incident_id, run, step)
                return await self._escalate(incident_id, run, "invalid_provider_json")

            try:
                evidence = await self._tools.collect(
                    pending, incident_id, run.epoch,
                    worker_id=self._worker_id, now=self._clock(),
                )
            except LeaseLost:
                return InvestigationOutcome("aborted", "lease_lost", run.epoch)
            except ModelUnavailable:
                return await self._escalate(incident_id, run, "tool_unavailable")
            except Exception:  # noqa: BLE001 - a failed observation escalates, never recovers
                return await self._escalate(incident_id, run, "tool_failure")

            try:
                await self._repo.record_investigation_step(
                    incident_id, run.epoch, "tool_result",
                    {"tool": pending.tool, "evidence_id": str(evidence.id)},
                    worker_id=self._worker_id, now=self._clock(), advance_tool_calls=True,
                )
            except LeaseLost:
                return InvestigationOutcome("aborted", "lease_lost", run.epoch)
            pending = None
            refreshed = await self._repo.get_investigation_run(incident_id, run.epoch)
            if refreshed is not None:
                run = refreshed

    def _pending_tool_request(self, steps: list[InvestigationStep]) -> Optional[ToolRequest]:
        pending: Optional[ToolRequest] = None
        for step in steps:
            if step.kind == "tool_request":
                payload = step.payload or {}
                pending = ToolRequest(
                    tool=payload["tool"],
                    reason=payload.get("reason", ""),
                    lines=payload.get("lines"),
                )
            elif step.kind in ("tool_result", "diagnosis", "decision", "escalation"):
                pending = None
        return pending

    async def _build_context(
        self, incident_id: UUID, run: InvestigationRun, remaining: float
    ) -> InvestigationContext:
        evidence = await self._repo.list_evidence(incident_id, epoch=run.epoch)
        observations = [
            ToolObservation(
                evidence_id=e.id,
                tool=e.source.split(":", 1)[-1],
                observed_at=e.observed_at,
                summary=e.payload,
            )
            for e in evidence
        ]
        steps = await self._repo.list_investigation_steps(incident_id, run.epoch)
        return InvestigationContext(
            incident_id=incident_id,
            service_id=SERVICE_ID,
            epoch=run.epoch,
            step=len(steps),
            tool_calls_used=run.tool_calls,
            max_tool_calls=self._max_tool_calls,
            seconds_remaining=max(0.0, remaining),
            observations=observations,
            adapter_identity=run.adapter,
        )

    async def _decide(
        self, incident_id: UUID, run: InvestigationRun, diagnosis: Diagnosis
    ) -> InvestigationOutcome:
        snapshot = await self._repo.get_deployment_snapshot()
        evidence = await self._repo.list_evidence(incident_id)
        decision = evaluate_diagnosis(
            diagnosis,
            incident_id=incident_id,
            epoch=run.epoch,
            evidence=evidence,
            snapshot=snapshot,
        )
        if not decision.allowed:
            try:
                await self._repo.record_investigation_step(
                    incident_id, run.epoch, "decision",
                    {"allowed": False, "reason": decision.reason},
                    worker_id=self._worker_id, now=self._clock(),
                )
            except LeaseLost:
                return InvestigationOutcome("aborted", "lease_lost", run.epoch)
            return await self._escalate(incident_id, run, decision.reason)

        try:
            proposal = await self._repo.create_investigation_proposal(
                incident_id,
                run.epoch,
                service_id=snapshot.service_id,
                expected_generation=snapshot.generation,
                current_revision=snapshot.revision,
                target_revision=decision.target_revision,
                evidence_ids=diagnosis.evidence_ids,
                digest=decision.digest,
                worker_id=self._worker_id,
                now=self._clock(),
            )
        except LeaseLost:
            return InvestigationOutcome("aborted", "lease_lost", run.epoch)
        except IllegalStateTransition:
            return InvestigationOutcome("aborted", "state_changed", run.epoch)

        try:
            await self._repo.record_investigation_step(
                incident_id, run.epoch, "decision",
                {
                    "allowed": True,
                    "proposal_id": str(proposal.id),
                    "digest": decision.digest,
                    "target_revision": decision.target_revision,
                },
                worker_id=self._worker_id, now=self._clock(),
            )
            await self._repo.commit_under_lease(
                incident_id,
                self._worker_id,
                IncidentState.AWAITING_APPROVAL,
                lease_seconds=self._lease_seconds,
                event_payload={"proposal_id": str(proposal.id), "digest": decision.digest},
                now=self._clock(),
            )
            # Hand the incident off cleanly: an awaiting_approval incident must
            # not keep a live investigation lease, or the recovery worker could
            # be blocked from claiming it once the operator approves.
            await self._repo.release_lease(incident_id, self._worker_id)
        except LeaseLost:
            return InvestigationOutcome("aborted", "lease_lost", run.epoch)
        await self._repo.set_investigation_run_state(
            incident_id, run.epoch, RUN_DECIDED, now=self._clock()
        )
        return InvestigationOutcome("awaiting_approval", "proposed", run.epoch, proposal.id)

    async def _escalate(
        self, incident_id: UUID, run: InvestigationRun, reason: str
    ) -> InvestigationOutcome:
        try:
            await self._repo.record_investigation_step(
                incident_id, run.epoch, "escalation", {"reason": reason},
                worker_id=self._worker_id, now=self._clock(),
            )
        except LeaseLost:
            return InvestigationOutcome("aborted", "lease_lost", run.epoch)
        await self._repo.set_investigation_run_state(
            incident_id, run.epoch, RUN_ESCALATED, last_error=reason, now=self._clock()
        )
        try:
            await self._repo.escalate_investigation(
                incident_id, self._worker_id, reason=reason, now=self._clock(), epoch=run.epoch
            )
        except LeaseLost:
            return InvestigationOutcome("aborted", "lease_lost", run.epoch)
        except IllegalStateTransition:
            return InvestigationOutcome("aborted", "state_changed", run.epoch)
        return InvestigationOutcome("escalated", reason, run.epoch)
