"""The deterministic proposal gate refuses dependency-outage rollbacks.

A dependency outage is not a deployment regression: the gate must escalate
rather than admit a rollback, regardless of model confidence.  These tests
exercise the shared gate with staging-shaped evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from incident_recovery.agent import evaluate_diagnosis
from incident_recovery.contracts import DeploymentSnapshot, Diagnosis
from incident_recovery.models import Evidence, EvidenceType
from incident_recovery.service_profile import STAGING_PROFILE

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
HEALTHY = STAGING_PROFILE.healthy_revision
FAULTY = STAGING_PROFILE.faulty_revision


def _snapshot() -> DeploymentSnapshot:
    return DeploymentSnapshot(
        service_id=STAGING_PROFILE.service_id,
        revision=FAULTY,
        generation=2,
        activated_at=NOW,
        predecessor=HEALTHY,
    )


def _evidence(incident_id, *, kind: EvidenceType, payload: dict, epoch: int = 1) -> Evidence:
    return Evidence(
        id=uuid4(),
        incident_id=incident_id,
        source="tool:health" if kind is EvidenceType.HEALTH else "tool:deployments",
        evidence_type=kind,
        observed_at=NOW,
        payload=payload,
        epoch=epoch,
    )


def _deployment_evidence(incident_id, epoch: int = 1) -> Evidence:
    return _evidence(
        incident_id,
        kind=EvidenceType.DEPLOYMENT,
        payload={
            "tool": "deployments",
            "service_id": STAGING_PROFILE.service_id,
            "current_revision": FAULTY,
            "generation": 2,
            "predecessor": HEALTHY,
        },
        epoch=epoch,
    )


def _diagnosis(evidence_ids) -> Diagnosis:
    return Diagnosis(
        symptoms=["tenant business request failed"],
        candidate_cause="faulty revision is functionally failing",
        uncertainty="low",
        evidence_ids=list(evidence_ids),
        proposed_rollback=True,
    )


def test_dependency_outage_is_refused_even_with_functional_failure() -> None:
    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500, "dependencies_ok": False},
    )
    deployment = _deployment_evidence(incident_id)
    decision = evaluate_diagnosis(
        _diagnosis([health.id, deployment.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, deployment],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason == "dependencies_unhealthy"


def test_functional_failure_with_healthy_dependencies_is_admitted() -> None:
    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500, "dependencies_ok": True},
    )
    deployment = _deployment_evidence(incident_id)
    decision = evaluate_diagnosis(
        _diagnosis([health.id, deployment.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, deployment],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is True
    assert decision.target_revision == HEALTHY


def test_foreign_evidence_is_refused() -> None:
    incident_id = uuid4()
    other = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500, "dependencies_ok": True},
    )
    foreign = _deployment_evidence(other)
    decision = evaluate_diagnosis(
        _diagnosis([health.id, foreign.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, foreign],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason == "foreign_evidence"


def test_stale_deployment_evidence_is_refused() -> None:
    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500, "dependencies_ok": True},
    )
    stale = _evidence(
        incident_id,
        kind=EvidenceType.DEPLOYMENT,
        payload={"current_revision": HEALTHY, "generation": 1},
    )
    decision = evaluate_diagnosis(
        _diagnosis([health.id, stale.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, stale],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason == "stale_deployment_evidence"


def test_dependency_outage_with_stale_generation_never_admits_a_rollback() -> None:
    """A dependency outage must win over any deployment-generation race.

    Even when the deployment observation is stale/contradictory, a real
    dependency failure is non-repairable by a rollback: the gate refuses with the
    dependency reason and never falls through to an executable rollback.
    """

    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500, "dependencies_ok": False},
    )
    stale = _evidence(
        incident_id,
        kind=EvidenceType.DEPLOYMENT,
        payload={"current_revision": HEALTHY, "generation": 1},
    )
    decision = evaluate_diagnosis(
        _diagnosis([health.id, stale.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, stale],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason == "dependencies_unhealthy"
    assert getattr(decision, "target_revision", None) is None
