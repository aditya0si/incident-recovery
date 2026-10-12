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


def _evidence(incident_id, *, kind: EvidenceType, payload: dict, epoch: int = 1, observed_at=NOW) -> Evidence:
    return Evidence(
        id=uuid4(),
        incident_id=incident_id,
        source="tool:health" if kind is EvidenceType.HEALTH else "tool:deployments",
        evidence_type=kind,
        observed_at=observed_at,
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


# --- dependency veto is independent of the model's citations -------------------


def _health(incident_id, *, deps_ok, observed_at=NOW, functional_ok=False):
    return _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={
            "functional_ok": functional_ok,
            "http_status": 500,
            "dependencies_ok": deps_ok,
        },
        observed_at=observed_at,
    )


def test_uncited_later_dependency_outage_vetoes_a_cited_healthy_sample() -> None:
    """The model cites an earlier healthy sample and omits a later outage.

    The gate considers the whole current epoch, so the newer outage still vetoes
    and no proposal target is ever returned.
    """

    incident_id = uuid4()
    earlier = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    later = datetime(2026, 10, 12, 12, 5, 0, tzinfo=timezone.utc)
    healthy_sample = _health(incident_id, deps_ok=True, observed_at=earlier)
    outage = _health(incident_id, deps_ok=False, observed_at=later)
    deployment = _deployment_evidence(incident_id)
    # The model only cites the earlier healthy sample + the deployment.
    decision = evaluate_diagnosis(
        _diagnosis([healthy_sample.id, deployment.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[healthy_sample, outage, deployment],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason in ("dependencies_unhealthy", "dependencies_contradictory")
    assert getattr(decision, "target_revision", None) is None


def test_contradictory_dependency_evidence_fails_closed() -> None:
    incident_id = uuid4()
    healthy = _health(incident_id, deps_ok=True)
    outage = _health(incident_id, deps_ok=False)
    deployment = _deployment_evidence(incident_id)
    decision = evaluate_diagnosis(
        _diagnosis([healthy.id, outage.id, deployment.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[healthy, outage, deployment],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
    )
    assert decision.allowed is False
    assert decision.reason == "dependencies_contradictory"


def test_dependency_veto_is_order_independent() -> None:
    incident_id = uuid4()
    healthy_sample = _health(incident_id, deps_ok=True, observed_at=datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc))
    outage = _health(incident_id, deps_ok=False, observed_at=datetime(2026, 10, 12, 12, 5, tzinfo=timezone.utc))
    deployment = _deployment_evidence(incident_id)
    for ordering in (
        [healthy_sample, outage, deployment],
        [deployment, outage, healthy_sample],
        [outage, healthy_sample, deployment],
    ):
        decision = evaluate_diagnosis(
            _diagnosis([healthy_sample.id, deployment.id]),
            incident_id=incident_id,
            epoch=1,
            evidence=ordering,
            snapshot=_snapshot(),
            known_good_revision=HEALTHY,
            broken_revision=FAULTY,
        )
        assert decision.allowed is False, ordering


def test_missing_dependency_attestation_fails_closed_when_required() -> None:
    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500},
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
        require_dependency_health=True,
    )
    assert decision.allowed is False
    assert decision.reason == "dependency_evidence_missing"


def test_missing_dependency_attestation_is_ignored_for_the_demo_default() -> None:
    incident_id = uuid4()
    health = _evidence(
        incident_id,
        kind=EvidenceType.HEALTH,
        payload={"functional_ok": False, "http_status": 500},
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


def test_healthy_dependency_control_still_admits() -> None:
    incident_id = uuid4()
    health = _health(incident_id, deps_ok=True)
    deployment = _deployment_evidence(incident_id)
    decision = evaluate_diagnosis(
        _diagnosis([health.id, deployment.id]),
        incident_id=incident_id,
        epoch=1,
        evidence=[health, deployment],
        snapshot=_snapshot(),
        known_good_revision=HEALTHY,
        broken_revision=FAULTY,
        require_dependency_health=True,
    )
    assert decision.allowed is True
    assert decision.target_revision == HEALTHY
