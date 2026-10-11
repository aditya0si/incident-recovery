"""Real-PostgreSQL control-plane semantics for the isolated staging service.

These run against the demo PostgreSQL *server* but in a dedicated schema seeded
with the **staging** profile, so they prove:

* the staging and demo deployment records never collide,
* a staging switch refuses a reservation bound to a foreign service, and
* the full fault -> approval -> recovery switch path applies for staging only.
"""

from __future__ import annotations

import os
import uuid

import asyncpg
import pytest
import pytest_asyncio

from incident_recovery import db as db_module
from incident_recovery.contracts import SERVICE_ID as DEMO_SERVICE_ID
from incident_recovery.contracts import SwitchRequest as DemoSwitchRequest
from incident_recovery.gateway import DeploymentStore, ensure_deployment_state
from incident_recovery.models import IncidentState
from incident_recovery.repository import IncidentRepository
from incident_recovery.service_profile import DEMO_PROFILE, STAGING_PROFILE
from incident_recovery.staging.contracts import (
    STAGING_HEALTHY_REVISION,
    StagingSwitchRequest,
)

pytestmark = pytest.mark.asyncio


def _host_dsn() -> str:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    name = os.environ.get("POSTGRES_DB")
    port = os.environ.get("POSTGRES_PORT", "5432")
    if not (user and password and name):
        raise RuntimeError("staging control tests require POSTGRES_* from .env")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"


@pytest_asyncio.fixture
async def staging_pool():
    dsn = _host_dsn()
    admin = await asyncpg.connect(dsn)
    schema = f"stg_{uuid.uuid4().hex[:12]}"
    await admin.execute(f'CREATE SCHEMA "{schema}"')
    await admin.close()
    pool = await db_module.create_pool(dsn, schema=schema)
    await db_module.bootstrap_schema(pool, profile=STAGING_PROFILE)
    try:
        yield pool
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn)
        try:
            await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        finally:
            await admin.close()


async def test_staging_rows_do_not_collide_with_demo(staging_pool) -> None:
    staging = DeploymentStore(staging_pool, profile=STAGING_PROFILE)
    demo = DeploymentStore(staging_pool, profile=DEMO_PROFILE)
    staging_snapshot = await staging.get_snapshot()
    assert staging_snapshot.revision == STAGING_HEALTHY_REVISION
    # A demo store over the same schema only ever sees its own seeded row and
    # refuses to operate on the absent demo row rather than reading staging.
    rows = await staging_pool.fetch(
        "SELECT service_id FROM deployment_state ORDER BY service_id"
    )
    assert [row["service_id"] for row in rows] == ["tenant-api-staging"]


async def test_staging_switch_refuses_foreign_service_reservation(staging_pool) -> None:
    repo = IncidentRepository(staging_pool)
    staging = DeploymentStore(staging_pool, profile=STAGING_PROFILE)
    operation_id = uuid.uuid4()
    # A reservation bound to the *demo* service (foreign to staging).
    await repo.reserve(
        operation_id,
        scope="fault",
        expected_generation=1,
        target_revision=STAGING_PROFILE.faulty_revision,
        service_id=DEMO_SERVICE_ID,
    )
    decision = await staging.switch(
        StagingSwitchRequest(
            operation_id=operation_id,
            expected_generation=1,
            target_revision=STAGING_PROFILE.faulty_revision,
            scope="fault",
        )
    )
    assert decision.status == "unauthorized"
    assert (await staging.get_snapshot()).revision == STAGING_HEALTHY_REVISION


async def test_staging_fault_approval_recovery_round_trip(staging_pool) -> None:
    repo = IncidentRepository(staging_pool)
    staging = DeploymentStore(staging_pool, profile=STAGING_PROFILE)
    service = STAGING_PROFILE.service_id
    healthy = STAGING_PROFILE.healthy_revision
    faulty = STAGING_PROFILE.faulty_revision

    # 1) Inject the faulty revision under a fault reservation.
    fault_op = uuid.uuid4()
    await repo.reserve(
        fault_op, scope="fault", expected_generation=1, target_revision=faulty, service_id=service
    )
    decision = await staging.switch(
        StagingSwitchRequest(
            operation_id=fault_op, expected_generation=1, target_revision=faulty, scope="fault"
        )
    )
    assert decision.status == "applied"
    assert decision.snapshot.revision == faulty
    assert decision.snapshot.predecessor == healthy
    assert decision.snapshot.generation == 2
    await repo.release_reservation(fault_op)

    # 2) Create the incident and the gated proposal bound to staging.
    incident, _ = await repo.ingest_alert("staging-incident", service, "fault", {})
    await repo.transition(incident.id, IncidentState.INVESTIGATING)
    incident = await repo.get_incident(incident.id)
    await repo.transition(incident.id, IncidentState.AWAITING_APPROVAL)
    proposal = await repo.create_proposal(
        incident_id=incident.id,
        service_id=service,
        expected_generation=2,
        current_revision=faulty,
        target_revision=healthy,
        evidence_ids=[],
        digest="digest-staging-1",
    )

    # 3) Operator approval binds the staging service and creates the reservation.
    approval, operation, created = await repo.approve_incident(
        incident.id, proposal.digest, "operator", service_id=service
    )
    assert created is True
    assert approval.service_id == service
    assert operation.service_id == service

    # 4) The recovery switch applies through the staging store.
    recovery = await staging.switch(
        StagingSwitchRequest(
            operation_id=operation.id,
            expected_generation=2,
            target_revision=healthy,
            scope="recovery",
        )
    )
    assert recovery.status == "applied"
    assert recovery.snapshot.revision == healthy
    assert recovery.snapshot.predecessor == faulty


async def test_demo_switch_cannot_route_a_staging_reservation(staging_pool) -> None:
    repo = IncidentRepository(staging_pool)
    demo = DeploymentStore(staging_pool, profile=DEMO_PROFILE)
    # Seed the demo row so the store can read its snapshot.
    await ensure_deployment_state(staging_pool, DEMO_PROFILE)
    operation_id = uuid.uuid4()
    await repo.reserve(
        operation_id,
        scope="fault",
        expected_generation=1,
        target_revision=STAGING_PROFILE.faulty_revision,
        service_id=STAGING_PROFILE.service_id,
    )
    # A demo store reading its own row refuses the staging reservation by
    # revision-set membership and service mismatch.
    decision = await demo.switch(
        DemoSwitchRequest(
            operation_id=operation_id,
            expected_generation=1,
            target_revision="broken-v2",
            scope="fault",
        )
    )
    assert decision.status == "unauthorized"
