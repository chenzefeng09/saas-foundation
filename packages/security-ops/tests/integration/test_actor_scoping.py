"""X-Actor end to end: security-ops data is platform-scoped, so RLS admits only the
ADMIN / SYSTEM / SERVICE actors, whatever tenant or user the request carries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select

from foundation_security_ops.domain.models import Incident, SbomWatch, ScanRun
from tests.integration._support import as_actor

pytestmark = pytest.mark.integration

TENANT = "tnt_01J00000000000000000000001"
LISTS = ("/scans/runs", "/vulnerabilities", "/incidents", "/drills")


async def _seed(client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    for resp in (
        await client.post(
            "/scans/runs",
            json={
                "type": "sca",
                "tool": "trivy",
                "target": "image:identity",
                "started_at": now.isoformat(),
                "status": "failed",
                "findings_count": {"critical": 1},
            },
        ),
        await client.post(
            "/incidents", json={"severity": "low", "category": "other", "title": "seed"}
        ),
        await client.post(
            "/drills",
            json={"kind": "tabletop", "scheduled_at": (now + timedelta(days=1)).isoformat()},
        ),
        await client.post("/sbom/watch", json={"image_ref": "registry.example.com/seed:1"}),
    ):
        assert resp.status_code == 201, resp.text


@pytest.mark.parametrize("actor", ["ADMIN", "SYSTEM", "SERVICE"])
async def test_platform_actors_see_platform_rows(client: httpx.AsyncClient, actor: str) -> None:
    await _seed(client)
    for path in LISTS:
        resp = await client.get(path, headers={"X-Actor": actor, "X-Tenant-Id": TENANT})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1, path
    watches = await client.get("/sbom/watch", headers={"X-Actor": actor})
    assert len(watches.json()) == 1


@pytest.mark.parametrize("actor", ["USER", "MIGRATOR"])
async def test_other_actors_see_nothing(client: httpx.AsyncClient, actor: str) -> None:
    await _seed(client)
    headers = {
        "X-Actor": actor,
        "X-Tenant-Id": TENANT,
        "X-User-Id": "usr_01J0000000000000000000USR1",
    }
    for path in LISTS:
        resp = await client.get(path, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["items"] == [], path
    assert (await client.get("/sbom/watch", headers=headers)).json() == []
    dashboard = (await client.get("/vulnerabilities/sla-dashboard", headers=headers)).json()
    assert dashboard == {"overdue_by_severity": {}, "by_owner": {}, "mttr_days": {}}

    async with as_actor("SERVICE") as session:
        inc_id = (await session.scalars(select(Incident.id))).one()
    resp = await client.get(f"/incidents/{inc_id}", headers=headers)
    assert resp.status_code == 404


@pytest.mark.parametrize("actor", ["USER", "MIGRATOR"])
async def test_other_actors_cannot_write(client: httpx.AsyncClient, actor: str) -> None:
    writes = (
        ("/incidents", {"severity": "high", "category": "insider", "title": "x"}),
        (
            "/scans/runs",
            {
                "type": "sast",
                "tool": "semgrep",
                "target": "repo:x",
                "started_at": datetime.now(UTC).isoformat(),
                "status": "passed",
            },
        ),
        ("/sbom/watch", {"image_ref": "registry.example.com/x:1"}),
    )
    for path, body in writes:
        resp = await client.post(path, json=body, headers={"X-Actor": actor})
        # Rejected by the WITH CHECK clause of the RLS policy.
        assert not resp.is_success, (path, resp.text)

    async with as_actor("SERVICE") as session:
        for model in (Incident, ScanRun, SbomWatch):
            count = (await session.execute(select(func.count()).select_from(model))).scalar_one()
            assert count == 0, model.__name__


async def test_other_actor_cannot_modify_platform_rows(client: httpx.AsyncClient) -> None:
    await _seed(client)
    async with as_actor("SERVICE") as session:
        inc_id = (await session.scalars(select(Incident.id))).one()

    resp = await client.patch(
        f"/incidents/{inc_id}", json={"status": "resolved"}, headers={"X-Actor": "USER"}
    )
    assert resp.status_code == 404
    stored = (await client.get(f"/incidents/{inc_id}")).json()
    assert stored["status"] == "DETECTED"


@pytest.mark.parametrize("actor", ["ROOT", "admin", "Service", "ADMIN,SERVICE", ""])
async def test_unknown_actor_is_rejected(client: httpx.AsyncClient, actor: str) -> None:
    resp = await client.get("/incidents", headers={"X-Actor": actor})
    assert resp.status_code == 400
    assert resp.json()["code"] == "FOUNDATION.SECURITY_OPS.INPUT.INVALID_FORMAT"
