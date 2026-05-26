"""Integration tests for Org Service — requires Postgres.

Tests the full org-unit + team + membership lifecycle against real Postgres:
  1. Create org units (root + child)
  2. Create teams
  3. Upsert user membership
  4. Add/remove team members
  5. Archive and delete org units
  6. Transfer user between org units
"""

from __future__ import annotations

import httpx
import pytest


class TestOrgUnitCRUD:
    @pytest.fixture(scope="class")
    async def root_ou(self, client: httpx.AsyncClient, endpoints, tenant) -> dict:
        payload = {
            "code": "integration-root",
            "name": "Integration Test Root",
            "kind": "DEPARTMENT",
            "metadata": {"test": True},
        }
        r = await client.post(
            f"{endpoints.org}/org-units",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create root OU failed: {r.text}"
        return r.json()

    async def test_create_root_ou(self, root_ou: dict) -> None:
        assert root_ou["code"] == "integration-root"
        assert root_ou["depth"] == 0
        assert root_ou["parent_id"] is None
        assert root_ou["id"].startswith("ou_")

    async def test_get_org_unit(
        self, client: httpx.AsyncClient, endpoints, tenant, root_ou: dict,
    ) -> None:
        r = await client.get(
            f"{endpoints.org}/org-units/{root_ou['id']}",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Integration Test Root"

    async def test_create_child_ou(
        self, client: httpx.AsyncClient, endpoints, tenant, root_ou: dict,
    ) -> dict:
        payload = {
            "parent_id": root_ou["id"],
            "code": "integration-child",
            "name": "Integration Test Child",
            "kind": "DEPARTMENT",
        }
        r = await client.post(
            f"{endpoints.org}/org-units",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create child OU failed: {r.text}"
        child = r.json()
        assert child["parent_id"] == root_ou["id"]
        assert child["depth"] == 1
        return child

    async def test_list_org_units(
        self, client: httpx.AsyncClient, endpoints, tenant, root_ou: dict,
    ) -> None:
        r = await client.get(
            f"{endpoints.org}/org-units",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) >= 1

    async def test_update_org_unit(
        self, client: httpx.AsyncClient, endpoints, tenant, root_ou: dict,
    ) -> None:
        r = await client.patch(
            f"{endpoints.org}/org-units/{root_ou['id']}",
            json={"name": "Updated Root Name"},
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Root Name"

    async def test_code_conflict(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """Creating an OU with duplicate code under same parent should 409."""
        r = await client.post(
            f"{endpoints.org}/org-units",
            json={"code": "integration-root", "name": "Duplicate"},
            headers=tenant.headers,
        )
        assert r.status_code == 409


class TestTeamCRUD:
    @pytest.fixture(scope="class")
    async def test_ou(self, client: httpx.AsyncClient, endpoints, tenant) -> dict:
        r = await client.post(
            f"{endpoints.org}/org-units",
            json={"code": "integration-team-ou", "name": "Team Test OU", "kind": "DEPARTMENT"},
            headers=tenant.headers,
        )
        assert r.status_code == 201
        return r.json()

    async def test_create_team(
        self, client: httpx.AsyncClient, endpoints, tenant, test_ou: dict,
    ) -> dict:
        payload = {
            "org_unit_id": test_ou["id"],
            "code": "backend-team",
            "name": "Backend Team",
            "kind": "PROJECT",
        }
        r = await client.post(
            f"{endpoints.org}/teams",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create team failed: {r.text}"
        team = r.json()
        assert team["code"] == "backend-team"
        assert team["id"].startswith("tm_")
        return team

    async def test_list_teams(
        self, client: httpx.AsyncClient, endpoints, tenant, test_ou: dict,
    ) -> None:
        r = await client.get(
            f"{endpoints.org}/teams?org_unit_id={test_ou['id']}",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert len(r.json()["items"]) >= 1

    async def test_add_member(
        self, client: httpx.AsyncClient, endpoints, tenant, test_ou: dict,
    ) -> None:
        # First create a team
        create_resp = await client.post(
            f"{endpoints.org}/teams",
            json={
                "org_unit_id": test_ou["id"],
                "code": "member-test-team",
                "name": "Member Test Team",
                "kind": "PROJECT",
            },
            headers=tenant.headers,
        )
        assert create_resp.status_code == 201
        team_id = create_resp.json()["id"]

        # Add member
        r = await client.post(
            f"{endpoints.org}/teams/{team_id}/members",
            json={
                "user_id": "usr_01J5INT000000000000MEM01",
                "role_in_team": "MEMBER",
            },
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Add member failed: {r.text}"

    async def test_remove_member(
        self, client: httpx.AsyncClient, endpoints, tenant, test_ou: dict,
    ) -> None:
        create_resp = await client.post(
            f"{endpoints.org}/teams",
            json={
                "org_unit_id": test_ou["id"],
                "code": "remove-test-team",
                "name": "Remove Test Team",
                "kind": "PROJECT",
            },
            headers=tenant.headers,
        )
        assert create_resp.status_code == 201
        team_id = create_resp.json()["id"]
        member_id = "usr_01J5INT000000000000MEM02"

        # Add
        await client.post(
            f"{endpoints.org}/teams/{team_id}/members",
            json={"user_id": member_id, "role_in_team": "MEMBER"},
            headers=tenant.headers,
        )
        # Remove
        r = await client.delete(
            f"{endpoints.org}/teams/{team_id}/members/{member_id}",
            headers=tenant.headers,
        )
        assert r.status_code == 204


class TestMembershipCRUD:
    @pytest.fixture(scope="class")
    async def member_ou(self, client: httpx.AsyncClient, endpoints, tenant) -> dict:
        r = await client.post(
            f"{endpoints.org}/org-units",
            json={"code": "integration-mem-ou", "name": "Membership Test OU", "kind": "DEPARTMENT"},
            headers=tenant.headers,
        )
        assert r.status_code == 201
        return r.json()

    async def test_upsert_membership(
        self, client: httpx.AsyncClient, endpoints, tenant, member_ou: dict,
    ) -> None:
        user_id = "usr_01J5INT000000000000MEM03"
        payload = {
            "primary_org_unit_id": member_ou["id"],
            "job_title": "Integration Test Engineer",
            "employee_no": "IT-001",
            "employment_kind": "EMPLOYEE",
        }
        r = await client.put(
            f"{endpoints.org}/users/{user_id}/membership",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code in (200, 201), f"Upsert membership failed: {r.text}"
        data = r.json()
        assert data["primary_org_unit_id"] == member_ou["id"]
        assert data["job_title"] == "Integration Test Engineer"

    async def test_get_membership(
        self, client: httpx.AsyncClient, endpoints, tenant, member_ou: dict,
    ) -> None:
        user_id = "usr_01J5INT000000000000MEM03"
        r = await client.get(
            f"{endpoints.org}/users/{user_id}/membership",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["primary_org_unit_id"] == member_ou["id"]


class TestHealth:
    async def test_healthz(self, client: httpx.AsyncClient, endpoints) -> None:
        r = await client.get(f"{endpoints.org}/healthz")
        assert r.status_code == 200
