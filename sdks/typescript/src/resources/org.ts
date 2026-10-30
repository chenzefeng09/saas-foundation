/**
 * Org resource — four-level organization tree management.
 * Mirrors Python SDK foundation_sdk/resources/org.py
 */

import type { Transport } from "../transport.js";

export class OrgResource {
  constructor(private readonly t: Transport) {}

  // --- Org Units ---

  async listOrgUnits(params?: { parentId?: string }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/org/v1/org-units", {
      params: { "filter.parent_id": params?.parentId },
    });
  }

  async createOrgUnit(params: {
    name: string;
    parentId?: string;
    description?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/org/v1/org-units", {
      json: {
        name: params.name,
        parent_id: params.parentId ?? null,
        description: params.description ?? "",
      },
    });
  }

  async getOrgUnit(orgUnitId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/org/v1/org-units/${orgUnitId}`);
  }

  // --- Teams ---

  async listTeams(params?: { orgUnitId?: string }): Promise<Record<string, unknown>> {
    return this.t.request("GET", "/api/org/v1/teams", {
      params: { "filter.org_unit_id": params?.orgUnitId },
    });
  }

  /** `code`: unique slug in the tenant, `^[a-z][a-z0-9_-]{0,31}$`. */
  async createTeam(params: {
    name: string;
    code: string;
    orgUnitId: string;
    description?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", "/api/org/v1/teams", {
      json: {
        name: params.name,
        code: params.code,
        org_unit_id: params.orgUnitId,
        description: params.description ?? "",
      },
    });
  }

  // --- Memberships ---

  /** `role`: MEMBER, LEAD or OBSERVER. */
  async addMember(params: {
    userId: string;
    teamId: string;
    role?: string;
  }): Promise<Record<string, unknown>> {
    return this.t.request("POST", `/api/org/v1/teams/${params.teamId}/members`, {
      json: { user_id: params.userId, role_in_team: params.role ?? "MEMBER" },
    });
  }

  async removeMember(userId: string, teamId: string): Promise<Record<string, unknown>> {
    return this.t.request("DELETE", `/api/org/v1/teams/${teamId}/members/${userId}`);
  }

  async listMembers(teamId: string): Promise<Record<string, unknown>> {
    return this.t.request("GET", `/api/org/v1/teams/${teamId}/members`);
  }
}
