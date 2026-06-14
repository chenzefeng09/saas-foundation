"""Org-service reverse-lookup client for large-attachment subject resolve.

Thin async ``httpx`` client over a handful of foundation-org read endpoints.
Used by :meth:`LargeAttachmentService.resolve` to enrich a user with the
TEAM / ORG_UNIT subjects they belong to, so a whitelist on a team or org-unit
(with ancestor inheritance) can admit the user.

Auth model: the org reverse-lookup endpoints
(``/users/{id}/teams``, ``/users/{id}/membership``,
``/users/{id}/secondary-org-units``, ``/org-units/{id}/ancestors``) are
*tenant-gated only* — they depend on ``current_context`` (the
``X-Tenant-Id`` request context) and do NOT carry ``require_scope`` guards.
So we forward only ``X-Tenant-Id`` (plus ``X-Request-Id`` for tracing); no
``X-Foundation-Scopes`` is needed or sent.

Fail-soft: org enrichment is best-effort. A 404 (no membership) or any
transport / 5xx failure degrades to "no team/ou memberships" (logged as a
warning) rather than raising — the caller (``resolve``) is fail-CLOSED on
admission, so degraded org data simply yields ``not_listed`` rather than a
spurious allow or a crash.
"""

from __future__ import annotations

import httpx

from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)

_TIMEOUT_SECONDS = 5.0


class OrgClient:
    """Reverse-lookup client: team / org-unit memberships for a user."""

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        # ``base_url`` already includes the ``/api/org/v1`` prefix.
        self._base = base_url.rstrip("/")
        # ``client`` lets unit tests inject a fake/mocked client; in production
        # we open a fresh AsyncClient per call (mirrors KeycloakAdmin — keep-alive
        # pools have proved flaky against sibling services under Docker Desktop).
        self._injected_client = client

    # ------------------------------------------------------------------ helpers
    def _new_client(self) -> httpx.AsyncClient:
        if self._injected_client is not None:
            return self._injected_client
        return httpx.AsyncClient(
            timeout=_TIMEOUT_SECONDS,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    @staticmethod
    def _headers(tenant_id: str) -> dict[str, str]:
        # Tenant-gated only — no scope header required by org.
        return {"X-Tenant-Id": tenant_id}

    async def _get_json(self, path: str, *, tenant_id: str) -> object | None:
        """GET ``path`` and return parsed JSON, or ``None`` on any failure.

        Returns ``None`` for 404 (no membership / not found) and for any
        transport error or non-2xx status — the caller degrades gracefully.
        """
        url = f"{self._base}{path}"
        client = self._new_client()
        try:
            try:
                resp = await client.get(
                    url, headers=self._headers(tenant_id)
                )
            except httpx.HTTPError as exc:
                log.warning(
                    "large_attachment.org_lookup.transport_error",
                    path=path,
                    tenant_id=tenant_id,
                    error=str(exc),
                )
                return None
        finally:
            if self._injected_client is None:
                await client.aclose()

        if resp.status_code == 404:
            # No membership row / unknown user — treat as "no data".
            return None
        if resp.status_code >= 400:
            log.warning(
                "large_attachment.org_lookup.bad_status",
                path=path,
                tenant_id=tenant_id,
                status=resp.status_code,
            )
            return None
        try:
            return resp.json()
        except ValueError as exc:  # malformed body
            log.warning(
                "large_attachment.org_lookup.bad_body",
                path=path,
                tenant_id=tenant_id,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------ public
    async def teams_of(self, *, tenant_id: str, user_id: str) -> list[str]:
        """Return the team ids the user is an active member of.

        Org ``GET /users/{id}/teams`` returns a bare ``list[TeamRead]``; we
        project to ``id``. Degrades to ``[]`` on any failure.
        """
        data = await self._get_json(
            f"/users/{user_id}/teams", tenant_id=tenant_id
        )
        if not isinstance(data, list):
            return []
        return [
            tid
            for item in data
            if isinstance(item, dict)
            and isinstance((tid := item.get("id")), str)
        ]

    async def org_units_of(self, *, tenant_id: str, user_id: str) -> list[str]:
        """Return all org-unit ids the user is attached to, incl. ancestors.

        Union of:
          * primary org-unit (``/membership`` → ``primary_org_unit_id``),
          * every secondary org-unit (``/secondary-org-units`` →
            ``org_unit_id``),
          * for EACH of the above, the full ancestor chain
            (``/org-units/{id}/ancestors`` → bare ``list[OrgUnitRead]``,
            each with ``id``).

        Ancestor inheritance is ON by design: a user in ``/eng/infra`` is
        covered by a whitelist on ``/eng``. Deduped, order-preserving.
        Degrades to whatever it could collect on partial failure.
        """
        seeds: list[str] = []

        membership = await self._get_json(
            f"/users/{user_id}/membership", tenant_id=tenant_id
        )
        if isinstance(membership, dict):
            primary = membership.get("primary_org_unit_id")
            if isinstance(primary, str):
                seeds.append(primary)

        secondary = await self._get_json(
            f"/users/{user_id}/secondary-org-units", tenant_id=tenant_id
        )
        if isinstance(secondary, list):
            for item in secondary:
                if isinstance(item, dict):
                    ou = item.get("org_unit_id")
                    if isinstance(ou, str):
                        seeds.append(ou)

        # Union the seeds with each seed's ancestor chain, deduped + ordered.
        result: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            if seed not in seen:
                seen.add(seed)
                result.append(seed)
            ancestors = await self._get_json(
                f"/org-units/{seed}/ancestors", tenant_id=tenant_id
            )
            if isinstance(ancestors, list):
                for item in ancestors:
                    if isinstance(item, dict):
                        aid = item.get("id")
                        if isinstance(aid, str) and aid not in seen:
                            seen.add(aid)
                            result.append(aid)
        return result
