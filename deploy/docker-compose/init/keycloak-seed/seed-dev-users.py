#!/usr/bin/env python3
"""Keep the dev realm's seed users able to sign in, on every ``up``.

Why
---
Keycloak imports ``init/keycloak/foundation-realm.json`` only once: ``--import-realm``
skips a realm that already exists.  The realm's password policy is kept identical
to production and includes ``forceExpiredPasswordChange(90)``, so 90 days after
the first import every seed user's password counts as expired: Keycloak adds the
UPDATE_PASSWORD required action at login and the password grant fails with
"Account is not fully set up".

What
----
For every user that foundation-realm.json seeds with a password — and only those —
this job (dev compose service ``keycloak-init``):

* sets the seed password from the realm file again, as a non-temporary password.
  That writes a fresh credential, so the 90-day window starts over;
* resets the user's required actions to what the realm file declares (none);
* clears a brute-force lockout.

It also copies each client's ``attributes`` from the realm file to the live
realm, so a client setting changed in the file later (``use.refresh.tokens``,
for one) reaches dev realms imported before the change.  Only the attribute
keys the file declares are written; other attributes, secrets, redirect URIs
and the rest of the client are left alone.

Users that are not in the realm file are never read or changed, and the realm's
password policy is left as it is.  A disabled seed user stays disabled: that is a
deliberate admin action.  Side effect: a password a developer set on a seed user
is replaced by the realm-file value on the next ``up``.  Use a non-seed user to
try out password changes.

``passwordHistory(3)`` also matches the *current* password, so Keycloak rejects
setting the same seed value again.  The job therefore deletes the user's stored
password history first and, if the current password is itself the seed value,
deletes that credential before setting it again.

``--check`` changes nothing: it only signs every seed user in with the password
grant (via the realm file's direct-access client) and exits 1 if any fails.
``tools/dev/healthcheck.sh`` uses it.

Never prints a password or token.  Standard library only (runs on python:3-slim).

Environment
-----------
KC_URL                   Keycloak base URL            (default http://keycloak:8080)
KC_REALM_FILE            realm export with seed users (default /seed/foundation-realm.json)
KEYCLOAK_ADMIN           master-realm admin username  (required, except for --check)
KEYCLOAK_ADMIN_PASSWORD  master-realm admin password  (required, except for --check)
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

KC_URL = os.environ.get("KC_URL", "http://keycloak:8080").rstrip("/")
REALM_FILE = os.environ.get("KC_REALM_FILE", "/seed/foundation-realm.json")

# In-network call: never route it through an HTTP(S)_PROXY a container may inherit.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_HISTORY_REJECTED = "invalidPasswordHistoryMessage"  # Keycloak error key


class SeedError(RuntimeError):
    pass


def _call(
    method: str,
    url: str,
    *,
    token: str | None = None,
    json_body: Any = None,
    form: dict[str, str] | None = None,
) -> tuple[int, Any]:
    headers: dict[str, str] = {}
    data: bytes | None = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    # KC_URL is checked to be http(s) in main(), so no file:/custom schemes here.
    request = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
    try:
        with _OPENER.open(request, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except ValueError:
            return exc.code, raw.decode(errors="replace")[:200]


def _admin_token(username: str, password: str, *, attempts: int = 30) -> str:
    """Master-realm admin token; waits while Keycloak is still starting."""
    last: object = None
    for _ in range(attempts):
        try:
            status, body = _call(
                "POST",
                f"{KC_URL}/realms/master/protocol/openid-connect/token",
                form={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": username,
                    "password": password,
                },
            )
        except urllib.error.URLError as exc:  # not listening yet
            last = exc.reason
        else:
            if status == 200:
                return str(body["access_token"])
            if 400 <= status < 500:  # wrong credentials: retrying will not help
                error = body.get("error") if isinstance(body, dict) else body
                raise SeedError(f"master-realm admin login failed: HTTP {status} {error}")
            last = f"HTTP {status}"
        time.sleep(2)
    raise SeedError(f"Keycloak not reachable at {KC_URL}: {last}")


def _seed_users(doc: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
    seeds = []
    for user in doc.get("users", []):
        password = next(
            (
                c.get("value")
                for c in user.get("credentials", [])
                if c.get("type") == "password" and c.get("value")
            ),
            None,
        )
        if password:
            seeds.append((user, password))
    return seeds


def _delete_credentials(token: str, users_url: str, user_id: str, cred_type: str) -> int:
    status, creds = _call("GET", f"{users_url}/{user_id}/credentials", token=token)
    if status != 200:
        raise SeedError(f"list credentials: HTTP {status}")
    deleted = 0
    for cred in creds or []:
        if cred.get("type") == cred_type:
            status, _ = _call(
                "DELETE", f"{users_url}/{user_id}/credentials/{cred['id']}", token=token
            )
            if status not in (204, 404):
                raise SeedError(f"delete {cred_type} credential: HTTP {status}")
            deleted += 1
    return deleted


def _reset_password(token: str, users_url: str, user_id: str, password: str) -> tuple[int, Any]:
    return _call(
        "PUT",
        f"{users_url}/{user_id}/reset-password",
        token=token,
        json_body={"type": "password", "value": password, "temporary": False},
    )


def _apply(token: str, realm: str, user: dict[str, Any], password: str) -> str:
    users_url = f"{KC_URL}/admin/realms/{realm}/users"
    username = user["username"]
    query = urllib.parse.urlencode({"username": username, "exact": "true"})
    status, found = _call("GET", f"{users_url}?{query}", token=token)
    if status != 200:
        raise SeedError(f"look up user: HTTP {status}")
    if not found:
        return "not in Keycloak (deleted after import?) — skipped"
    current = found[0]
    user_id = current["id"]

    # Stored history would make the seed value "one of the last N passwords".
    _delete_credentials(token, users_url, user_id, "password-history")
    status, body = _reset_password(token, users_url, user_id, password)
    if status == 400 and _HISTORY_REJECTED in json.dumps(body):
        # The current password *is* the seed value: drop it, then set it again.
        _delete_credentials(token, users_url, user_id, "password")
        status, body = _reset_password(token, users_url, user_id, password)
    if status != 204:
        error = body.get("error") if isinstance(body, dict) else body
        raise SeedError(f"reset password: HTTP {status} {error}")
    notes = ["password re-applied (expiry window restarted)"]

    # A non-temporary reset already drops UPDATE_PASSWORD; restore the rest of the
    # realm-file state (seed users declare no required actions).
    wanted = list(user.get("requiredActions") or [])
    status, fresh = _call("GET", f"{users_url}/{user_id}", token=token)
    if status != 200:
        raise SeedError(f"read user: HTTP {status}")
    if sorted(fresh.get("requiredActions") or []) != sorted(wanted):
        status, _ = _call(
            "PUT", f"{users_url}/{user_id}", token=token, json_body={"requiredActions": wanted}
        )
        if status != 204:
            raise SeedError(f"reset required actions: HTTP {status}")
        notes.append(f"required actions {fresh.get('requiredActions')} -> {wanted}")

    status, _ = _call(
        "DELETE",
        f"{KC_URL}/admin/realms/{realm}/attack-detection/brute-force/users/{user_id}",
        token=token,
    )
    if status not in (204, 404):
        raise SeedError(f"clear brute-force state: HTTP {status}")

    if not current.get("enabled", True):
        notes.append("user is DISABLED in Keycloak — left disabled")
    return "; ".join(notes)


def _sync_client_attributes(token: str, realm: str, client: dict[str, Any]) -> str | None:
    """Write the realm file's attributes for ``client`` to the live realm.

    Returns a note when something changed, ``None`` when it already matched.
    """
    wanted = {k: str(v) for k, v in (client.get("attributes") or {}).items()}
    if not wanted:
        return None
    clients_url = f"{KC_URL}/admin/realms/{realm}/clients"
    query = urllib.parse.urlencode({"clientId": client["clientId"]})
    status, found = _call("GET", f"{clients_url}?{query}", token=token)
    if status != 200:
        raise SeedError(f"look up client: HTTP {status}")
    if not found:
        return "not in Keycloak (deleted after import?) — skipped"
    live_id = found[0]["id"]
    current = found[0].get("attributes") or {}
    changed = {k: v for k, v in wanted.items() if current.get(k) != v}
    if not changed:
        return None
    # Keycloak updates only the fields present, and only the attribute keys given.
    status, body = _call(
        "PUT", f"{clients_url}/{live_id}", token=token, json_body={"attributes": changed}
    )
    if status != 204:
        error = body.get("error") if isinstance(body, dict) else body
        raise SeedError(f"update attributes: HTTP {status} {error}")
    status, fresh = _call("GET", f"{clients_url}/{live_id}", token=token)
    if status != 200:
        raise SeedError(f"read client: HTTP {status}")
    applied = fresh.get("attributes") or {}
    missed = sorted(k for k, v in changed.items() if applied.get(k) != v)
    if missed:
        raise SeedError(f"attributes not applied: {', '.join(missed)}")
    return "; ".join(f"{k} {current.get(k)!r} -> {v!r}" for k, v in sorted(changed.items()))


def _check_logins(doc: dict[str, Any], seeds: list[tuple[dict[str, Any], str]]) -> int:
    """Password-grant sign-in for every seed user; read-only."""
    client = next(
        (
            c
            for c in doc.get("clients", [])
            if c.get("directAccessGrantsEnabled") and c.get("enabled", True)
        ),
        None,
    )
    if client is None:
        print("keycloak-init --check: no client with direct access grants in the realm file")
        return 1
    failed = 0
    for user, password in seeds:
        form = {
            "grant_type": "password",
            "client_id": client["clientId"],
            "username": user["username"],
            "password": password,
        }
        if not client.get("publicClient") and client.get("secret"):
            form["client_secret"] = client["secret"]
        url = f"{KC_URL}/realms/{doc['realm']}/protocol/openid-connect/token"
        try:
            status, body = _call("POST", url, form=form)
        except urllib.error.URLError as exc:
            print(f"keycloak-init --check: Keycloak not reachable at {KC_URL}: {exc.reason}")
            return 1
        if status == 200 and isinstance(body, dict) and body.get("access_token"):
            print(f"  {user['username']}: sign-in OK")
            continue
        failed += 1
        detail = body.get("error_description") if isinstance(body, dict) else body
        print(f"  {user['username']}: sign-in FAILED (HTTP {status}: {detail})")
    return 1 if failed else 0


def main() -> int:
    if not KC_URL.startswith(("http://", "https://")):
        print(f"keycloak-init: KC_URL must be http(s), got {KC_URL!r}", file=sys.stderr)
        return 2
    if sys.argv[1:] == ["--check"]:
        with open(REALM_FILE, encoding="utf-8") as fh:
            doc = json.load(fh)
        return _check_logins(doc, _seed_users(doc))
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--check]", file=sys.stderr)
        return 2
    admin_user = os.environ.get("KEYCLOAK_ADMIN")
    admin_password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
    if not admin_user or not admin_password:
        print("keycloak-init: KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD not set", file=sys.stderr)
        return 2

    with open(REALM_FILE, encoding="utf-8") as fh:
        doc = json.load(fh)
    realm = doc["realm"]
    seeds = _seed_users(doc)
    print(f"keycloak-init: realm '{realm}', {len(seeds)} seed user(s) from {REALM_FILE}")

    token = _admin_token(admin_user, admin_password)
    for _ in range(30):  # the realm import finishes during Keycloak start-up
        status, _ = _call("GET", f"{KC_URL}/admin/realms/{realm}", token=token)
        if status == 200:
            break
        time.sleep(2)
    else:
        print(f"keycloak-init: realm '{realm}' not found", file=sys.stderr)
        return 1

    token = _admin_token(admin_user, admin_password)  # admin-cli tokens live ~60 s
    failed = 0
    for client in doc.get("clients", []):
        try:
            outcome = _sync_client_attributes(token, realm, client)
        except SeedError as exc:
            failed += 1
            outcome = f"FAILED: {exc}"
        if outcome:
            print(f"  client {client['clientId']}: {outcome}")
    for user, password in seeds:
        try:
            outcome = _apply(token, realm, user, password)
        except SeedError as exc:
            failed += 1
            outcome = f"FAILED: {exc}"
        print(f"  {user['username']}: {outcome}")
    if failed:
        print(f"keycloak-init: {failed} client(s) or seed user(s) could not be fixed", file=sys.stderr)
        return 1
    print("keycloak-init: done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
