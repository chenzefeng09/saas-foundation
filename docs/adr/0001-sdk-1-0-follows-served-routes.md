# 0001. Release the SDKs as 1.0.0, sending only requests the services serve

- **Status:** Proposed
- **Date:** 2026-10-30
- **Scope:** `foundation-sdk` (`sdks/python`) and `@foundation/sdk` (`sdks/typescript`), both at 0.1.0

## Context

The SDK resources are written by hand, and nothing compared what they send
with what the services serve. Replaying every public method of the 0.1.0 SDKs
against the services' apps, 54 of 193 Python calls and 46 of 174 TypeScript
calls failed:

- some hit a route that does not exist (404) or with the wrong method (405);
- some sent a body the route rejects (422);
- some sent parameter or field names the route does not declare. These failed
  silently: FastAPI ignores unknown query parameters and pydantic drops unknown
  body fields, so the call returned 2xx while a filter or option had no effect.

Six methods have no route behind them at all.

Fixing the calls removes methods, changes signatures and changes one return
type. [`docs/sdk-release.md`](../sdk-release.md) §1 makes each of those a major
release that needs an ADR.

## Decision

1. Both SDKs send the requests the services serve, and both are released as
   **1.0.0**. Where a route and its contract disagreed, the implemented route
   won if something already called it (the SDKs or agent-platform's BFF).
   Where no route settled a name, the design docs and
   [`docs/CONVENTIONS.md`](../CONVENTIONS.md) decided. The contracts were
   corrected to match.

2. **Six methods with no route are removed**, not deprecated: `audit.get_event`,
   `identity.disable_user`, `identity.validate_password`,
   `lifecycle.set_retention_policy`, `lifecycle.get_retention_policy` and
   `lifecycle.generate_destruction_certificate`. A method whose only possible
   answer is 404 has no behaviour to keep. Each can come back in a minor
   release once its route exists.

3. **These signatures change**, so code that calls them must change. The table
   uses the Python names; TypeScript changes the same way, in camelCase with
   options objects.

   | Method | Change |
   | --- | --- |
   | `lifecycle.restore_from_bin`, `lifecycle.purge_from_bin` | Take the recycle-bin entry id (`bin_id`, as `list_recycle_bin` returns it), not the resource id. Nothing in the call names who acted: the service records the authenticated caller. |
   | `audit.verify_chain` | `event_ids` is gone. It re-verifies the tenant's chain from `from_event_id` onwards (`service`, `limit`). |
   | `audit.export` | Returns the exported file as text (`str`), not a dict. Gains `user_id` and `resource_id` filters. |
   | `authz.bind_role` | `role_name` and `scope` become `role_id` (from `list_roles`) and `scope_kind` (default `TENANT`). `scope_id`, `expires_at` and `grant_reason` are optional. |
   | `crypto.encrypt`, `crypto.decrypt` | `aad` becomes `context`, the encryption context (a string map). |
   | `crypto.sign`, `crypto.verify` | `algorithm` is gone and `key_label` is required. `prehash`, `detached` and `kek_version` are optional. |
   | `crypto.create_kek` | `purpose` is required. |
   | `crypto.rewrap` | `target_kek_label` becomes the optional `target_kek_version`. |
   | `identity.create_user` | `password` is gone: identity emails an invite instead. |
   | `identity.freeze_user` | `reason` (5 to 500 characters) is required. |
   | `identity.list_sessions`, `identity.revoke_session` | Act on the caller's own sessions, so `user_id` is gone. |
   | `org.create_team` | `code` is required. |
   | `search.deindex` | Takes `resource_type` before `resource_id`. |

4. **Other methods keep their signatures but now reach their route:**
   - `audit.query` posts to `/events:query`;
   - `lifecycle.release_legal_hold` posts to `/legal-holds/{hold_id}:release`;
   - `crypto.hash_password` and `crypto.verify_password` use `/password-hash`
     and `/password-verify`;
   - `identity.get_password_policy` uses `/policies/password`;
   - `org.add_member` and `org.remove_member` use `/teams/{team_id}/members`.
     `add_member`'s `role` takes the route's values (`MEMBER`, `LEAD`,
     `OBSERVER`) and defaults to `MEMBER`;
   - `org.list_org_units` and `org.list_teams` send `filter.*`.

   Others now send the field their route requires:
   - `lifecycle.mark_legal_hold` sends `resource_type_id`;
   - `authz.create_role` sends `display_name`;
   - `authz.check` sends `user_id`, which defaults to the context user. With
     no user, it raises before sending.

   Two answers change under the four-eyes rule (`docs/design/lifecycle-v1.md`
   §4.4). `lifecycle.purge_from_bin` and `lifecycle.release_legal_hold` act
   only once a second user approves. Until then they return
   `{destroyed: false, approval_request}` or `{released: false, approval_request}`.
   A caller that took the answer as done must now wait for the approval.

   Each `fix(sdk)` commit lists the request every method sent before and what
   the service answered.

5. **Additions** ship in the same release:
   - the lifecycle approval requests behind the four-eyes rule:
     `list_approval_requests`, `get_approval_request`, `approve_request` and
     `reject_request`;
   - optional arguments: `authz.check(user_id=)`,
     `authz.create_role(display_name=, description=)`,
     `lifecycle.mark_legal_hold(case_reference=)` and
     `crypto.create_kek(auto_rotate_days=)`. Python's `crypto.encrypt_async(context=)`,
     `search.query_async(cursor=)` and `notification.send_async(priority=)` are new too;
   - `bytes` as well as `str` for the payloads of `crypto.encrypt`, `crypto.sign` and
     `crypto.verify`;
   - a text response in both transports: Python `request_text` /
     `request_text_async`, TypeScript `responseType: "text"`;
   - a public TypeScript `Transport.resolveContext`.

6. **The golden requests are the SDKs' wire contract.**
   [`contracts/sdk/`](../../contracts/sdk/) pins the request every public
   method sends: method, path, query and JSON body. Two kinds of check use the
   pins:
   - both SDK suites check that each method sends exactly its pinned request;
   - every service suite (`tests/unit/test_sdk_requests.py`) checks that the
     request reaches a route that accepts it and that the contract documents it.

   Changing an existing case's method, path or required fields is a
   wire-level change, and so a major release. Adding a case or an optional
   field is a minor release.

## Alternatives considered

- **Release 0.2.0.** Semver lets a 0.x minor break, and consumers' `>=0.1,<0.2`
  pin would keep 0.2.0 out. Rejected: `docs/sdk-release.md` reserves breaking
  changes for a major and names 1.0.0 as the first one, and agent-platform's
  `docs/foundation-sdk-consumption.md` already plans the `>=1.0,<2.0` pin.
  Under 0.x, the policy's "a minor is compatible" row is never true.
- **Release 0.1.1.** Rejected: every `>=0.1,<0.2` lockfile would take the
  removals on its next `poetry update`.
- **Keep the old methods as deprecated wrappers.** Rejected: none of the old
  calls reached a route, so a wrapper would keep only the failure.
- **Change the services to accept the old requests.** Rejected: the routes are
  implemented and agent-platform's BFF already calls them. The old requests
  matched neither the services nor most contracts.

## Consequences

- **agent-platform needs no code change for the SDK.** It imports only `CookieSigner`,
  `SignatureExpiredError`, `SignatureInvalid` and `foundation_sdk.fastapi` from
  the SDK, and this release changes none of them. To take 1.0.0 from the
  internal index, it moves the pin in `docs/foundation-sdk-consumption.md`
  to `>=1.0,<2.0`. Images built from the `foundation_sdk` build context run the
  new code as soon as it is checked out.
- **Release order:** per `docs/sdk-release.md`, merge this and the agent-platform
  pin change, then tag `foundation-sdk-v1.0.0`.
- **The lifecycle service goes out first.** 1.0.0 sends hard-delete and
  legal-hold release without a body, and an older lifecycle service answers
  that with 422. So deploy the lifecycle service that records the
  authenticated caller and applies the four-eyes rule before publishing
  1.0.0, or with it. That service, in turn, needs agent-platform's admin web
  to have an approval view and BFF proxies for `/approval-requests` before it
  goes live.
- **Upgrading breaks only calls that were already failing.** Code calling a
  removed or changed method breaks at upgrade, but every such call was already
  getting a 404, 405 or 422, or being ignored.
- `docs/sdk-release.md` now describes the 1.x pin. It used to say
  `>=0.1,<0.2` admits 0.2.x, which it does not.
