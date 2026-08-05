<!--
Thanks for contributing to SaaS Foundation.
Please fill out every section. Keep the description focused on WHAT changes and WHY.
Security issues must NOT be disclosed in a public PR — follow the security policy (SECURITY.md) instead.
-->

## Summary

<!-- What does this PR do, and why? Link to the design or discussion if there is one. -->

## Type of change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior or API)
- [ ] Documentation only
- [ ] Build / CI / tooling
- [ ] Refactor (no functional change)

**Affected package(s):** <!-- e.g. authz, billing, storage, or "cross-cutting" -->

## Linked issues

<!-- Use "Closes #123" / "Fixes #123" to auto-close, or "Relates to #123". -->

Closes #

## Testing

<!-- Describe how you verified the change. Tick the commands you ran. -->

- [ ] `make lint` (ruff + mypy) passes
- [ ] `make test` (pytest, all packages) passes
- [ ] `make test-rls-fuzz` passes — **required for any change touching the database / RLS / tenant isolation**
- [ ] Contract check passes (Spectral lint of the OpenAPI spec under `contracts/openapi/`) — **required for any API change**
- [ ] `make integration-test` run, if cross-service behavior changed
- [ ] Manual verification (describe below)

<details>
<summary>Verification notes</summary>

<!-- Commands, payloads, before/after output, or screenshots that show the change working. -->

</details>

## Checklist

- [ ] I followed the project conventions (see [docs/CONVENTIONS.md](../docs/CONVENTIONS.md)).
- [ ] New or changed tables ship with RLS policies, and I added/updated RLS fuzz coverage under the package's `tests/security/`.
- [ ] For API changes, the OpenAPI spec under `contracts/openapi/` is updated and there is **no breaking change** to published contracts (or the breaking change is called out above and the version bumped accordingly).
- [ ] Security gates pass: `make scan` (secret scan, SAST, license check) is clean and no new high/critical findings were introduced.
- [ ] No secrets, credentials, private filesystem paths, or internal hostnames are committed (config and examples use placeholders).
- [ ] Documentation (README / design docs / SDK docs) is updated where behavior or contracts changed.
- [ ] Changes are scoped to the foundation's general-purpose responsibilities and do not leak consumer-specific logic (e.g. from [Agent Platform](https://github.com/chenzefeng09/agent-platform)).
