# foundation-lifecycle

SaaS Foundation — Lifecycle Service.

Tenant-level service for data retention policies, recycle bin (soft-delete),
legal holds, destruction certificates and backup/destruction orchestration.

- API prefix: `/api/lifecycle/v1`
- Container port: `8006`
- Schema: `lifecycle`
- Tenant context: required
- Depends on crypto service for key-destruction (`crypto_url`)
