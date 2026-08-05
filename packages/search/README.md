# foundation-search

SaaS Foundation search with mandatory tenant, ACL, and L1-L5 filtering.

- Indexing resolves the resource sensitivity from DLP; callers cannot submit it.
- Querying resolves the user clearance from Identity and injects a numeric
  `sensitivity_rank <= clearance_rank` OpenSearch filter.
- Every returned candidate is revalidated against live DLP state, so a resource
  upgraded after indexing cannot leak through a stale index.
- Identity, DLP, Authz, or OpenSearch failures are handled fail-closed.

After applying migration `0003_search_sensitivity`, reindex existing documents:

```bash
cd packages/search
PYTHONPATH=src poetry run python scripts/reindex_opensearch.py
```
