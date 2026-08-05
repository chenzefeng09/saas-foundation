# foundation-storage

SaaS Foundation — Storage abstraction layer for MinIO/S3 (tenant-scoped key layout, quota hooks, OTel spans).

## Usage

```python
from foundation_storage import StorageClient, get_settings
from foundation_storage.keys import ObjectKey

client = StorageClient(
    get_settings(),
    tenant_id="tnt_01J5DEVXX00000000000000001",
    actor_id="usr_01J5DEVUSER000000000000001",
)
key = ObjectKey.for_workspace_file(
    "tnt_01J5DEVXX00000000000000001", "ws_01", "f_01", "report.pdf"
)
await client.put_object(key, body=b"hello", content_type="application/pdf")
```

Tenant-scoped clients fail closed: every object operation requires an actor and
an authoritative DLP decision; reads/downloads below the resource sensitivity
are denied, and L5 objects cannot be downloaded. Background reconciliation and
migration jobs must opt into the explicit `StorageClient.as_system(...)` path;
constructing an ordinary client with `tenant_id=None` is rejected.

Presigned URLs support only `get_object` and `put_object`. Their TTL must be
between one second and `STORAGE_PRESIGNED_URL_TTL_SECONDS`; callers cannot
override that configured maximum.
