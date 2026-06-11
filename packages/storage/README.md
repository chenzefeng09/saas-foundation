# foundation-storage

SaaS Foundation — Storage abstraction layer for MinIO/S3 (tenant-scoped key layout, quota hooks, OTel spans).

## Usage

```python
from foundation_storage import StorageClient, get_settings
from foundation_storage.keys import ObjectKey

client = StorageClient(get_settings(), tenant_id="tnt_demo")
key = ObjectKey.for_workspace_file("tnt_demo", "ws_01", "f_01", "report.pdf")
await client.put_object(key, body=b"hello", content_type="application/pdf")
```
