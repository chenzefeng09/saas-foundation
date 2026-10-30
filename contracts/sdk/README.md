# SDK golden requests

The resource methods in `sdks/python/foundation_sdk/resources/` and
`sdks/typescript/src/resources/` are written by hand, not generated from
`contracts/openapi/`. Each file here pins, for one service, the exact HTTP
request every one of those methods sends. Both sides are checked against it:

| Suite | Checks |
|---|---|
| `sdks/python/tests/test_golden_requests.py`, `sdks/typescript/tests/golden_requests.test.ts` | Each listed call sends exactly `request`, and every public method has a case. |
| `packages/<service>/tests/unit/test_sdk_requests.py` (through `tools/contracts/sdk_requests.py`) | `request` reaches a route of the service that accepts it, and `contracts/openapi/<service>.yaml` documents that request with the same parameters and body fields as the route. |

The checks reject names a route does not declare, not only missing required
ones: FastAPI ignores unknown query parameters and pydantic drops unknown body
keys, so a misspelt filter or field still gets a 2xx and silently does
something else.

## Format

```json
{
  "service": "authz",
  "context": {"tenant_id": "tnt_01J9Z8Y7X6W5V4T3S2R1Q0P9N8", "user_id": "usr_01J9Z8Y7X6W5V4T3S2R1Q0P9N8"},
  "cases": [
    {
      "id": "check:defaults",
      "python": [
        {"method": "check", "args": [], "kwargs": {"action": "billing.invoice.read", "resource_type": "document"}},
        {"method": "check_async", "args": [], "kwargs": {"action": "billing.invoice.read", "resource_type": "document"}}
      ],
      "typescript": [
        {"method": "check", "args": [{"action": "billing.invoice.read", "resourceType": "document"}]}
      ],
      "request": {
        "method": "POST",
        "path": "/api/authz/v1/check",
        "json": {"user_id": "usr_01J9Z8Y7X6W5V4T3S2R1Q0P9N8", "action": "billing.invoice.read", "resource_type": "document"}
      }
    }
  ]
}
```

- `context`: the tenant and user both SDK suites make every call under. A
  request that takes a value from the context, like the `user_id` above or the
  `tenant_id` of an audit query, expects these ids.
- `python` / `typescript`: the calls that must send `request`, in both languages;
  a sync method and its `_async` twin share a case.
- `request.path` is the path as sent, percent-encoding included. `query` maps a
  name to a string, or to a list when it is repeated; leave it out when there is
  none. `json` is the body; leave it out when there is none. Headers are the
  transports' business and are not pinned.
- Use argument values the route would accept (ids with their prefix and ULID,
  enum members, lengths): the service side validates them.
- A case id names the method; a second case of the same method gets a suffix,
  such as `:defaults` for the call with only the required arguments.

## Changing a method, a route or a contract operation

Change the case in the same change. A failing SDK test prints the request the
method sent next to the pinned one; a failing service test names the route, the
parameter or the field it disagrees on. Add a case for every new public method:
the SDK suites fail on a method without one.
