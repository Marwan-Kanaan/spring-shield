# Error responses

Authentication and authorization failures return a consistent JSON body:

```json
{
  "timestamp": "2026-08-17T12:30:00Z",
  "status": 403,
  "code": "ACCESS_DENIED",
  "message": "Access denied",
  "path": "/api/invoices"
}
```

| Status | `code` | Meaning |
|---|---|---|
| 401 | `UNAUTHENTICATED` | We do not know who you are. |
| 403 | `ACCESS_DENIED` | We know who you are, and you may not do this. |

Branch on **`code`**, not on `message`. The code is stable; the wording is not.

Three things the body deliberately never contains:

- **The exception message.** Reasons like "user not found" or "credentials expired" tell an
  unauthenticated caller which accounts exist and what state they are in.
- **A stack trace**, even when `server.error.include-stacktrace` is enabled for the rest of
  the application.
- **The query string**, which routinely carries tokens and keys. Only the path is echoed,
  and it is JSON-escaped, since it is caller-controlled.

The missing authority is never named either — reporting "requires invoice.approve" would
let a caller map your permission model by probing endpoints.

A browser navigating to a protected page still gets the login redirect rather than a JSON
body it cannot render. The JSON contract applies to clients that do not ask for HTML.


[Back to the README](../README.md)
