# OpenFirebase Scan JSON Schema v1.0

Structured output for programmatic consumers (webapp, CI, downstream tools).
One JSON document per scan run — one bundle, one DNS list, or one `--project-id` invocation.

Authoritative machine-readable schema: [openfirebase-scan.schema.json](./openfirebase-scan.schema.json).

---

## Design principles

1. **`unauth` and `auth` are siblings on the same finding**, not separate top-level sections. This is the drift-proofing: there is no second formatter that can fall out of sync, because the data lives together.
2. **Raw `status` / `security` are preserved** exactly as the scanner emits them. A derived `verdict` field gives the webapp a stable, small vocab to key off so UI logic doesn't chase every new `security` value the scanners add.
3. **Transport errors go into `error`, not `security`.** The scanner dict conflates the two today (CF writes `TIMEOUT` into `security`); the JSON output separates them. The raw value stays visible — just also mirrored into `error.kind`.
4. **Read and write are separate findings**, not a merged result. RTDB, Firestore, and Storage probe both; Remote Config and Cloud Functions probe read only. Four severity buckets per URL: read-public-unauth, read-public-auth, write-public-unauth, write-public-auth.
5. **Extraction output is first-class.** Service-account blobs and leaked PEM keys are both extraction artifacts *and* findings in their own right — the webapp can render them in two views without duplicating storage.

---

## Top-level shape

```
{
  schema_version, tool_version, scan_id, started_at, finished_at,
  input:      { type, source, platform },
  config:     { check_with_auth, fuzz_collections, fuzz_functions, wordlist, ... },
  auth:       { used, identities[] },
  extraction: { bundle?: {...}, dns?: {...} },
  projects:   [ { project_id, findings[] } ],
  summary:    { per_service: { firestore: {...}, ... } }
}
```

---

## Vocabularies (grounded in scanner code)

### HTTP status codes observed per service

| service         | status codes |
|-----------------|--------------|
| RTDB            | `200`, `401`, `403`, `404`, `423`, `429` |
| Firestore       | `200`, `400`, `401`, `403`, `404`, `429` |
| Storage         | `200`, `400`, `401`, `403`, `404` |
| Remote Config   | `200`, `401`, `403`, `404`, `429` |
| Cloud Functions | `200`, `400`, `401`, `403`, `404`, `405`, `415`, `429`, `500` |
| transport       | `"0"` (timeout / connection error) |

### `security` values emitted per service (unauth path)

| service         | values |
|-----------------|--------|
| RTDB            | `PUBLIC`, `PROTECTED`, `LOCKED`, `NOT_FOUND`, `WRITE_DENIED`, `RATE_LIMITED`, `UNKNOWN` |
| Firestore       | `PUBLIC`, `PUBLIC_DB_NONEXISTENT_COLLECTION`, `DATASTORE_MODE`, `PROTECTED`, `NOT_FOUND`, `WRITE_DENIED`, `UNKNOWN` |
| Storage         | `PUBLIC`, `PROTECTED`, `NOT_FOUND`, `WRITE_DENIED`, `RULES_VERSION_ERROR`, `UNKNOWN` |
| Remote Config   | `PUBLIC`, `PROTECTED`, `NO_CONFIG`, `MISSING_CONFIG`, `NOT_FOUND`, `RATE_LIMITED`, `UNKNOWN` |
| Cloud Functions | `PUBLIC`, `PROTECTED`, `NOT_FOUND`, `SOURCE_LEAK`, `SKIPPED`, `TIMEOUT`, `CONNECTION_ERROR`, `ERROR`, `UNKNOWN` |

### `security` values emitted on the auth-retry path (any service)

`PUBLIC`, `PUBLIC_AUTH` (user token), `PUBLIC_SA` (service account), `PROTECTED`, `APP_CHECK`, `NOT_FOUND`, `UNKNOWN`.

### Derived `verdict` (small stable vocab — UI keys off this)

- `unauth.verdict`: `public | protected | not_found | rate_limited | locked | error | unknown`
- `auth.verdict`:   `public | still_protected | app_check | not_found | error | unknown`

### `probe`

- `read` — emitted by all five services.
- `write` — emitted only by RTDB, Firestore, Storage. Remote Config and Cloud Functions never emit `write` findings.

### Service-specific `resource` fields

| service         | fields set on `resource` |
|-----------------|--------------------------|
| RTDB            | `origin` |
| Firestore       | `collection`, `origin` (`extracted` / `fuzzed` / `default`) |
| Storage         | `surface` (`Firebase Rules` or `GCS IAM`), `origin` |
| Remote Config   | `origin` |
| Cloud Functions | `function_name`, `region`, `origin` (`extracted` / `fuzzed`) |

### Source-code bucket leaks

Cloud Functions source bucket leaks (`security: "SOURCE_LEAK"`) are emitted as regular findings under `projects[].findings[]`, one per leaking region-bucket (gen1 uses `gcf-sources-{num}-{region}`, gen2 uses `gcf-v2-sources-{num}-{region}`). The `url` points at the GCS bucket listing endpoint rather than a function invocation URL.

---

## Multi-APK and `--project-id` handling

- **Multi-APK uploads**: one scan document per APK. The webapp treats each upload as its own result tab. Cross-APK dedup is a UI concern, not a schema concern.
- **`--project-id`**: `input.type = "project_ids"`, no `extraction.bundle` block, findings populated normally.
- **DNS list input**: `input.type = "dns_list"`, `extraction.dns.matched_project_ids` holds the parsed project IDs, findings populated as usual.

---

## Example document

```json
{
  "schema_version": "1.0",
  "tool_version": "1.4.0",
  "scan_id": "2026-04-20T09-12-44_app.apk",
  "started_at": "2026-04-20T09:12:44Z",
  "finished_at": "2026-04-20T09:14:02Z",

  "input":  { "type": "apk", "source": "app.apk", "platform": "android" },
  "config": {
    "check_with_auth": true,
    "fuzz_collections": true,
    "fuzz_functions": false,
    "wordlist": "default",
    "services": ["rtdb", "firestore", "storage", "remote_config", "cloud_functions"]
  },
  "auth": {
    "used": true,
    "identities": [
      { "kind": "service_account", "ref": "firebase-adminsdk-xyz@my-proj.iam.gserviceaccount.com" }
    ]
  },

  "extraction": {
    "bundle": {
      "type": "apk",
      "path": "app.apk",
      "package_name": "com.example.app",
      "signatures": { "sha1": ["AA:BB:CC:..."] },
      "items": [
        { "type": "Google_API_Key",            "value": "AIzaSy...",                              "source": "strings.xml" },
        { "type": "Firebase_Project_ID",       "value": "my-proj",                                "source": "strings.xml" },
        { "type": "Google_App_ID",             "value": "1:000000000000:android:abcdef",          "source": "strings.xml" },
        { "type": "Firebase_Storage_Old",      "value": "my-proj.appspot.com",                    "source": "strings.xml" },
        { "type": "Firestore_Collection_Name", "value": "users",                                  "source": "dex" },
        { "type": "Cloud_Functions_Callable_Name", "value": "sendEmail",                          "source": "dex" }
      ],
      "service_accounts": [
        {
          "client_email": "firebase-adminsdk-xyz@my-proj.iam.gserviceaccount.com",
          "project_id": "my-proj",
          "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
          "file_path": "assets/service-account.json"
        }
      ],
      "leaked_private_keys": [
        {
          "pem_type": "RSA PRIVATE KEY",
          "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
          "source": "dex"
        }
      ]
    }
  },

  "projects": [{
    "project_id": "my-proj",
    "package_names": ["com.example.app"],
    "started_at":  "2026-04-20T09:12:50Z",
    "finished_at": "2026-04-20T09:14:01Z",

    "findings": [
      {
        "service": "firestore",
        "url": "https://firestore.googleapis.com/v1/projects/my-proj/databases/(default)/documents/users",
        "probe": "read",
        "resource": { "collection": "users", "origin": "extracted" },
        "unauth": {
          "status": "403", "security": "PROTECTED", "message": "Permission denied",
          "response_content": "...", "verdict": "protected"
        },
        "auth": {
          "status": "200", "security": "PUBLIC_SA", "message": "Public access (service account)",
          "response_content": "{\"documents\":[...]}",
          "verdict": "public",
          "identity": {
            "kind": "service_account",
            "ref": "firebase-adminsdk-xyz@my-proj.iam.gserviceaccount.com"
          }
        },
        "error": null
      },
      {
        "service": "firestore",
        "url": "https://firestore.googleapis.com/v1/projects/my-proj/databases/(default)/documents/users",
        "probe": "write",
        "resource": { "collection": "users", "origin": "extracted" },
        "unauth": {
          "status": "403", "security": "WRITE_DENIED", "message": "Write denied",
          "verdict": "protected"
        },
        "auth": null,
        "error": null
      },
      {
        "service": "storage",
        "url": "https://firebasestorage.googleapis.com/v0/b/my-proj.appspot.com/o",
        "probe": "read",
        "resource": { "surface": "Firebase Rules", "origin": "extracted" },
        "unauth": {
          "status": "200", "security": "PUBLIC", "message": "Public access",
          "verdict": "public"
        },
        "auth": null,
        "error": null
      },
      {
        "service": "storage",
        "url": "https://storage.googleapis.com/storage/v1/b/my-proj.appspot.com/o",
        "probe": "read",
        "resource": { "surface": "GCS IAM", "origin": "extracted" },
        "unauth": {
          "status": "401", "security": "PROTECTED", "message": "Unauthorized",
          "verdict": "protected"
        },
        "auth": {
          "status": "401", "security": "APP_CHECK",
          "message": "Callable returned UNAUTHENTICATED with a valid Bearer token",
          "verdict": "app_check",
          "identity": { "kind": "service_account", "ref": "firebase-adminsdk-xyz@my-proj.iam.gserviceaccount.com" }
        },
        "error": null
      },
      {
        "service": "cloud_functions",
        "url": "https://us-central1-my-proj.cloudfunctions.net/api",
        "probe": "read",
        "resource": { "function_name": "api", "region": "us-central1", "origin": "extracted" },
        "unauth": {
          "status": "0", "security": "TIMEOUT", "message": "Request timeout",
          "verdict": "error"
        },
        "auth": null,
        "error": { "stage": "unauth", "kind": "TIMEOUT", "message": "Request timeout" }
      },
      {
        "service": "cloud_functions",
        "url": "https://storage.googleapis.com/storage/v1/b/gcf-sources-000000000000-us-central1/o",
        "probe": "read",
        "resource": { "region": "us-central1", "origin": "extracted" },
        "unauth": {
          "status": "200", "security": "SOURCE_LEAK",
          "message": "Cloud Functions source code bucket is publicly listable (gen1)",
          "verdict": "public"
        },
        "auth": null,
        "error": null
      }
    ]
  }],

  "summary": {
    "per_service": {
      "firestore":       { "read_public_unauth": 0, "read_public_auth": 1, "write_public_unauth": 0, "write_public_auth": 0, "protected": 1, "not_found": 0 },
      "storage":         { "read_public_unauth": 1, "read_public_auth": 0, "write_public_unauth": 0, "write_public_auth": 0, "app_check": 1 },
      "cloud_functions": { "errors": 1 }
    }
  }
}
```

---

## Compatibility

- Breaking changes bump `schema_version` major (e.g. `2.0`).
- Additive fields (new optional keys, new enum values in per-service `security` vocab as scanners grow) do **not** bump the major. Consumers must ignore unknown fields.
- The webapp should reject documents whose `schema_version` major doesn't match what it was built for, with a clear "upgrade required" error rather than silent partial rendering.
