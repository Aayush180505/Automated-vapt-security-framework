# Phase 5 — Active Vulnerability Assessment

## 1. Objective

Add the first **controlled active detection** plugins on top of the Phase 4 assessment engine.

These plugins send a small number of **in-scope GET** requests against query parameters discovered in Phase 3. They look for explainable evidence of:

- SQL injection (database error signatures)
- Reflected XSS (unique marker reflection in HTML)
- Path traversal (file-content indicators on path-like parameters)

They are **detection-oriented**. They do not exploit, dump data, execute JavaScript, or persist access.

## 2. Passive vs active plugins

`SecurityPlugin` remains the contract. `is_active = False` by default.

`ActivePlugin` sets `is_active = True`.

| Plugin | Kind | Extra HTTP |
| --- | --- | --- |
| `security-headers` | Passive | None (uses Phase 3 probe) |
| `information-disclosure` | Passive | None |
| `sql-injection` | Active | GET probes via `ScannerHttpClient` |
| `reflected-xss` | Active | GET probes via `ScannerHttpClient` |
| `path-traversal` | Active | GET probes via `ScannerHttpClient` |

Passive plugins must not construct `ScannerHttpClient` or call `httpx` directly.

## 3. Active scanner architecture

```
CLI → recon (Nmap, HTTP, crawl) → AssessmentEngine
        → PluginRegistry (fixed order)
            → PassivePlugin.check()
            → ActivePlugin.check()
                → ScannerHttpClient.get()
                    → HttpClient (timeout, User-Agent, TLS)
        → validate → dedupe → ScanContext.findings
```

The engine does not contain SQLi/XSS/path rules. Future scanners register on `PluginRegistry` the same way.

## 4. ScannerHttpClient

Shared GET-only helper (`scanners/active/client.py`):

- Timeout and User-Agent come from the existing `HttpClient` / settings
- Redirects are not followed off-origin
- Request count is tracked per plugin instance
- Out-of-scope URLs are skipped (no request)
- Logs scanner name, method, parameter **name**, request number, and path — not payload values

Scanners must not create their own `httpx` clients.

## 5. Request limits

`VAPT_MAX_SCANNER_REQUESTS` (default **25**) is enforced **per plugin per target** in `ScannerHttpClient`.

When the budget is exhausted:

- further `get()` calls return `None`
- the scanner stops
- findings already produced are kept
- the condition is logged

There is no unbounded payload loop.

## 6. Scope enforcement

Every GET is checked with the existing same-origin helper (`scheme` + `host` + `port`).

- `http://lab.local` and `https://external.example` are different origins
- `http://lab.local:8080` and `http://lab.local:9090` are different origins
- A `Location` header that leaves origin is **not** followed

The crawler already stays on-origin; active scanners do not widen that.

## 7. SQL injection detection

Eligible: GET endpoints with query parameters (not password/token/csrf/auth names). Forms and POST bodies are not submitted.

For each parameter:

1. Baseline GET of the original URL
2. Replace **only** that parameter with a single quote `'`
3. Compare bodies

A finding is raised only if a **database error signature** appears in the test body and was **absent** from the baseline. Families: MySQL, PostgreSQL, MSSQL, Oracle, SQLite. A small needle list is used; there is no payload database.

Status-code or length change alone is not enough.

Title: **Potential SQL Injection**. Severity **HIGH**, confidence **MEDIUM**. This is indicative, not a confirmed dump or bypass.

## 8. Reflected XSS detection

Eligible: same GET query parameters.

Sends unique marker `VAPTREFLECT123`. If the marker is reflected in an HTML/text response, context is classified as:

- `html-attribute` (marker inside a quoted attribute value)
- `html-text` (otherwise present in the body)

Reflection is **not** treated as confirmed script execution. No browser, no JavaScript runtime, no stored/DOM XSS.

Title: **Potential Reflected XSS**. Severity **MEDIUM**, confidence **MEDIUM**.

## 9. Path traversal detection

Eligible: GET query names in a small list: `file`, `filename`, `filepath`, `path`, `page`, `document`, `template`.

Probe: `../etc/passwd` on that parameter only.

A finding requires a content indicator (`root:x:0:0`, `root:x:0:`, `[fonts]`) in the test body that was **not** in the baseline. Length/status change alone is ignored.

Title: **Potential Path Traversal**. Severity **HIGH**, confidence **MEDIUM**. This is not an arbitrary file-read exploit.

## 10. Baseline comparison

SQLi and path traversal always compare against the original URL. XSS uses a unique marker so accidental presence of that token in a static page is extremely unlikely; missing marker means no finding.

## 11. Finding evidence

`Evidence` holds a short description, URL, GET method, status, and a short excerpt (error snippet, marker window, or indicator). Cookie values and full bodies are not stored.

## 12. Severity

Guidelines only (no CVSS / risk engine yet):

- Potential SQL Injection: HIGH when an error signature appears after the probe
- Potential Reflected XSS: MEDIUM (reflection, not execution)
- Potential Path Traversal: HIGH when a file-content indicator appears after the probe

## 13. Confidence

Existing `Confidence` enum. Phase 5 active findings use **MEDIUM**: the signal is repeatable and specific, but not a full confirmation of exploitability. Weak signals are not reported.

## 14. False-positive control

Do **not** report because:

- status code changed
- content length changed
- a generic error appeared
- the parameter exists
- the marker appeared in a non-HTML binary-like type

Prefer fewer findings.

## 15. Scanner registration

`default_registry()` order:

1. `security-headers`
2. `information-disclosure`
3. `sql-injection`
4. `reflected-xss`
5. `path-traversal`

Order is insertion order, not a Python dict accident.

## 16. Error isolation

Plugin exceptions become `AssessmentResult.errors`. Other plugins still run. HTTP timeouts become `HTTPProbeError` and are swallowed per parameter inside each scanner.

## 17. Testing strategy

Mocked `httpx.MockTransport` only. No internet, HTB, or public sites. Coverage includes eligibility, database families, reflection contexts, path indicators, limits, scope, timeouts, isolation, and deduplication.

## 18. Security boundaries

- Authorization warning remains on every `scan`
- GET query parameters only
- No form POST, cookies, or Authorization-header mutation
- No command injection, SSRF, RCE, credential attacks, stored/DOM XSS, blind/time-based SQLi
- Active checks can be turned off: `VAPT_ENABLE_ACTIVE_SCANNERS=false` (CLI states they were disabled)

Default: active scanners **enabled**, because the user already opted into `scan` after the authorization warning. Disable them when you only want passive header/disclosure checks.

Timeouts use `VAPT_HTTP_TIMEOUT` / `VAPT_REQUEST_TIMEOUT`. Scanners cannot pick an unsafe timeout.

## 19. Limitations

- Error-based SQLi only; no boolean/blind/time/OOB
- XSS is reflection detection, not exploit confirmation
- Path checks only on name heuristics and a tiny indicator list
- No API fuzzing, directory brute force, or Nuclei
- No database, reporting, or exploitation

## 20. Phase 6

Later work may add further **detection** plugins (for example command injection or SSRF) with the same `ScannerHttpClient` limits. Phase 6 is **not** implemented here. Reporting and persistence remain out of scope.

These scanners are detection-oriented. They do not perform exploitation.
