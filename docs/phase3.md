# Phase 3 — HTTP/HTTPS Detection & Web Attack-Surface Enumeration

## 1. Objective

Discover and structure the **web attack surface** of authorized HTTP(S) services. Phase 3 does not decide whether endpoints are vulnerable. Future scanners will consume `Endpoint`, `Parameter`, and `Form` objects.

## 2. HTTP service detection

Nmap results are classified first using the service name/product/extra text. A port is treated as HTTP only if that text contains `http` (for example `http`, `https`, `http-alt`, `ssl/http`).

The framework does **not** assume port 80 is HTTP or port 443 is HTTPS. SSH on 80 is ignored. If the operator passes an explicit `http://` or `https://` target, that origin is added as a candidate even when Nmap listed only other services.

## 3. HTTP adapter

```text
adapters/http/client.py   transport (httpx)
adapters/http/probe.py    detection + HEAD/GET probe
adapters/http/models.py   HTTPService, HTTPResponseInfo
```

## 4. HTTP client

`HttpClient` wraps httpx with timeout, User-Agent, TLS verify, and max redirects from `Settings`. Responses are converted to `HTTPResponseInfo`. Cookie **names** are stored, not cookie values. Full HTML is not kept on `ScanContext`.

## 5. HTTP probing

Prefer `HEAD` with redirect following for metadata. If the status is 405/501 or the content type looks like HTML (or is missing), fall back to `GET` for title extraction. No payloads, no POST.

Probe failures set `HTTPService.reachable = False` and an error string. They do not abort Nmap results or other origins.

## 6. Web crawler architecture

```text
enumeration/web/crawler.py   queue, visited, limits, scope
enumeration/web/parser.py    BeautifulSoup/lxml (static HTML)
enumeration/web/models.py    Endpoint, Form, Parameter, WebAttackSurface
utils/urls.py                normalize, same-origin, query names
```

The crawler only `GET`s in-scope URLs. It never submits forms. HTML is parsed with BeautifulSoup (`html.parser`) so the project stays installable without compiling lxml.

## 7. URL normalization

`urljoin`, lowercase host/scheme, strip fragments, drop credentials, collapse duplicate slashes, default ports omitted, query keys sorted for stable dedupe. Values of query strings are preserved (names are what scanners will use).

## 8. Same-origin scope

Same origin means matching **scheme, hostname, and port**. `http://10.10.10.10` and `http://10.10.10.10:8080` are different. External links are recorded on `external_references` and not fetched. `javascript:`, `mailto:`, `tel:`, and `data:` are ignored.

## 9. Endpoint model

`method`, `url`, `path`, `parameters`, `source` (`crawl` or `form`), optional `content_type`. Example: `GET /search` with parameter `q`.

## 10. Form model

`action_url`, `method`, `fields` (`name` + `field_type` including textarea/select). Forms are not submitted.

## 11. Parameter discovery

Query names from URLs and form field names. Duplicates collapse by `(name, location)`. Values are not stored for later abuse; this is inventory only.

## 12. robots.txt

`GET /robots.txt` is parsed into `RobotsEntry` records. Disallow prefixes are **not** used as a brute-force list. When respect-robots is on, those paths are skipped if a crawl would hit them.

## 13. Attack-surface model

`WebAttackSurface`: base URL, endpoints, forms, parameters, robots entries, external references, pages crawled. Sorted for stable tests.

## 14. ScanContext

Adds `http_services` and `web_attack_surfaces` without removing Phase 2 `discovery_results`.

## 15. Crawl limits

Defaults: `max_pages=50`, `max_depth=3`, configurable via `VAPT_MAX_PAGES` and `VAPT_MAX_DEPTH`. HTTP timeout via `VAPT_HTTP_TIMEOUT` (falls back to `VAPT_REQUEST_TIMEOUT`).

## 16. Error handling

Timeouts, connection errors, TLS errors, bad redirects, and malformed HTML are handled per origin. One failed HTTPS probe does not drop HTTP. Crawler request failures skip that URL.

## 17. Testing

`httpx.MockTransport` plus HTML/robots fixtures. No internet, no live Nmap.

## 18. Security boundaries

No form POST, no parameter injection, no JS execution, no directory brute force, no credential use, no external-domain crawl, TLS verify on by default (`VAPT_TLS_VERIFY`).

## 19. Limitations

Static HTML only. No SPA/JavaScript routes, no authenticated crawl, no OpenAPI import, no vulnerability verdicts.

## 20. Phase 4

Assessment plugins (starting with security headers / information disclosure) that **read** this attack surface instead of recrawling.
