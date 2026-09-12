# Phase 8 — Professional Reporting

## 1. Architecture

Reporting is **read-only**. It never runs Nmap, HTTP, or scanners, and it does not write to MySQL or change risk scores.

```
Scan (already complete)
        ↓
StorageService.get_scan  or  in-memory ScanContext
        ↓
ReportData
        ↓
Jinja2 (autoescape)
        ↓
HTML file under VAPT_REPORT_DIR
```

PDF is **not** implemented (WeasyPrint is not bundled; HTML is the deliverable).

## 2. ReportData

`reporting/models.py` holds scan metadata, services, findings (with stored evidence and risk fields), and static methodology/limitations text. Templates never query MySQL.

## 3. ReportService

`ReportService.write_from_scan_id` / `write_from_details` / `write_from_context` build `ReportData`, render, and write `vapt_report_<scan_id>.html`.

## 4. Template rendering

`reporting/templates/report.html.j2` is loaded with Jinja2 `autoescape` enabled. Untrusted strings are escaped.

## 5. Report sections

Cover, executive summary, scope, methodology, discovered services, web attack surface (only if present in memory; **not** reconstructed from Phase 7 history), risk summary (copied values), findings, evidence, remediation, limitations.

## 6. Risk preservation

Severity, confidence, risk_score, risk_band, and priority are copied from storage or `ScanContext`. They are not recalculated.

## 7. Evidence sanitization

Only stored evidence fields are shown (description, URL, method, status, excerpt). Cookie values and Authorization headers are not persisted in Phase 7 and are not added here.

## 8. HTML escaping

Jinja2 autoescape is on. Tests inject `<script>alert(1)</script>` into target, title, URL, parameter, and evidence and expect `&lt;script&gt;`.

## 9. Generation

```bash
python -m vapt_framework.cli.main report <scan_id>
python -m vapt_framework.cli.main scan --target http://10.10.10.10 --report
```

`--report` writes from the **just-completed** in-memory results (no second scan). `report` loads a stored scan (requires MySQL).

## 10. Optional PDF

Not supported in this release. `--format` accepts `html` only.

## 11. Testing

Mocked storage and temp directories. No live MySQL or network.

## 12. Limitations

No dashboard, no PDF, no attack-surface reconstruction from history, no CVE feed. Zero findings is not a security certification.
