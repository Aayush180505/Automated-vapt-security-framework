# Automated VAPT & Security Assessment Framework

Modular **Python CLI** for **authorized** security assessments (local labs, CTFs, HTB/Academy, and other systems you own or have explicit permission to test).

This is an assessment and orchestration framework, **not** an exploit kit and **not** a web dashboard.

## Status

| Phase | Area | State |
| --- | --- | --- |
| 1 | Foundation | COMPLETE |
| 2 | Nmap Discovery | COMPLETE |
| 3 | Web Attack Surface | COMPLETE |
| 4 | Assessment Engine | COMPLETE |
| 5 | Active Assessment | COMPLETE |
| 6 | Risk Engine | COMPLETE |
| 7 | MySQL Persistence | COMPLETE |
| 8 | Professional Reporting | COMPLETE |

## Purpose

Repeatable, authorized vulnerability **assessment** (detection, evidence, explainable risk, optional history, HTML reports). It does not exploit systems, steal credentials, or claim complete VAPT coverage.

## Architecture

```
Target
  → Target validation
  → Nmap / service discovery
  → HTTP detection
  → Web enumeration / attack surface
  → Passive checks
  → Active checks (bounded, in-scope GET)
  → Finding validation + deduplication
  → Risk engine
  → Optional MySQL persistence
  → HTML report (read-only; no rescan)
```

## Installation

Python 3.11+. Nmap on `PATH` for live `scan`. MySQL only if you enable persistence.

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` locally. Do not commit real passwords.

- HTTP/crawler/scanner limits: `VAPT_HTTP_TIMEOUT`, `VAPT_MAX_PAGES`, `VAPT_ENABLE_ACTIVE_SCANNERS`, …
- Reports: `VAPT_REPORT_DIR` (default `reports/`, gitignored)
- MySQL (opt-in): `VAPT_DATABASE_ENABLED=false` by default

## MySQL setup

1. Create an empty database (for example `vapt_framework`).
2. Set `VAPT_DB_*` and `VAPT_DATABASE_ENABLED=true`.
3. `python -m vapt_framework.cli.main db init`

## Commands

```bash
python -m vapt_framework.cli.main --help
python -m vapt_framework.cli.main version
python -m vapt_framework.cli.main scan --target http://10.10.10.10
python -m vapt_framework.cli.main scan --target http://10.10.10.10 --report
python -m vapt_framework.cli.main history --limit 10
python -m vapt_framework.cli.main show <scan_id>
python -m vapt_framework.cli.main report <scan_id>
python -m vapt_framework.cli.main db init
```

`report` loads a **stored** scan. `--report` on `scan` writes HTML from the **current** in-memory results without scanning again.

Output example: `reports/vapt_report_<scan_id>.html`

PDF export is **not** implemented.

## Testing

```bash
pytest
```

Default tests mock Nmap, HTTP, and MySQL. They do not use the internet.

## Authorized use

Only scan systems you are explicitly authorized to assess. The CLI prints this warning on every `scan`.

## Limitations

Conservative detection only (error-based SQLi, reflected-marker XSS, heuristic path probes). No exploitation, no authenticated scanning, no browser/DOM XSS, no CVE feeds, no dashboard. A clean report is not proof the target is secure.

See [docs/phase8.md](docs/phase8.md).
