# Phase 1 — Foundation

## Why this framework exists

The Automated VAPT & Security Assessment Framework is a modular Python CLI meant to help authorized testers run repeatable assessments against systems they own or have permission to test (local vulnerable apps, CTFs, HTB/Academy labs).

It is an **orchestration and reporting** codebase, not an exploit kit. Phase 1 builds the skeleton so later stages (recon, enumeration, plugins, storage, reports) can be added without rewriting the core.

## Phase 1 objectives

- Installable/importable package layout matching the approved architecture
- Target validation and normalization **without network requests**
- Configuration and logging
- CLI that fails cleanly on invalid input
- Core dataclasses and severity labels
- Tests and documentation that do not claim unimplemented features

## Project structure

```
vapt-framework/
├── README.md
├── requirements.txt
├── pytest.ini
├── .gitignore
├── .env.example
├── docs/phase1.md
├── tests/
│   ├── test_target.py
│   ├── test_settings.py
│   └── test_cli.py
└── vapt_framework/
    ├── cli/main.py
    ├── config/settings.py
    ├── core/          # models, enums, exceptions, target
    ├── utils/logging.py
    ├── recon/         # stub
    ├── adapters/      # stub (nmap, http)
    ├── enumeration/   # stub
    ├── assessment/    # stub
    ├── scanners/      # stub (headers, information_disclosure)
    ├── findings/      # stub
    ├── storage/       # stub
    └── reporting/     # stub
```

`core` does not import CLI, recon, scanners, storage, or reporting.

## Target model

`vapt_framework.core.target.Target` is a frozen dataclass:

| Field | Meaning |
| --- | --- |
| `raw_input` | String supplied by the operator |
| `normalized` | Canonical form used by later stages |
| `scheme` | `http`, `https`, or `None` for host/IP-only targets |
| `hostname` | Lowercased host or IP literal |
| `port` | Explicit port, if any |
| `ip_address` | Set when the host is an IP address |
| `path` | URL path (and query if present) |
| `is_valid` | Always `True` for returned instances (invalid input raises) |

`parse_target()` accepts HTTP(S) URLs, `host:port`, hostnames, and IPv4 addresses such as `10.10.10.10`. It does not resolve DNS or open sockets. Invalid input raises `TargetValidationError`. Credentials in URLs are rejected.

## ScanContext

`ScanContext` (`core/models.py`) binds a validated `Target` to a run, with `created_at` (UTC) and a default `profile` of `"standard"`. Later phases will attach recon data and findings to the pipeline without changing this basic shape.

## Finding model

`Finding` is a dataclass only: title, description, `Severity`, optional confidence, target, evidence, remediation, and scanner/plugin name. No scanner produces findings in Phase 1.

## Severity

`Severity` (`core/enums.py`): `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. No weighted risk algorithm yet.

## Configuration

`Settings.from_env()` reads:

- `VAPT_LOG_LEVEL`
- `VAPT_DATABASE_URL` (placeholder; unused)
- `VAPT_REQUEST_TIMEOUT`
- `VAPT_USER_AGENT`
- `VAPT_REPORT_DIR`
- `VAPT_SCAN_OUTPUT_DIR`

See `.env.example`. Phase 1 never connects to MySQL.

## Logging

`configure_logging()` / `get_logger()` in `utils/logging.py` write to stderr as:

```text
2026-09-12 22:00:00 | INFO | vapt_framework.cli | Starting scan
```

## CLI flow

```text
python -m vapt_framework.cli.main scan --target <TARGET>
```

1. Print product banner and authorization warning
2. Load settings and configure logging
3. `parse_target()`
4. Construct `ScanContext`
5. Print normalized target and exit `0`

Expected user errors (invalid target, bad config) print `Error: ...` to stderr and exit `2` without a traceback. `version` prints `0.1.0`. No HTTP or Nmap.

## Testing strategy

`pytest` with `pythonpath = .`. Coverage for valid/invalid targets, normalization, severity, settings defaults/env, CLI help/version/scan. Mocks are limited to environment variables (`monkeypatch`). No live network.

## Phase 2 (not started)

Intended next work, consistent with the architecture document:

- Scan orchestrator skeleton and pipeline stages
- Scope validation helpers
- HTTP client adapter **without** crawling or scanners
- Possibly config file loading (YAML) when that phase needs it

Nmap execution, crawlers, vulnerability plugins, MySQL, and reports remain after Phase 2.
