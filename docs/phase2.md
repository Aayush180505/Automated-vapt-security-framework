# Phase 2 — Nmap / Service Discovery

## Why Nmap is used

Nmap is the standard, locally installed tool for authorized port and service discovery. This framework does not reimplement a scanner. It runs a **conservative** Nmap command, reads **XML**, and turns the result into Python objects for later pipeline stages.

Phase 2 does not exploit services, load NSE vulnerability scripts, or crawl HTTP.

## Nmap adapter architecture

```text
CLI
  → recon.engine (require_nmap / discover_services)
    → NmapAdapter
      → runner.find_nmap_executable / build_nmap_command / run_nmap
      → parser.parse_nmap_xml
      → models (NmapScanResult, HostResult, PortResult, ServiceInfo)
  → ScanContext.discovery_results
  → CLI summary (cli/output.py)
```

The CLI never calls `subprocess`. The runner never formats tables. The parser never executes Nmap.

| Module | Responsibility |
| --- | --- |
| `adapters/nmap/runner.py` | PATH lookup, allowlisted argv, `subprocess.run(..., shell=False)` |
| `adapters/nmap/parser.py` | Nmap XML → models (`defusedxml`) |
| `adapters/nmap/models.py` | Frozen dataclasses independent of XML |
| `adapters/nmap/adapter.py` | Single `discover(target, timeout)` API |
| `recon/engine.py` | Thin facade so CLI depends on recon, not XML |

## Runner

1. `shutil.which("nmap")` (and `nmap.exe` on Windows)
2. `build_nmap_command(host, nmap_executable=..., port=optional)` → `list[str]`
3. Default command: `nmap -sV -T3 -oX - <host>`
4. If the validated target has an explicit port, `-p <port>` is added
5. `subprocess.run` with capture, timeout from `Settings.nmap_timeout` (`VAPT_NMAP_TIMEOUT`, default 120)
6. XML is taken from **stdout** (`-oX -`). No temp files, so nothing is left on disk

Forbidden: `shell=True`, `os.system()`, `-A`, NSE `--script`.

The host argument is the already-validated `Target.hostname`. Values starting with `-` are rejected so they cannot be treated as flags.

## XML parser

Human-readable Nmap text is unstable (columns, versions, localization). XML is a documented schema (`host`, `address`, `ports/port`, `state`, `service`).

`defusedxml` is used so untrusted XML cannot expand entities. Nmap’s `<!DOCTYPE nmaprun>` is stripped before parse because DTDs are not required to read the tree.

Missing `product` / `version` / entire `service` nodes become `None`; display uses `-`.

## Nmap models

`NmapScanResult` → `HostResult` → `PortResult` → optional `ServiceInfo`.

The rest of the app should treat these as “discovered services,” not “XML nodes.”

## Service discovery flow

1. Validate/normalize target (Phase 1)
2. Confirm Nmap is on PATH
3. Execute conservative `-sV` scan
4. Parse XML
5. Attach `NmapScanResult` to `ScanContext.discovery_results`
6. Print open-port summary

Service names come from Nmap (`ssh`, `http`, `mysql`, …). There is no local IANA database.

## ScanContext integration

`ScanContext` gained an optional `discovery_results` field. Core does not import the adapter at runtime (`TYPE_CHECKING` only). Omit the field and Phase 1-style construction still works.

## CLI flow

Authorization warning → validate → “Checking Nmap” → discover → table → “Service discovery complete.”

Errors (`NmapNotFoundError`, `NmapExecutionError`, `NmapParseError`, `TargetValidationError`) print `Error: …` to stderr without a traceback.

## Error handling

| Situation | Result |
| --- | --- |
| Nmap missing | `NmapNotFoundError` — install/PATH message |
| Timeout | `NmapExecutionError` — timed out |
| Non-zero exit without XML | `NmapExecutionError` — discovery failed |
| Empty/malformed XML | `NmapParseError` |
| Invalid target | `TargetValidationError` prefixed with `Invalid target:` |

## Testing strategy

Pytest mocks `shutil.which` and `subprocess.run`. Parser tests use `tests/fixtures/*.xml` (lab-style `10.10.10.10`, never contacted). CLI tests inject fake `discover_services` results. Nmap does not need to be installed for `pytest`.

## Security considerations

- Authorized targets only; warning is mandatory
- Argument lists, not shell strings
- No NSE vuln scripts, no `-A`, no evasion flags
- No credentials in logs or commands
- XML parsed with defusedxml
- Timeout so a hung scan cannot run forever

## Phase 3

HTTP/HTTPS detection and a scoped HTTP client / web-application identification, still without a full crawler or vulnerability plugins unless that phase’s spec says otherwise.
