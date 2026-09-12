# Phase 7 — MySQL Persistence and Scan History

## 1. Objective

Persist completed assessments (findings, evidence, risk, services, target) so they can be listed and reopened later. Reporting is **not** in this phase.

## 2. Database architecture

```
Core models (ScanContext, Finding)
        ↓
ScanStorageService / persist_scan()
        ↓
ScanRepository  (parameterized SQL)
        ↓
Database        (mysql-connector-python)
        ↓
MySQL
```

The CLI never embeds SQL. Scanners never import storage. SQLAlchemy is not used; the architecture already referenced a MySQL URL and this phase uses **mysql-connector-python** with bound parameters (`%s`).

## 3. Schema

Tables are created by `python -m vapt_framework.cli.main db init` (`CREATE TABLE IF NOT EXISTS`). Version `1` is stored in `schema_version`.

## 4–5. Tables and relationships

```
targets 1──∞ scans 1──∞ services
                 └──∞ findings 1──1 risk_assessments
                                 └──∞ evidence
```

Deleting a scan row cascades to services, findings, evidence, and risk rows. Findings are unique per `(scan_id, fingerprint)` inside one scan, not globally.

## 6. Repository layer

`ScanRepository` writes a scan in one transaction: target → scan → services → findings/evidence/risk → summary update.

## 7. Persistence service

`ScanStorageService` is the CLI-facing API. `persist_scan(context, settings)` never raises into the scan command: failures become a warning outcome.

## 8. Transactions

`Database.transaction()` commits on success and **rolls back** on any exception so a failed findings insert does not leave a half-written scan.

## 9. Error handling

`DatabaseConnectionError`, `DatabaseMigrationError`, and `DatabasePersistenceError` extend `DatabaseError` → `VAPTFrameworkError`. The CLI prints `Error: …` without a traceback. Connection errors mention env var **names**, not password values.

## 10. Scan lifecycle

`ScanContext.scan_id` is a UUID assigned in memory. Status is `running` until recon finishes, then `completed`. A persistence failure does **not** change that status to `failed`.

## 11–12. History and retrieval

`history [--limit]` lists `scan_id`, target, date, finding count (no finding bodies).  
`show <scan_id>` loads services, risk totals, and prioritized finding titles.

## 13. CLI commands

| Command | Role |
| --- | --- |
| `scan --target …` | Assess; persist only if `VAPT_DATABASE_ENABLED=true` |
| `db init` | Create tables (needs a reachable MySQL) |
| `history [--limit N]` | Recent scans |
| `show <scan_id>` | One saved scan |

## 14. Secret-handling

No passwords, tokens, cookies, or Authorization headers are stored. Evidence persists description, URL, method, status, and a truncated excerpt (512 chars). HTTP header maps are not written.

SQL never interpolates target, URL, or title into the statement string.

## 15. Testing

Unit tests use `FakeDatabase`. Normal `pytest` does **not** require MySQL.

## 16. Optional integration testing

If a local server exists, you may run a manual `db init` + `scan` with `VAPT_DATABASE_ENABLED=true`. There is no default pytest dependency on that server. Tests marked `integration` are reserved for that optional path.

## 17. Limitations

- No HTML/PDF reports
- No dashboard or multi-user auth
- No automatic database *server* creation (the schema is created inside an existing database)
- History filtering is limit-only

## 18. Phase 8

Reporting should **read** stored scans via `ScanStorageService.get_scan` / finding rows (title, severity, risk_score, evidence excerpt) instead of re-running scanners. Phase 8 is not implemented here.
