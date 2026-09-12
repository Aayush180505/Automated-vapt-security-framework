# Phase 4 — Security Assessment Engine

## 1. Objective

Add a **plugin-based assessment engine** that turns Phase 3 HTTP metadata into structured findings. Current plugins are **passive**. They do not prove exploitability.

## 2. Assessment engine

`AssessmentEngine.assess(AssessmentContext)` loads plugins from a registry, skips those that do not apply, runs `check()`, validates findings, deduplicates by fingerprint, and returns `AssessmentResult`. It contains **no** header or disclosure rules.

## 3. Plugin architecture

`SecurityPlugin` (`scanners/base.py`) defines `name`, `description`, `version`, `supported_types`, `applies_to()`, and `check()`. Phase 5 scanners implement the same class.

## 4. Plugin lifecycle

Loaded → `applies_to` → `check` → validate → dedupe → `ScanContext.findings`.

Plugins return `list[Finding]`. They must not drive the CLI or database.

## 5. Plugin registry

`PluginRegistry.register` / `get_all`. Duplicate names raise `PluginRegistryError`. `default_registry()` registers the two built-in plugins. No filesystem plugin scan.

## 6. Assessment context

`AssessmentContext` wraps `ScanContext` plus optional `Settings`. Plugins see `target`, HTTP services, and attack surfaces without importing the CLI.

## 7. Finding model

`Finding`: title, description, severity, confidence, plugin_name, fingerprint, category, finding_type, target, affected_url, evidence, remediation.

Fingerprint: `plugin|finding_type|url|parameter` (deterministic).

## 8. Evidence model

`Evidence`: short description, URL, method, status, filtered headers, optional excerpt. No cookie values, tokens, or full bodies.

## 9. Severity vs confidence

**Severity** = how serious the issue would be (INFO–CRITICAL).  
**Confidence** = how sure we are the observation is real (LOW/MEDIUM/HIGH).  
Missing a header is HIGH confidence that the header was absent, and typically LOW/INFO severity.

## 10. Validation

`validate_finding` drops incomplete output (empty title, bad enums, missing plugin/target/URL). The engine continues.

## 11. Deduplication

`deduplicate_findings` keeps the first item per fingerprint.

## 12. Security Headers plugin

Uses probed `HTTPService.response.headers`. Reports **absence** of CSP, HSTS (HTTPS only), X-Content-Type-Options, Referrer-Policy, Permissions-Policy (INFO), X-Frame-Options. Present headers (even weak) are not scored in Phase 4.

## 13. Information Disclosure plugin

Reports `Server` when it looks versioned (digit or `/`) and any `X-Powered-By`. Severity **INFO**. No extra requests.

## 14. ScanContext

Adds `findings` and `assessment_errors`. `run_scan` runs recon then the engine.

## 15. CLI flow

After the attack-surface summary: findings list, severity counts, plugin errors if any. Empty results include an explicit “not secure” disclaimer.

## 16. Error handling

One plugin exception becomes an error string; others still run.

## 17. Testing

Registry, engine skip/fail isolation, finding identity, both plugins, CLI summaries. Mocks only.

## 18. Security boundaries

No payloads, form POST, fuzzing, or brute force. Passive analysis of existing responses.

## 19. Limitations

No per-crawled-page header set (probe/base URL only). No header-value policy engine. No CVSS. No active vulns.

## 20. Phase 5

New `SecurityPlugin` subclasses (SQLi, XSS, …) register on `PluginRegistry`. Engine, Finding, CLI, and ScanContext stay as-is. Those plugins may send **controlled lab checks** later; they are not in Phase 4.
