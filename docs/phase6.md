# Phase 6 — Finding Intelligence and Risk Engine

## 1. Objective

Turn validated, deduplicated scanner findings into **explainable, prioritized** results.

Phase 6 does **not** add scanners, exploitation, persistence, or reports.

Pipeline:

```
Plugin → Finding → validate → dedupe → RiskEngine → FindingPrioritizer → AssessmentSummary
```

## 2. Finding normalization

`normalize_finding()` trims titles, descriptions, scanner names, categories, URLs, and parameter names. **Evidence objects are not rewritten.** Missing optional fields stay `None`. Invalid severity/confidence is not invented; those findings never pass `validate_finding`.

## 3. Severity

How serious the issue **would be if present** (`INFO` … `CRITICAL`). Scanners still set this. The risk engine never overwrites it.

## 4. Confidence

How certain the observation is (`LOW`, `MEDIUM`, `HIGH`). Separate from severity.

## 5. Risk score

A number in **0–100** used for prioritization. It is **not** CVSS and **not** a proof of exploitability.

## 6. Risk formula

Architecture documents did not define weights. Phase 6 uses:

**Severity weight**

| Severity | Weight |
| --- | --- |
| INFO | 10 |
| LOW | 25 |
| MEDIUM | 50 |
| HIGH | 75 |
| CRITICAL | 100 |

**Confidence multiplier**

| Confidence | Multiplier |
| --- | --- |
| LOW | 0.50 |
| MEDIUM | 0.75 |
| HIGH | 1.00 |

```
risk_score = clamp(severity_weight × confidence_multiplier, 0, 100)
```

The product is deterministic. No randomness, no ML, no plugin-name branches.

## 7. Risk bands

Bands describe the **score**, not the original severity:

| Score | Band |
| --- | --- |
| 0–19 | INFO |
| 20–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Example: severity HIGH (75) × confidence MEDIUM (0.75) = **56.25** → band **MEDIUM**, severity remains HIGH.

## 8. Priority

| Score | Priority |
| --- | --- |
| 90–100 | P1 |
| 70–89 | P2 |
| 50–69 | P3 |
| 30–49 | P4 |
| 0–29 | P5 |

High-priority count in summaries is **P1 + P2**.

## 9. Risk explanation

Each assessment includes a sentence and the arithmetic, for example:

```
High severity finding with medium confidence.
75.0 × 0.75 = 56.25
```

## 10. Finding prioritization

`FindingPrioritizer` scores every finding, then sorts by:

1. Highest risk score
2. Highest original severity
3. Highest confidence
4. Affected URL (case-insensitive)
5. Scanner name
6. Fingerprint

Insertion order is not used.

## 11. Finding statistics

`AssessmentSummary` counts (on the **deduplicated** list):

- totals by original severity
- totals by risk band
- totals by priority
- average and maximum risk
- high-priority count (P1+P2)
- distinct scanner names

## 12. AssessmentResult integration

After plugins run, the engine sets `findings` (ranked) and `summary`. Scanners never see `RiskEngine`.

## 13. ScanContext integration

`ScanContext.assessment_summary` holds the same summary for CLI and, later, storage. No database fields.

## 14. CLI output

After the finding list: Risk Assessment (distributions, average/max), then prioritized cards with URL, parameter, severity, confidence, score, band, priority, reason, and calculation.

Empty scans print that no findings were identified **and** that this does not mean the target is secure, plus “No findings available for risk scoring.”

## 15. Testing strategy

Unit tests cover formula cases, band/priority boundaries, clamp, sorting, duplicates, empty summaries, engine integration, passive vs active scoring, plugin-failure isolation, and CLI text. No network.

## 16. Limitations

- No asset value, exposure, or CVSS
- No CVE lookup
- Confidence is scanner-assigned, not Bayesian
- Risk is not exploitability

**Severity ≠ Confidence ≠ Risk.**

## 17. Why risk is centralized

A new scanner should emit a `Finding` only. One formula keeps ranking consistent and avoids “if scanner == sql-injection” special cases.

## 18. Phase 7

Phase 7 is expected to persist `Finding` + risk fields + `AssessmentSummary` in MySQL (scan history). Reporting (Phase 8) can render the same numbers. Phase 7 is **not** implemented here.
