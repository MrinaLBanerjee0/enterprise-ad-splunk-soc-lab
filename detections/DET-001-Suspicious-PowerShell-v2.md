# DET-001 v2 — Suspicious PowerShell

## Purpose
Reduce the false positives seen in DET-001 v1 by requiring stronger context around suspicious PowerShell behavior.

## Data source
- `Microsoft-Windows-PowerShell/Operational`
- Event ID `4104`
- Splunk index: `soc_windows`

## Detection logic
The tuned rule extracts `ScriptBlockText`, lowercases it, and looks for stronger patterns:

- `Invoke-WebRequest` or `DownloadString(` together with `http://` or `https://`
- `FromBase64String(`
- `Invoke-Expression`
- `iex(`

SPL: [`../spl/DET-001-v2.spl`](../spl/DET-001-v2.spl)

## Validation
Two controlled tests were used:

- The previous benign marker `Write-Output "LAB-INC-SEP10 Invoke-WebRequest"` no longer matched.
- A controlled `[System.Convert]::FromBase64String("QQ==")` test matched the tuned logic.

This showed that the rule could reject the known benign keyword-only event while still detecting a stronger suspicious pattern.

### Validation evidence
- [Negative retest — original benign marker excluded](../evidence/tuning/det001-v2-negative-retest.png)
- [Positive validation — FromBase64String match](../evidence/tuning/det001-v2-positive-validation.png)
- [Detection tuning report](../investigations/detection-tuning-report.md#4-det-001-retest)
- [Visual evidence gallery](../evidence/README.md#detection-tuning-and-validation-evidence)

## Limitations
- This is heuristic detection logic, not exhaustive PowerShell coverage.
- Obfuscated or alternative PowerShell techniques may not match.
- A match still requires analyst investigation and correlation with surrounding telemetry.

## Final state
Enabled.
