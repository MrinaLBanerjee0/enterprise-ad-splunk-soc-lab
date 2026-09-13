# DET-001 v1 — Suspicious PowerShell

## Purpose
Detect PowerShell Script Block Logging events containing strings commonly associated with suspicious execution or download activity.

## Data source
- `Microsoft-Windows-PowerShell/Operational`
- Event ID `4104`
- Splunk index: `soc_windows`

## Detection logic
The v1 rule extracted `ScriptBlockText`, normalized it to lowercase, and matched broad keywords including `encodedcommand`, `frombase64string`, `invoke-expression`, `iex`, `downloadstring`, and `invoke-webrequest`.

SPL: [`../spl/DET-001-v1.spl`](../spl/DET-001-v1.spl)

## Validation
During the Sep 10 controlled lab activity, the command below matched the rule:

```powershell
Write-Output "LAB-INC-SEP10 Invoke-WebRequest"
```

The command only printed a string. It did not perform an actual web request. This demonstrated that keyword-only matching could produce a benign false-positive security interpretation.

## Limitations
- Broad keyword matching can trigger on harmless strings or demonstrations.
- A match does not prove network activity, payload download, or compromise.
- XML-rendered PowerShell events require extraction of `ScriptBlockText` from the raw event.

## Final state
Disabled after DET-001 v2 was validated.

## Historical query note
The SPL file in this repository is the version documented in the project conversation. The original Splunk saved-alert export was not retained separately, so it should not be described as a byte-for-byte export of the original saved object.
