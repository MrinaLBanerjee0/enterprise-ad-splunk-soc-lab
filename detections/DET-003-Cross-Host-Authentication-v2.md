# DET-003 v2 — Cross-Host Authentication

## Purpose
Improve cross-host authentication detection by focusing on the actual new-logon user and reducing service-account noise.

## Data source
- Windows Security log
- Event ID `4624`
- Hosts: `WIN11-01`, `WIN11-02`
- Splunk index: `soc_windows`

## Detection logic
The tuned rule:

- extracts `TargetUser` from the `New Logon` section
- extracts `LogonType`
- removes `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, machine accounts, `DWM-*`, and `UMFD-*`
- keeps logon types `2`, `10`, and `11`
- requires the same user on more than one workstation
- requires the first and last matching events to be within 900 seconds

SPL: [`../spl/DET-003-v2.spl`](../spl/DET-003-v2.spl)

## Validation
Historical validation against the Sep 10 lab window identified `Mr.Banerjee` on both workstations:

- `WIN11-01` at approximately `14:07:53`
- `WIN11-02` at approximately `14:17:16`

The events were within the 15-minute correlation window. DC01 Kerberos events `4768` and `4769` were also used during the investigation to corroborate authentication from the two workstation IP addresses.

### Validation evidence
- [DET-003 v2 historical validation](../evidence/tuning/det003-v2-validation.png)
- [Cross-host authentication screenshot](../evidence/incident/cross-host-authentication.png)
- [Kerberos correlation screenshot](../evidence/incident/kerberos-correlation.png)
- [Final saved-alert state](../evidence/tuning/final-alert-state.png)
- [Detection tuning report](../investigations/detection-tuning-report.md#7-det-003-retest)
- [Visual evidence gallery](../evidence/README.md#det-003-v2--historical-validation)

## Alert tuning
The v2 alert was scheduled every 5 minutes over a 15-minute lookback and duplicate suppression/throttling was added to reduce repeated alerts for the same condition.

## Limitations
- Cross-host authentication can be legitimate administrative or user activity.
- A match does not by itself prove account compromise or lateral movement.
- Analyst correlation with Kerberos, endpoint process activity, and account context is still required.

## Final state
Enabled.
