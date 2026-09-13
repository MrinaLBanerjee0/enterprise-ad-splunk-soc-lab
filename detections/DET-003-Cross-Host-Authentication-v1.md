# DET-003 v1 — Cross-Host Authentication

## Purpose
Identify an account authenticating across both Windows workstations during the same search window.

## Data source
- Windows Security log
- Event ID `4624`
- Hosts: `WIN11-01`, `WIN11-02`
- Splunk index: `soc_windows`

## Detection logic
The v1 rule grouped successful logons by `Account_Name`, excluded `SYSTEM` and machine accounts ending in `$`, and alerted when the same account appeared on more than one workstation.

SPL: [`../spl/DET-003-v1.spl`](../spl/DET-003-v1.spl)

## Validation
The Sep 10 controlled activity produced the expected cross-host condition for `Mr.Banerjee` on `WIN11-01` and `WIN11-02`.

## Problems found
- `Account_Name` was too broad for reliable human-user correlation in the raw Windows event structure.
- Service and desktop-session identities created unnecessary noise.
- The rule did not constrain relevant interactive logon types.
- Overlapping scheduled windows caused repeated alerting.
- A cross-host logon by itself is not proof of lateral movement.

## Final state
Disabled after DET-003 v2 was validated.
