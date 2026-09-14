# Evidence Index

This folder contains selected screenshots captured from the Project 2 lab. Each image is mapped to the claim it supports and the main boundary of that evidence.

## Architecture

| Evidence | What it supports | Boundary |
|---|---|---|
| [`architecture/enterprise-ad-splunk-soc-lab-overview.svg`](architecture/enterprise-ad-splunk-soc-lab-overview.svg) | Evidence-backed visual summary of the lab architecture, telemetry flow, Sep 10 controlled incident timeline, separate process/hash validation, and final detection states | This is a summary graphic assembled from the documented project evidence; the underlying screenshots and investigation files remain the primary proof |
| [`architecture/lab-vm-inventory.png`](architecture/lab-vm-inventory.png) | VirtualBox lab contains `DC01`, the Splunk VM, `WIN11-01`, and `WIN11-02` | VM presence does not by itself prove service health or network connectivity |
| [`architecture/splunk-host-ingestion.png`](architecture/splunk-host-ingestion.png) | `soc_windows` contains events from `DC01`, `WIN11-01`, and `WIN11-02` | Host counts are evidence of ingestion, not complete telemetry coverage |

## Incident evidence

| Evidence | What it supports | Boundary |
|---|---|---|
| [`incident/powershell-4104-marker.png`](incident/powershell-4104-marker.png) | `WIN11-01` PowerShell Event ID `4104` recorded `Write-Output "LAB-INC-SEP10 Invoke-WebRequest"` at the documented Sep 10 time | The event shows the string was logged; it does not show that an actual web request occurred |
| [`incident/ad-group-add-4728.png`](incident/ad-group-add-4728.png) | `Administrator` added `Mr.Banerjee` to `SOC-Analysts` in Event ID `4728` | The event proves the group change, not malicious intent |
| [`incident/cross-host-authentication.png`](incident/cross-host-authentication.png) | `Mr.Banerjee` had successful `4624` logons on both `WIN11-01` and `WIN11-02` | Cross-host authentication does not by itself prove lateral movement or compromise |
| [`incident/kerberos-correlation.png`](incident/kerberos-correlation.png) | `DC01` recorded `4768`/`4769` activity associated with `10.10.10.101` and `10.10.10.102` | Kerberos activity corroborates authentication context; it does not establish malicious intent |
| [`incident/cmd-hash-splunk.png`](incident/cmd-hash-splunk.png) | Sysmon telemetry recorded the SHA-256 associated with `C:\Windows\System32\cmd.exe` during the separate process-tree validation | The hash identifies the observed binary; it does not determine whether the surrounding activity was benign |
| [`incident/cmd-hash-enrichment.png`](incident/cmd-hash-enrichment.png) | VirusTotal showed `0/71` security vendors flagging the hash at the time of lookup | Reputation is point-in-time external enrichment and does not prove that the activity was safe |

## Threat-hunt evidence

| Evidence | What it supports | Boundary |
|---|---|---|
| [`threat-hunt/threat-hunt-powershell-cmd.png`](threat-hunt/threat-hunt-powershell-cmd.png) | The investigated Sysmon window produced one PowerShell-to-`cmd.exe` process-chain match on `WIN11-01` for `CORP\Mr.Banerjee` | The result only describes telemetry available in the searched window |
| [`threat-hunt/ad-group-membership-hunt.png`](threat-hunt/ad-group-membership-hunt.png) | Group-membership activity in the investigated window was reviewed for the known add/remove events | The hunt does not prove no uncollected or out-of-window group changes occurred |

## Tuning and validation evidence

| Evidence | What it supports | Boundary |
|---|---|---|
| [`tuning/det001-v2-negative-retest.png`](tuning/det001-v2-negative-retest.png) | DET-001 v2 returned `0` results over the window containing the original benign marker | A zero result is specific to the tested query and time range |
| [`tuning/det001-v2-positive-validation.png`](tuning/det001-v2-positive-validation.png) | DET-001 v2 returned a controlled `FromBase64String("QQ==")` match | The test validates one retained pattern; it does not prove complete PowerShell detection coverage |
| [`tuning/det003-v2-validation.png`](tuning/det003-v2-validation.png) | DET-003 v2 correlated `Mr.Banerjee` across `WIN11-01` and `WIN11-02` within the 15-minute condition | The result proves the correlation condition, not malicious lateral movement |
| [`tuning/final-alert-state.png`](tuning/final-alert-state.png) | Final saved-alert state: DET-001 v1 disabled, DET-001 v2 enabled, DET-002 v1 enabled, DET-003 v1 disabled, DET-003 v2 enabled | Current configuration does not preserve the expired Sep 10 Triggered Alerts UI history |

## Retention limitation

Splunk Triggered Alerts entries were retained for only 24 hours in this lab. The Sep 10 Triggered Alerts UI history was therefore no longer available when the final evidence set was collected. The repository instead preserves the underlying telemetry, historical validation searches, tuning results, and final alert configuration.

[Return to project README](../README.md) · [Read the Sep 10 investigation](../investigations/sep10-incident-investigation.md) · [Read the tuning report](../investigations/detection-tuning-report.md)
