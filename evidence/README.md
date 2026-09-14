# Evidence Gallery

I kept the main screenshots on one page so a reviewer can see the proof without digging through folders. The reports explain the investigation in more detail; this page is mainly for quick visual checking.

## Project overview

![Verified Enterprise AD + Splunk SOC Lab overview](architecture/enterprise-ad-splunk-soc-lab-overview.svg)

This diagram summarizes the lab architecture, telemetry flow, Sep 10 timeline, separate process/hash validation, and final detection states. It is a summary built from the project records below, not a replacement for the original screenshots.

## Architecture and ingestion

### VirtualBox lab inventory

![VirtualBox lab inventory](architecture/lab-vm-inventory.png)

This shows the four lab systems: `DC01`, the Splunk VM, `WIN11-01`, and `WIN11-02`. It confirms the VMs existed, but by itself it does not prove that every service was healthy or that connectivity was working at that exact moment.

### Splunk host ingestion

![Splunk host ingestion](architecture/splunk-host-ingestion.png)

This shows events from `DC01`, `WIN11-01`, and `WIN11-02` in `soc_windows`. I use it as proof that Splunk was receiving data from those hosts, not as proof that every possible log source was being collected.

## Sep 10 incident evidence

### PowerShell Event ID 4104

![PowerShell 4104 marker](incident/powershell-4104-marker.png)

`WIN11-01` logged the controlled Script Block `Write-Output "LAB-INC-SEP10 Invoke-WebRequest"` at the documented Sep 10 time. The screenshot proves the text was logged; the command only printed the string and did not perform a web request.

### Active Directory group addition — Event ID 4728

![AD group addition 4728](incident/ad-group-add-4728.png)

This is the `4728` event where `Administrator` added `Mr.Banerjee` to `SOC-Analysts`. The event confirms the change happened. Whether the action was malicious or authorized had to be decided from the investigation context.

### Cross-host authentication

![Cross-host authentication](incident/cross-host-authentication.png)

This shows successful `4624` logons for `Mr.Banerjee` on both `WIN11-01` and `WIN11-02`. That was enough to satisfy the cross-host condition, but not enough to call it lateral movement or account compromise.

### Kerberos correlation

![Kerberos correlation](incident/kerberos-correlation.png)

`DC01` recorded `4768`/`4769` activity associated with `10.10.10.101` and `10.10.10.102`. I used these events to support the workstation authentication timeline; they do not make the activity malicious by themselves.

## Separate process and hash validation

### Sysmon process/hash evidence

![Sysmon cmd hash](incident/cmd-hash-splunk.png)

During a later controlled process-tree test, Sysmon recorded the SHA-256 for `C:\Windows\System32\cmd.exe`. This was useful for practicing process and hash analysis, but the hash alone cannot tell whether the surrounding activity was safe.

### VirusTotal enrichment

![VirusTotal hash enrichment](incident/cmd-hash-enrichment.png)

At the time I checked it, VirusTotal showed `0/71` security vendors flagging the hash. I treated that as one piece of enrichment only; a clean reputation result does not prove that activity using the binary was benign.

## Threat-hunt evidence

### PowerShell to cmd.exe process-chain hunt

![Threat hunt PowerShell to cmd](threat-hunt/threat-hunt-powershell-cmd.png)

The Sysmon hunt returned one relevant PowerShell-to-`cmd.exe` process-chain match on `WIN11-01` for `CORP\Mr.Banerjee`. That result only describes the time range and telemetry I actually searched.

### AD group-membership hunt

![AD group membership hunt](threat-hunt/ad-group-membership-hunt.png)

I reviewed the group-membership events in the investigated window and found the known add/remove activity. This does not rule out changes outside the search window or anything that was not collected.

## Detection tuning and validation evidence

### DET-001 v2 — negative retest

![DET-001 v2 negative retest](tuning/det001-v2-negative-retest.png)

When I reran DET-001 v2 over the window containing the original benign marker, it returned `0` results. That is the expected result for this specific retest, not a claim that the rule has no false negatives in general.

### DET-001 v2 — positive validation

![DET-001 v2 positive validation](tuning/det001-v2-positive-validation.png)

The controlled `FromBase64String("QQ==")` test still matched DET-001 v2. I used this to check that the tuning removed the known benign case without removing every retained suspicious pattern.

### DET-003 v2 — historical validation

![DET-003 v2 validation](tuning/det003-v2-validation.png)

DET-003 v2 correlated `Mr.Banerjee` across `WIN11-01` and `WIN11-02` inside the 15-minute condition. This validates the correlation logic; it still does not prove malicious lateral movement.

### Final saved-alert state

![Final alert state](tuning/final-alert-state.png)

The final state shown here is:

- DET-001 v1 — disabled
- DET-001 v2 — enabled
- DET-002 v1 — enabled
- DET-003 v1 — disabled
- DET-003 v2 — enabled

This screenshot shows the final configuration, not the original Sep 10 Triggered Alerts history.

## Retention limitation

In this lab, Splunk kept Triggered Alerts entries for only 24 hours. By the time I collected the final evidence set, the Sep 10 alert-list history had expired. I therefore kept the underlying events, later validation results, tuning evidence, and final saved-alert state instead.

If I run another validation later, I will label those screenshots as a later retest rather than presenting them as historical Sep 10 alert proof.

[Return to project README](../README.md) · [Read the Sep 10 investigation](../investigations/sep10-incident-investigation.md) · [Read the tuning report](../investigations/detection-tuning-report.md)
