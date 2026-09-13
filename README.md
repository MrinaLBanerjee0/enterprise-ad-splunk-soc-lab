# Enterprise Active Directory + Splunk SOC Lab

A hands-on SOC lab built to practice Windows and Active Directory monitoring, Splunk detection engineering, alert triage, cross-host correlation, process-tree analysis, threat hunting, and detection tuning.

The project uses a small Windows domain with two workstations, a domain controller, and a dedicated Splunk server. The main case study is a controlled Sep 10 activity sequence that generated three detections and was then investigated and tuned using the telemetry collected in the lab.

## Lab architecture

| System | Role | IP |
|---|---|---|
| `DC01` | Windows Server 2022, Active Directory Domain Services, DNS | `10.10.10.10` |
| `SPLUNK01` | Ubuntu Server, Splunk Enterprise | `10.10.10.20` |
| `WIN11-01` | Windows 11 domain workstation | `10.10.10.101` |
| `WIN11-02` | Windows 11 domain workstation | `10.10.10.102` |

- Domain: `corp.soclab.test`
- NetBIOS: `CORP`
- Internal VirtualBox network: `SOCLAB`
- Splunk index: `soc_windows`
- Splunk receiving port: `9997`

## Telemetry collected

The Windows systems forward telemetry to Splunk with the Universal Forwarder. The lab collected:

- Windows Application, Security, and System logs
- PowerShell Operational logs with Script Block Logging (`4104`)
- Sysmon Operational logs, including process creation (`Event ID 1`)
- Successful authentication events (`4624`)
- Active Directory group-membership events (`4728`, `4729`)
- Kerberos authentication events (`4768`, `4769`)

The sanitized forwarder input configuration used for the project is available in [`configs/splunk-forwarder-inputs.conf`](configs/splunk-forwarder-inputs.conf).

## Detection engineering

| Detection | Purpose | Final state |
|---|---|---|
| [DET-001 v1](detections/DET-001-Suspicious-PowerShell-v1.md) | Broad suspicious PowerShell keyword matching | Disabled |
| [DET-001 v2](detections/DET-001-Suspicious-PowerShell-v2.md) | Tuned suspicious PowerShell detection | Enabled |
| [DET-002 v1](detections/DET-002-AD-Group-Membership-v1.md) | AD security-group membership changes | Enabled |
| [DET-003 v1](detections/DET-003-Cross-Host-Authentication-v1.md) | Broad cross-host authentication correlation | Disabled |
| [DET-003 v2](detections/DET-003-Cross-Host-Authentication-v2.md) | Tuned human-user cross-host correlation | Enabled |

The corresponding SPL searches are stored in [`spl/`](spl/).

## Sep 10 controlled activity

The main investigation scenario was intentionally generated inside the lab so I could follow the alert-to-investigation workflow instead of only testing searches in isolation.

The sequence included:

1. `CORP\Mr.Banerjee` authenticated on `WIN11-01`.
2. PowerShell Event ID `4104` recorded the controlled marker `Write-Output "LAB-INC-SEP10 Invoke-WebRequest"`.
3. `Administrator` added `Mr.Banerjee` to the `SOC-Analysts` group on `DC01`.
4. `Mr.Banerjee` authenticated on `WIN11-02`.
5. DC01 Kerberos `4768`/`4769` events corroborated authentication activity from the two workstation IP addresses.
6. The group membership was later removed as cleanup.

All three detections fired during the exercise. The important result was not simply that the alerts worked, but that they required different analyst conclusions.

The complete investigation is documented in [`investigations/sep10-incident-investigation.md`](investigations/sep10-incident-investigation.md).

## Investigation findings

### PowerShell

DET-001 v1 fired because the test string contained `Invoke-WebRequest`. The command only printed text and did not execute a web request. I treated this as a benign false-positive security interpretation and used it as the reason to tune the rule.

DET-001 v2 was then tested in both directions: the old benign marker no longer matched, while a controlled `FromBase64String` test did match.

### Active Directory group change

DET-002 correctly detected the real addition and removal of `Mr.Banerjee` from `SOC-Analysts`. The security event was real, but the action was authorized lab activity. This was a useful example of a true detection condition that still required business/context validation before calling it malicious.

### Cross-host authentication

DET-003 v1 detected `Mr.Banerjee` on both workstations, but the initial rule was too broad and produced noise from account-field handling and overlapping alert windows.

DET-003 v2 extracts the actual new-logon user, filters service and machine identities, keeps relevant interactive-style logon types, and requires the same user to appear on both workstations within 15 minutes. Duplicate suppression/throttling was also added.

## Process-tree analysis

During controlled validation on `WIN11-01`, Sysmon process telemetry showed the relationship:

```text
CORP\Mr.Banerjee
└── powershell.exe
    └── cmd.exe
        └── conhost.exe
```

This was used to practice parent/child process analysis rather than judging a process only by its filename. The observed `cmd.exe` SHA-256 was:

```text
8DD1EBB0B969370C70A5EE7F7EE347949AA7046AA5E1A33FCD7B1E9415B21FC3
```

The executable was consistent with legitimate Windows `cmd.exe`, but the investigation did not treat a legitimate hash as proof that the surrounding activity was benign.

## Independent threat hunt

After reviewing the alerts, I searched the collected telemetry for similar activity outside the original alert results, including:

- similar PowerShell activity on other hosts
- additional PowerShell-to-`cmd.exe` process chains
- other unexplained security-group changes
- other human users showing the same cross-host authentication pattern

No additional matching suspicious activity was identified in the collected telemetry during the investigated time window.

## MITRE ATT&CK mapping

Only techniques directly supported by the observed lab activity are included:

- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1098.007` — Additional Local or Domain Groups

The cross-host login was not treated as proof of malicious lateral movement.

## What I learned from tuning

This project reinforced that an alert is a starting point, not a conclusion. DET-001 showed how a keyword can match without the suspicious behavior actually happening. DET-002 showed that a technically correct alert can still be authorized activity. DET-003 showed how correlation logic can become noisy when identity fields and time windows are too broad.

The v1 and v2 searches are both kept in the repository so the detection changes are visible instead of only showing the final rule.

## Known limitations

- Sysmon Event ID `3` network-connect telemetry was not enabled during the Sep 10 activity. Network activity therefore could not be conclusively assessed from Sysmon for that incident window.
- This was a controlled home-lab scenario. No malicious compromise was confirmed.
- The DET-001 v1 and DET-002 v1 SPL files reflect the versions documented in the project conversation; the original Splunk saved-alert exports were not retained separately.
- Detection logic is lab-specific and would require additional baseline and tuning before production use.

## Repository structure

```text
spl/             Splunk detection searches
detections/      Detection logic, validation, and tuning notes
configs/         Sanitized Splunk Universal Forwarder input configuration
investigations/  Analyst investigation reports
```

Screenshots are intentionally not included in the repository at this stage.
