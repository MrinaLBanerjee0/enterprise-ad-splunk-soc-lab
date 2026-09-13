# Detection Tuning Report

## 1. Purpose of Tuning

After the Sep 10 controlled incident, I reviewed how each Splunk detection behaved instead of treating a triggered alert as proof that the rule was already good enough.

The investigation showed three different outcomes:

- DET-001 v1 matched a benign PowerShell string because the logic was too broad.
- DET-002 v1 correctly detected a real Active Directory group-membership change and did not show a clear tuning problem in this lab.
- DET-003 v1 identified the intended cross-host condition, but the rule was noisy because the account field and correlation logic were too broad and the scheduled alert could repeat on overlapping windows.

The tuning goal was therefore not to reduce alerts at any cost. I wanted to make DET-001 and DET-003 more specific while preserving the behavior I still wanted to detect.

The final approach was:

`v1 behavior → identify noise/false positive → change logic → retest old behavior → run positive validation → keep v1 for comparison → enable v2`

### SPL learning note

The SPL used in this lab was built with guidance while I was learning Splunk search syntax. I implemented the searches in Splunk, tested them against my own telemetry, investigated the results, identified false positives and noisy behavior, worked through field-extraction problems, applied the tuned versions, and retested them. I do not present the SPL as independently authored from scratch.

---

## 2. DET-001 v1 Problem

DET-001 v1 monitored PowerShell Script Block Logging (`Event ID 4104`) and matched broad suspicious strings such as:

- `encodedcommand`
- `frombase64string`
- `invoke-expression`
- `iex`
- `downloadstring`
- `invoke-webrequest`

During the Sep 10 controlled activity, the following command triggered the rule:

```powershell
Write-Output "LAB-INC-SEP10 Invoke-WebRequest"
```

The detection technically worked as written because `Invoke-WebRequest` appeared in the Script Block. However, reviewing the command showed that the string was only being printed with `Write-Output`.

There was no URL in the command and no actual web request was executed by that Script Block.

I therefore treated the alert as a **false positive caused by benign keyword matching**, not as evidence of a download or compromise.

### What was wrong with the v1 logic

The main issue was context. The rule treated the presence of a suspicious keyword as if the associated behavior had happened.

For example, these are not equivalent:

```text
Invoke-WebRequest https://example.test/file
```

and

```text
Write-Output "Invoke-WebRequest"
```

Both contain the same keyword, but the second example does not perform a web request.

This made DET-001 v1 useful for broad visibility, but too noisy to keep as the final alert logic.

SPL: [`../spl/DET-001-v1.spl`](../spl/DET-001-v1.spl)

---

## 3. DET-001 v2 Changes

DET-001 v2 kept PowerShell Script Block Logging as the data source but added stronger context around the suspicious patterns.

The tuned logic still extracts `ScriptBlockText` and normalizes it to lowercase, but the matching behavior was changed so that:

- `Invoke-WebRequest` must also contain `http://` or `https://`
- `DownloadString(` must also contain `http://` or `https://`
- `FromBase64String(` remains a suspicious pattern
- `Invoke-Expression` remains a suspicious pattern
- `iex(` remains a suspicious pattern

This reduced the chance that a harmless mention of `Invoke-WebRequest` or `DownloadString` would trigger the rule by itself.

The exact tuned search is stored in:

[`../spl/DET-001-v2.spl`](../spl/DET-001-v2.spl)

### Tuning principle

The change was not intended to make every PowerShell alert automatically malicious. It simply made the detection condition closer to the behavior I originally wanted to identify.

PowerShell is used legitimately in Windows environments, so an analyst still needs to review the command, user, host, parent process, timing, and surrounding telemetry.

---

## 4. DET-001 Retest

I used both a negative retest and a positive validation.

### Negative retest

I retested the original benign marker:

```powershell
Write-Output "LAB-INC-SEP10 Invoke-WebRequest"
```

**Result:** `0` matches with DET-001 v2.

This was the expected result because the Script Block contained the keyword but did not contain a URL or stronger execution pattern.

### Positive validation

I then used a controlled Base64-conversion test:

```powershell
[System.Convert]::FromBase64String("QQ==")
```

**Result:** DET-001 v2 returned `1` match.

This showed that the tuned rule could reject the known benign v1 case while still matching one of the stronger patterns intentionally retained in v2.

### Final DET-001 state

- DET-001 v1 — **Disabled**
- DET-001 v2 — **Enabled**

I kept v1 in the repository so the reason for the tuning is visible instead of only presenting the final query.

---

## 5. DET-003 v1 Problem

DET-003 v1 attempted to identify the same account authenticating on both `WIN11-01` and `WIN11-02` using successful logon events (`Event ID 4624`).

The rule did identify the controlled `Mr.Banerjee` cross-host condition, but the investigation showed that the v1 logic was too broad.

### Problems observed

The original search relied on `Account_Name`, which was not specific enough for reliably identifying the actual human user in the Windows event structure.

The search could also include identities that were not useful for this detection goal, including service, machine, and desktop-session accounts.

In addition, the v1 rule did not restrict the result to the interactive-style logon types I wanted to monitor.

Because the alert was scheduled repeatedly over an overlapping lookback window, the same condition could also generate repeated alerts while the matching events remained inside the search window.

The important distinction was that the underlying condition was real: `Mr.Banerjee` had authenticated on both workstations. The problem was the amount of unrelated or repeated signal around that condition.

SPL: [`../spl/DET-003-v1.spl`](../spl/DET-003-v1.spl)

---

## 6. DET-003 v2 Changes

DET-003 v2 was updated to correlate the actual user from the `New Logon` section of Event ID `4624` instead of depending on the broader `Account_Name` field.

The corrected search extracts:

- `TargetUser` from `New Logon: Account Name`
- `LogonType` from the event message

It then filters out identities that were not part of the human-user use case:

- `SYSTEM`
- `LOCAL SERVICE`
- `NETWORK SERVICE`
- machine accounts ending in `$`
- `DWM-*`
- `UMFD-*`

The search keeps only logon types:

- `2` — Interactive
- `10` — RemoteInteractive
- `11` — CachedInteractive

It then requires:

- the same `TargetUser`
- more than one workstation
- the matching activity to occur within `900` seconds (15 minutes)

The exact search is stored in:

[`../spl/DET-003-v2.spl`](../spl/DET-003-v2.spl)

### Debugging during tuning

The first v2 attempt did not immediately return the expected result. During debugging, I found that the existing account field was multi-value and the logon-type extraction was not giving the usable value I expected.

Instead of treating the `0` result as proof that no cross-host authentication occurred, I inspected the raw Windows event structure and changed the search to extract the actual `New Logon` account and `Logon Type` directly from `Message`.

That corrected the correlation logic and produced the expected historical result.

### Alert-level tuning

The final v2 alert used:

- schedule: every 5 minutes
- lookback: last 15 minutes
- trigger: number of results greater than 0
- trigger mode: once
- duplicate suppression/throttling added to reduce repeat notifications for the same condition

The detection remains a correlation alert, not proof of lateral movement or account compromise.

---

## 7. DET-003 Retest

I validated DET-003 v2 against the Sep 10 historical window containing the controlled cross-host activity.

The relevant authentication events were:

- `14:07:53.853` — `Mr.Banerjee` on `WIN11-01`
- `14:17:16.844` — `Mr.Banerjee` on `WIN11-02`

The corrected v2 search returned:

```text
TargetUser: Mr.Banerjee
host_count: 2
hosts: WIN11-01, WIN11-02
first_seen: 14:07:53.853
last_seen: 14:17:16.844
```

The time difference was approximately 9 minutes 23 seconds, which was within the 15-minute correlation requirement.

During the broader incident investigation, `DC01` Kerberos events `4768` and `4769` also corroborated authentication activity associated with the two workstation IP addresses.

### Interpretation

The retest proved that the tuned rule could still detect the controlled cross-host condition after the noise filters and more precise field extraction were added.

It did **not** prove malicious lateral movement. Cross-host authentication can be legitimate, so the resulting alert still needs analyst context and correlation.

### Final DET-003 state

- DET-003 v1 — **Disabled**
- DET-003 v2 — **Enabled**

---

## 8. Why DET-002 Stayed at v1

DET-002 monitored Active Directory security-group membership changes on `DC01`.

During the controlled incident it correctly identified:

- Event ID `4728` — `Mr.Banerjee` added to `SOC-Analysts`
- Event ID `4729` — `Mr.Banerjee` removed from `SOC-Analysts`

The detection condition was accurate. The fact that the activity was authorized did not mean the detection itself was faulty.

This is different from DET-001, where the rule logic created a benign keyword false positive, and DET-003, where the search produced unnecessary identity noise and repeated alerting.

For DET-002, the analyst still needs to determine whether a group change is expected or unauthorized, but I did not identify a specific detection-logic problem in the lab that justified creating a v2 simply for the sake of having another version.

### Final DET-002 state

- DET-002 v1 — **Enabled**
- No v2 created

This was a deliberate choice. I wanted the repository to show tuning only where the investigation actually demonstrated a reason to tune.

---

## 9. Final Detection State

| Detection | Final state | Reason |
|---|---|---|
| DET-001 v1 | Disabled | Broad keyword logic produced a benign false positive |
| DET-001 v2 | Enabled | Known benign marker excluded; stronger controlled pattern still detected |
| DET-002 v1 | Enabled | Correctly detected real AD group-membership changes |
| DET-003 v1 | Disabled | Broad identity handling and overlapping windows produced noise/repeat alerts |
| DET-003 v2 | Enabled | More precise user extraction, filtering, logon-type scope, 15-minute correlation, and suppression |

The final enabled set was therefore:

```text
DET-001 v2
DET-002 v1
DET-003 v2
```

The old versions were disabled in Splunk but preserved in GitHub so the tuning history remains visible.

---

## 10. Lessons Learned

The biggest lesson from this tuning exercise was that a detection is not finished just because it can generate an alert.

DET-001 showed me that a rule can technically match its condition while still giving the analyst the wrong security impression. Looking at the full command mattered more than the presence of one suspicious word.

DET-003 showed me that correlation rules depend heavily on field selection, identity filtering, time windows, and alert scheduling. When the first tuned query returned `0`, checking the raw event structure was more useful than assuming the original hypothesis was wrong.

DET-002 showed the opposite lesson: a correct detection does not need to be changed simply because the activity later turns out to be authorized. The detection and the incident disposition are separate decisions.

My final workflow from this project was:

1. investigate the alert
2. decide whether the detection condition was meaningful
3. identify the source of noise or false positives
4. change only the logic that needs improvement
5. retest the known benign case
6. run a positive validation
7. compare v1 and v2 behavior
8. keep the final alert understandable enough for another analyst to investigate

This made rule validation and tuning part of the investigation process instead of treating alert creation and incident analysis as separate exercises.

## Related files

- [`DET-001 v1 SPL`](../spl/DET-001-v1.spl)
- [`DET-001 v2 SPL`](../spl/DET-001-v2.spl)
- [`DET-002 v1 SPL`](../spl/DET-002-v1.spl)
- [`DET-003 v1 SPL`](../spl/DET-003-v1.spl)
- [`DET-003 v2 SPL`](../spl/DET-003-v2.spl)
- [`Sep 10 Incident Investigation`](sep10-incident-investigation.md)
