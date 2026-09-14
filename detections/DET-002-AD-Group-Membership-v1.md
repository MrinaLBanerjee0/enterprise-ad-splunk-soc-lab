# DET-002 v1 — AD Group Membership Modification

## Purpose
Detect security-group membership changes on the domain controller so privilege or role changes can be reviewed by an analyst.

## Data source
- Windows Security log on `DC01`
- Splunk index: `soc_windows`

## Relevant Event IDs
- `4728` — member added to a global security group
- `4729` — member removed from a global security group
- `4732` / `4733` — local security-group membership changes
- `4756` / `4757` — universal security-group membership changes

SPL: [`../spl/DET-002-v1.spl`](../spl/DET-002-v1.spl)

## Validation
During the Sep 10 controlled activity:

- `Administrator` added `Mr.Banerjee` to `SOC-Analysts`, producing Event ID `4728`.
- `Administrator` later removed `Mr.Banerjee`, producing Event ID `4729`.

The detection correctly surfaced real group-membership changes. The activity was authorized lab activity, so the detection was a true positive for the condition but did not represent malicious compromise.

### Validation evidence
- [AD group addition — Event ID 4728](../evidence/incident/ad-group-add-4728.png)
- [AD group-membership threat hunt](../evidence/threat-hunt/ad-group-membership-hunt.png)
- [Sep 10 incident investigation](../investigations/sep10-incident-investigation.md#6-active-directory-group-membership-analysis)
- [Visual evidence gallery](../evidence/README.md#active-directory-group-addition--event-id-4728)

## Limitations
- A group change by itself does not show whether the action was authorized or malicious.
- Analyst context is required to evaluate the actor, target user, group, timing, and surrounding authentication activity.

## Final state
Enabled. No v2 was created because the rule performed its intended function during the lab.

## Historical query note
The SPL file in this repository is the version documented in the project conversation. The original Splunk saved-alert export was not retained separately, so it should not be described as a byte-for-byte export of the original saved object.
