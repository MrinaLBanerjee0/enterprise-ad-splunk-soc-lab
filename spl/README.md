# SPL Searches and Provenance

This folder contains the detection searches used for the lab.

| File | Purpose | Provenance / state |
|---|---|---|
| [`DET-001-v1.spl`](DET-001-v1.spl) | Broad suspicious PowerShell keyword matching | Historical documented project version; original Splunk saved-alert export was not retained separately. Disabled after v2 validation. |
| [`DET-001-v2.spl`](DET-001-v2.spl) | Tuned suspicious PowerShell detection | Implemented and tested in the lab. Enabled. |
| [`DET-002-v1.spl`](DET-002-v1.spl) | AD security-group membership changes | Historical documented project version; original Splunk saved-alert export was not retained separately. Enabled. |
| [`DET-003-v1.spl`](DET-003-v1.spl) | Broad cross-host authentication correlation | Implemented/tested during the project and later disabled after tuning. |
| [`DET-003-v2.spl`](DET-003-v2.spl) | Tuned human-user cross-host correlation | Implemented, historically validated, and enabled. |

## Learning boundary

The SPL was implemented and tested as part of guided learning. The project evidence demonstrates configuring searches, validating them against lab telemetry, investigating results, identifying false positives/noise, troubleshooting field extraction, tuning logic, and retesting behavior. The searches are not presented as independently authored from scratch.

The two historical-version notes above are deliberate: `DET-001-v1.spl` and `DET-002-v1.spl` reflect the versions documented during the project, but the original Splunk saved-alert exports were not retained separately. They should not be described as byte-for-byte exports of those original saved objects.

[Detection documentation](../detections/) · [Detection tuning report](../investigations/detection-tuning-report.md) · [Visual evidence gallery](../evidence/README.md)
