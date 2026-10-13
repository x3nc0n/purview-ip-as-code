# Protection gaps and non-goals

- Service-side apply is explicit and inventory-backed. A non-production tenant deployment exercised labels, the custom SIT package and simulation-mode auto-label policies/rules; see [beta notes](../CHANGELOG.md). This does not establish classification accuracy or general tenant readiness.
- Scanner discovery is not equivalent to applying labels. The documented scanner cmdlet surface available to this project does not expose a verified writer for the BCSI/PII condition-to-label mapping. Bootstrap records `scannerLabelConditionsSupported=false` and never changes that setting to true.
- Label publishing is blocked because the documented `New-LabelPolicy` cmdlet has no recipient-user/group audience parameter. The adapter will not publish tenant-wide as a substitute for the configured pilot audience.
- Service auto-label activation requires explicit approval and an operator attestation to a named simulation run. The script verifies inventory ownership and policy/rule configuration before changing mode, but does not independently prove manual-label preservation or actual classification behavior.
- The scanner does not prove whether manual labels are preserved, overridden, downgraded, or protected from relabeling. `Enable-ScannerProtection.ps1` blocks activation even if a generic approval record exists.
- A label, encryption setting, `Do Not Forward`, or scanner does not replace access control, DLP response, identity governance, incident procedures, backups, or engineering controls. Recipients can photograph, copy, retype, or otherwise disclose viewed information.
- Limited lab checks of licensing, app consent and client installation are not portable validation. Scan classification accuracy, manual-label preservation and production compatibility remain unverified.
- A portal scanner cluster and assigned content scan job are required for online node configuration. Local cluster settings alone do not prove cloud node visibility. The initial disconnected scan did not validate the later online cluster job.
- The beta scans local synthetic files, not the provisioned Azure Files share. Identity-based SMB is not implemented, and shared-key access is disabled.
- Custom regexes and the synthetic fixture runner are illustrative, not certified detectors. Counts are fictional and count repeated SSN occurrences rather than distinct persons.
- The example makes no NERC CIP compliance determination and does not identify all forms of BCSI. Organizations must have qualified personnel determine applicability, classification, retention, and incident response.

Do not publish labels tenant-wide, enable automatic labeling, or enable scanner enforcement/relabeling until the unsupported publishing audience or scanner mappings and behavior have been independently reviewed, tested against synthetic edge cases in the target tenant, and explicitly approved.
