# Operations and recovery

## Local checks

Run the commands in the root README. `Test-Configuration.ps1` validates contracts; `Build-RulePackage.ps1` compiles the custom SIT XML; `Invoke-DetectionTests.ps1` evaluates only the local fixture expectations; and `Get-DeploymentPlan.ps1` renders intended operations. CI does not authenticate to Microsoft 365 or Azure.

## Service-side adapter

`Invoke-PurviewDeployment` is plan-only by default. Before `-Apply`, configure a non-production overlay, connect read-only to Exchange Online and connect to Security & Compliance PowerShell, then create a tenant-scoped inventory with `Initialize-PurviewInventory.ps1`. Apply checks required cmdlets and parameters, verifies the connected tenant ID and configured mail-enabled groups, rejects unowned name collisions, and records each created GUID before proceeding. It reconciles labels, the custom SIT package, and auto-label policies/rules in simulation mode. It does not delete objects.

The documented `New-LabelPolicy` cmdlet does not expose a recipient-user/group audience parameter. Label publishing is therefore reported as blocked rather than risked tenant-wide. Auto-label activation requires a simulation approval record with `approved=true`, `approvedBy`, `simulationRunId`, and `manualLabelPreservationVerified=true`; the script re-reads managed policies/rules and verifies the expected simulation configuration before changing modes. The manual-label field is an operator attestation, not a script-verified or Microsoft-certified result. Keep activation disabled until independent tenant tests support that attestation.

Drift reporting requires a connected, read-only-capable Security & Compliance session and an explicit tenant-scoped inventory. It only queries recorded GUIDs; it never adopts objects by display name. `Get-DriftReport.ps1` returns a PowerShell object and can write JSON to a file when `-OutputPath` is supplied.

## Consolidating an existing nine-policy deployment

Each auto-label policy applies one label, so tier-specific labels cannot be selected by rules inside one policy. The four-policy layout retains BCSI -> Highly Confidential / BES across configured workloads, PII 1-199 -> Confidential / Internal Only across workloads, PII 200+ files -> Highly Confidential / Internal Only, and PII 200+ Exchange -> Highly Confidential / Recipients Only with Do Not Forward. The policy locations are the existing overlay scopes, never an automatic expansion to `All`. PII is specifically the US SSN example, not a general HR classifier.

Update the overlay ownership allowlist to `demo-publishing`, `bcsi-high`, `pii-low`, `pii-high-files`, and `pii-exchange-high`. Preserve the existing inventory, including legacy IDs. Back up the inventory and live definitions before applying. Normal apply creates three replacements alongside the old simulation policies and reuses Exchange-high; it never deletes the old policies.

```powershell
Invoke-PurviewDeployment -EnvironmentPath <overlay> -InventoryPath <inventory> -Apply
Get-PurviewDriftReport -EnvironmentPath <overlay> -InventoryPath <inventory>
.\scripts\Remove-SupersededAutoLabelPolicies.ps1 -EnvironmentPath <overlay> -InventoryPath <inventory> -BackupPath <new-private-backup.clixml>
# After reviewing the retirement plan:
.\scripts\Remove-SupersededAutoLabelPolicies.ps1 -EnvironmentPath <overlay> -InventoryPath <inventory> -BackupPath <new-private-backup.clixml> -Apply
```

The retirement helper requires four matching replacement policies and every expected single-workload rule in simulation, checks tenant/ownership/exact legacy names, and saves a new CLIXML recovery snapshot before removing up to eight legacy policies by GUID. All three configured workloads produce 15 rules within the four policies. It rejects unowned rules and waits for rule deletion propagation (12 reads, 10 seconds apart) before saving each inventory change. Rule enumeration must also be warning-free: Purview can omit malformed rules while their parent policy deletion propagates. A read failure, unresolved warning, or timeout retains the inventory entry and stops retirement. On retry, an already absent policy is reconciled only if it has no remaining rules; otherwise wait and investigate. Keep backups private; they contain tenant configuration. `-WhatIf` prevents the helper's write block; do not rely on the remote cmdlet's `-WhatIf`. Afterwards verify four policies, the expected rules, scopes/labels/conditions, and a no-write reapply. If interrupted, inspect the snapshot and remaining live objects before repairing inventory; deleted GUIDs cannot be restored by importing CLIXML and must be recreated deliberately. Do not enable policies without separate simulation approval.

## Scanner states

The bootstrap writes `C:\ProgramData\PurviewIPAsCode\readiness.json`, containing separate `azureProvisioned`, `softwareInstalled`, `tenantConnected`, `demoContentSeeded`, `discoveryComplete`, `enforcementEnabled`, `scannerLabelConditionsSupported`, and `readyForEnforcement` fields. A `diagnosticCode` identifies the failed stage without copying secret values or scanned content. Readiness is never inferred from VM provisioning alone.

Create the portal cluster and assign a discovery-only content scan job before deploying. Set `scannerClusterName` to its exact name and keep `scannerConfigurationMode=Online`. The job must include `C:\PurviewScannerDemo\fixtures`; a cluster without a job/repository is not scan-ready. Connect an existing node with `extensions\scanner\scripts\Connect-ScannerCluster.ps1 -ClusterName <name> -ServiceUserCredentials <credential>` in elevated Windows PowerShell 5.1. This changes its database/cluster, enables online configuration and restarts the service without uninstalling it. Confirm node visibility in the portal separately.

The content scan job must explicitly use `Enforce Off`, `LabelFilesByContent Off`, `RelabelFiles Off`, and `EnforceDefaultLabel Off`. Online bootstrap reads and checks that job rather than overwriting it using offline-only cmdlets. Offline mode must be explicitly selected and does not establish portal registration. Bootstrap fails on unsupported cmdlet parameters, authentication failures, incorrect hashes/signatures, unowned fixture contents, missing/unsafe job settings, or no fresh reports covering every fixture within 90 minutes. Idle status alone is insufficient. Successful discovery clears stale failure codes. Reports are local to the service account's `%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`; inspect events and reports without exporting content or credentials.

The beta scans local fixtures, not Azure Files. The share is provisioned with shared-key authentication disabled; identity-based SMB is not implemented. Metadata is outside the scanned directory. See [scanner operations](../extensions/scanner/README.md) for cluster migration, recovery and exact commands.

The Azure deployment workflow requires a manual dispatch, an existing resource group, OIDC, environment credentials, and human approval. Tear down only after preserving the readiness report and reviewing resource contents. Delete the resource group only after confirming the exact name, no retained lab data, and no unrelated resources. Soft delete and purge protection mean the Key Vault may remain recoverable after resource deletion; follow the organization's retention and purge controls.
