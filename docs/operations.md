# Operations and recovery

## Local checks

Run the commands in the root README. `Test-Configuration.ps1` validates contracts; `Build-RulePackage.ps1` compiles the custom SIT XML; `Invoke-DetectionTests.ps1` evaluates only the local fixture expectations; and `Get-DeploymentPlan.ps1` renders intended operations. CI does not authenticate to Microsoft 365 or Azure.

## Service-side adapter

`Invoke-PurviewDeployment` is plan-only by default. Before `-Apply`, configure a non-production overlay, connect read-only to Exchange Online and connect to Security & Compliance PowerShell, then create a tenant-scoped inventory with `Initialize-PurviewInventory.ps1`. Apply checks required cmdlets and parameters, verifies the connected tenant ID and configured mail-enabled groups, rejects unowned name collisions, and records each created GUID before proceeding. It reconciles labels, the custom SIT package, and auto-label policies/rules in simulation mode. It does not delete objects.

The documented `New-LabelPolicy` cmdlet does not expose a recipient-user/group audience parameter. Label publishing is therefore reported as blocked rather than risked tenant-wide. Auto-label activation requires a simulation approval record with `approved=true`, `approvedBy`, `simulationRunId`, and `manualLabelPreservationVerified=true`; the script re-reads managed policies/rules and verifies the expected simulation configuration before changing modes. The manual-label field is an operator attestation, not a script-verified or Microsoft-certified result. Keep activation disabled until independent tenant tests support that attestation.

Drift reporting requires a connected, read-only-capable Security & Compliance session and an explicit tenant-scoped inventory. It only queries recorded GUIDs; it never adopts objects by display name. `Get-DriftReport.ps1` returns a PowerShell object and can write JSON to a file when `-OutputPath` is supplied.

## Label-level auto-labeling and container scopes

`config\labels.json` owns `scopes`, optional `autoLabeling`, and optional
`container` settings. These are separate from the service-side policies in
`config\auto-labeling-policies.json`. The scanner consumes published label
conditions, not cloud auto-label policies. Conditions also affect supported
Office clients for every user receiving these labels; they are not scanner-only.

The label conditions use SSN confidence 85 with inclusive 1-199 and 200+ tiers
on the Internal Only labels. BES uses an OR of the three custom BCSI detectors
at confidence 85. User-defined Recipients Only encryption is deliberately not
used for scanner conditions; the Exchange service-side 200+ policy retains its
Do Not Forward label. Automatic condition application is the default CCSI wire
behavior; only recommendations serialize `autoapplytype=Recommend`.

All selectable labels include File, Email, Site and UnifiedGroup scopes. Parent
categories are not independently selectable or configured by this writer. Existing additional
scopes such as Teamwork are preserved, never silently removed. Public,
Non-Business and General add no container restrictions. Confidential selectable
labels enforce private groups/Teams, allow guests, and restrict SharePoint
external sharing to existing guests. Highly Confidential selectable labels,
including BES, enforce private groups/Teams, block guests, and disable SharePoint
external sharing. The existing-guests-only restriction is a **SharePoint sharing**
control; the group guest switch is boolean and does not independently distinguish
new from existing guests. File encryption does not govern container membership,
and a container label does not label or encrypt the files inside it.

Deploy through the saved script with an existing authorized certificate:

```powershell
.\scripts\Invoke-ConnectedLabelDeployment.ps1 `
    -EnvironmentPath config\environments\<tenant>.json `
    -InventoryPath <private-managed-inventory.json> `
    -AppId <administration-app-id> `
    -CertificateThumbprint <installed-certificate-thumbprint> `
    -Organization <tenant>.onmicrosoft.com -Apply
```

Add `-UpdateDetectionPackage` to this launcher when deploying a versioned
`config\detection.json` correction. It checks the same tenant/inventory guards,
backs up the owned SIT package, rebuilds the Unicode XML, updates only that
package GUID and verifies its version. Without `-Apply` it reports the desired
and current versions without tenant writes. Keep the original package/SIT IDs;
do not create duplicate portal classifiers to work around cached policy.

Without `-Apply`, this returns the source-defined plan. A connected operator can
instead use `Set-LabelConfiguration.ps1`. Normal `Invoke-Deployment.ps1 -Apply`
also reconciles these settings after the SIT package is available. Writes require
the correct tenant and inventory-owned GUIDs, preflight every configured SIT,
save a private label snapshot, and verify conditions and container settings on
read-back. Reapply performs no label writes when the settings match. The connected
launcher requests `Execute-AzureAdLabelSync` after reconciliation. Before container
use, confirm Entra Group.Unified `EnableMIPLabels=True`; the launcher does not
change unrelated directory settings, assign site labels, or alter existing sites.
CI validates this code, but Microsoft 365 deployment uses this saved local
certificate-authenticated launcher unless Actions credentials are separately
configured. No private keys are committed or uploaded to GitHub.

In Purview, find the custom SITs under **Solutions > Information Protection >
Classifiers > Sensitive info types**. Filter to custom types and search for:
**BCSI Explicit Designation**, **BCSI Network and Security Configuration**, or
**BCSI Access and Security Procedures**. There is no single type named just
"BCSI". Their stable IDs and publisher are declared in `config\detection.json`.
Find the label conditions under **Sensitivity labels > edit a selectable label >
Auto-labeling for files and emails**.

After policy propagation, run the AD lab helper's `RefreshPolicy` stage while the
scanner is idle. It invokes supported `Start-ScannerDiagnostics -ResetConfig`
under the domain worker and restarts the service after temporary administrator
cleanup. This bypasses the four-hour policy-cache interval without editing SDK
databases or deleting token caches. Then run `StartDiscovery` with a full reset and inspect the
detailed report. Keep enforcement Off and write-denied ACLs until actual native
detections, proposed labels, negative controls and manual-label behavior have been
reviewed. A local regex test or successful tenant write is not scanner evidence.
`Test-ScannerBcsiDetection.ps1 -BesLabelId <inventory BES GUID>` verifies the three
positive BCSI scenarios in TXT, DOCX and PDF against the actual native report,
requiring both SIT matches and BES proposals. It does not validate label writes.

The lab scan ending 2026-10-14 at 23:09:26 UTC reported 29 successful files,
12 native BCSI matches/BES proposals, and zero label writes. All three detectors
matched their TXT, DOCX and PDF positives; the four public/isolated-address/
generic-SCADA/generic-credential controls did not match BCSI. The scanner service
remained Running as its domain account, with no temporary worker tasks or local
administrator membership. Evidence is separate from generic discovery readiness:
PII and manual-label behavior remain unvalidated, so enforcement stays blocked.
Use `-EvidencePath` on the verifier to retain its JSON beside the protected
guest scan reports. The lab retains
`C:\ProgramData\PurviewIPAsCode-AdLab\bcsi-native-evidence.json`.

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

The content scan job must explicitly use `Enforce Off`, `LabelFilesByContent On`, `RelabelFiles Off`, and `EnforceDefaultLabel Off`. Content inspection must be enabled even for reporting-only discovery; `Enforce Off` prevents label writes. Use `DiscoverInformationTypes All` to report sensitive information types independently of label conditions. Keep `EnableDlp Off` unless an on-premises scanner DLP policy actually exists; cloud auto-label policies are not scanner DLP policies. Online bootstrap reads and checks that job rather than overwriting it using offline-only cmdlets. Offline mode must be explicitly selected and does not establish portal registration. Bootstrap fails on unsupported cmdlet parameters, authentication failures, incorrect hashes/signatures, unowned fixture contents, missing/unsafe job settings, or no fresh reports covering every fixture within 90 minutes. Idle status alone is insufficient. Successful discovery clears stale failure codes. Reports are local to the service account's `%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`; inspect events and reports without exporting content or credentials.

Published beta.1 scans local fixtures, not Azure Files, and remains unchanged. Current source includes an optional private IaaS AD DS/Azure Files lab workflow with encrypted credentials, a domain scanner identity and keyless ACL setup. This explicitly approved offline job is separate from portal configuration. Migration invalidates old readiness; fresh UNC reports, restrictive ACLs, service-account read access and write denial are required before publishing completed discovery. Expected SIT detections and enforcement remain separate, unvalidated outcomes. See [scanner operations](../extensions/scanner/README.md) for the staged workflow, cluster migration, workday startup limitations and exact commands.

The Azure deployment workflow requires a manual dispatch, an existing resource group, OIDC, environment credentials, and human approval. Tear down only after preserving the readiness report and reviewing resource contents. Delete the resource group only after confirming the exact name, no retained lab data, and no unrelated resources. Soft delete and purge protection mean the Key Vault may remain recoverable after resource deletion; follow the organization's retention and purge controls.
