# Operations and recovery

## Local checks

Run the commands in the root README. `Test-Configuration.ps1` validates contracts; `Build-RulePackage.ps1` compiles the custom SIT XML; `Invoke-DetectionTests.ps1` evaluates only the local fixture expectations; and `Get-DeploymentPlan.ps1` renders intended operations. CI does not authenticate to Microsoft 365 or Azure.

## Service-side adapter

`Invoke-PurviewDeployment` is plan-only by default. Before `-Apply`, configure a non-production overlay, connect read-only to Exchange Online and connect to Security & Compliance PowerShell, then create a tenant-scoped inventory with `Initialize-PurviewInventory.ps1`. Apply checks required cmdlets and parameters, verifies the connected tenant ID and configured mail-enabled groups, rejects unowned name collisions, and records each created GUID before proceeding. It reconciles labels, the custom SIT package, and auto-label policies/rules in simulation mode. It does not delete objects.

The documented `New-LabelPolicy` cmdlet does not expose a recipient-user/group audience parameter. Label publishing is therefore reported as blocked rather than risked tenant-wide. Auto-label activation requires a simulation approval record with `approved=true`, `approvedBy`, `simulationRunId`, and `manualLabelPreservationVerified=true`; the script re-reads managed policies/rules and verifies the expected simulation configuration before changing modes. The manual-label field is an operator attestation, not a script-verified or Microsoft-certified result. Keep activation disabled until independent tenant tests support that attestation.

Drift reporting requires a connected, read-only-capable Security & Compliance session and an explicit tenant-scoped inventory. It only queries recorded GUIDs; it never adopts objects by display name. `Get-DriftReport.ps1` returns a PowerShell object and can write JSON to a file when `-OutputPath` is supplied.

## Scanner states

The bootstrap writes `C:\ProgramData\PurviewIPAsCode\readiness.json`, containing separate `azureProvisioned`, `softwareInstalled`, `tenantConnected`, `demoContentSeeded`, `discoveryComplete`, `enforcementEnabled`, `scannerLabelConditionsSupported`, and `readyForEnforcement` fields. A `diagnosticCode` identifies the failed stage without copying secret values or scanned content. Readiness is never inferred from VM provisioning alone.

Create the portal cluster and assign a discovery-only content scan job before deploying. Set `scannerClusterName` to its exact name and keep `scannerConfigurationMode=Online`. The job must include `C:\PurviewScannerDemo\fixtures`; a cluster without a job/repository is not scan-ready. Connect an existing node with `extensions\scanner\scripts\Connect-ScannerCluster.ps1 -ClusterName <name> -ServiceUserCredentials <credential>` in elevated Windows PowerShell 5.1. This changes its database/cluster, enables online configuration and restarts the service without uninstalling it. Confirm node visibility in the portal separately.

The content scan job must explicitly use `Enforce Off`, `LabelFilesByContent Off`, `RelabelFiles Off`, and `EnforceDefaultLabel Off`. Online bootstrap reads and checks that job rather than overwriting it using offline-only cmdlets. Offline mode must be explicitly selected and does not establish portal registration. Bootstrap fails on unsupported cmdlet parameters, authentication failures, incorrect hashes/signatures, unowned fixture contents, missing/unsafe job settings, or no fresh reports covering every fixture within 90 minutes. Idle status alone is insufficient. Successful discovery clears stale failure codes. Reports are local to the service account's `%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`; inspect events and reports without exporting content or credentials.

The beta scans local fixtures, not Azure Files. The share is provisioned with shared-key authentication disabled; identity-based SMB is not implemented. Metadata is outside the scanned directory. See [scanner operations](../extensions/scanner/README.md) for cluster migration, recovery and exact commands.

The Azure deployment workflow requires a manual dispatch, an existing resource group, OIDC, environment credentials, and human approval. Tear down only after preserving the readiness report and reviewing resource contents. Delete the resource group only after confirming the exact name, no retained lab data, and no unrelated resources. Soft delete and purge protection mean the Key Vault may remain recoverable after resource deletion; follow the organization's retention and purge controls.
