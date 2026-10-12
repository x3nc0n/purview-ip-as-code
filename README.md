# Purview Information Protection as code

Version-controlled Microsoft Purview sensitivity labels, a separately managed BCSI and PII detection example, and an optional private Azure Files lab for the Microsoft Purview Information Protection scanner.

> **Demonstration only.** This repository does not certify NERC CIP compliance, determine whether information is legally BCSI, decide whether an incident is reportable, or promise production detection accuracy. Validate every detector and protection outcome with your organization and a non-production tenant.

## What is included

- JSON definitions and JSON Schema validation for labels, policy families, detection rules, and a placeholder tenant overlay.
- A deterministic Unicode UTF-16 custom sensitive-information-type (SIT) XML compiler with stable, declared entity identifiers.
- A PowerShell module and commands for offline validation, plan generation, inventory-backed label/SIT/auto-label reconciliation, guarded activation, and drift reporting.
- Independent high-confidence BCSI policies and SSN-count PII policies. The fictional PII threshold is 200 occurrences **in one item**, not unique people or an incident total.
- Synthetic, reproducible detection fixtures and an expected-results manifest.
- A modular Bicep scanner lab and compiled ARM JSON template with private Azure Files SMB, private DNS, a managed identity, Key Vault, a Windows Server VM, and a guarded bootstrap contract.
- Pull-request validation, tag-built public release assets, and a manually dispatched, environment-protected GitHub deployment workflow.

The example label hierarchy is `Public`, `Non-Business`, `General`, `Confidential`, and `Highly Confidential`. Confidential and Highly Confidential each have `Any User (No Protection)`, `Internal Only`, and `Recipients Only` children. `BES` exists only as the final/highest-priority Highly Confidential child. BCSI matches target only that BES label. PII policies do not exclude BCSI and never target BES.

### Start locally

Requirements: PowerShell 7.4+, Pester 6.2+, PSScriptAnalyzer 1.25+, Python 3 with `requirements-dev.txt`, and Azure CLI with Bicep CLI v0.46.1 (for deterministic scanner-template compilation). ExchangeOnlineManagement is only relevant to tenant operations.

```powershell
./scripts/Test-Configuration.ps1
./scripts/Build-RulePackage.ps1
./scripts/Invoke-DetectionTests.ps1
./scripts/Get-DeploymentPlan.ps1 -EnvironmentPath ./config/environments/demo.example.json
Invoke-Pester ./tests
$diagnostics = @()
foreach ($path in @('./src', './scripts', './extensions/scanner/scripts')) {
    $diagnostics += @(Invoke-ScriptAnalyzer -Path $path -Recurse -Severity Error,Warning)
}
if ($diagnostics) { $diagnostics | Format-Table -AutoSize; throw 'PSScriptAnalyzer reported issues.' }
az bicep build --file ./extensions/scanner/infra/main.bicep --outfile ./extensions/scanner/infra/azuredeploy.json
```

No tenant connection or Azure resource is needed for these offline checks. The example overlay deliberately contains no tenant, group, app, or credential identifiers.

### Purview operations

```powershell
Import-Module ./src/PurviewIPAsCode/PurviewIPAsCode.psd1 -Force
Connect-ExchangeOnline
Connect-IPPSSession
$plan = Get-PurviewDeploymentPlan -EnvironmentPath ./config/environments/demo.example.json
Invoke-PurviewDeployment -EnvironmentPath ./config/environments/demo.example.json
# Tenant writes require an explicitly configured overlay, initialized inventory, and -Apply.
```

`Invoke-PurviewDeployment` returns a plan unless `-Apply` is explicitly supplied. Before applying, configure a real tenant overlay, connect to both Exchange Online and Security & Compliance PowerShell, and create a tenant-scoped inventory. Exchange Online supplies a read-only organization tenant-ID check; Security & Compliance supplies the label, SIT, and policy cmdlets:

```powershell
./scripts/Initialize-PurviewInventory.ps1 -EnvironmentPath ./config/environments/tenant.example.json
./scripts/Invoke-Deployment.ps1 -EnvironmentPath ./config/environments/tenant.example.json -Apply
./scripts/Get-DriftReport.ps1 -EnvironmentPath ./config/environments/tenant.example.json
```

Apply creates or updates inventory-owned labels, imports the stable-ID custom SIT package, and creates independent auto-label policy rules in `TestWithoutNotifications` mode. Auto-label policy priority follows the target label priority, so BES wins when BCSI and PII policies overlap. Existing resources outside the inventory are never adopted, name collisions fail closed, IDs are persisted after creation, and no object is deleted. The label-publishing policy remains **blocked**: the documented `New-LabelPolicy` interface does not expose a recipient-user/group audience parameter, so the adapter will not risk publishing the labels tenant-wide. A blocked publishing policy is reported in the apply result; it is not silently approximated.

Auto-label activation requires an approval record with `approved`, `approvedBy`, `simulationRunId`, and `manualLabelPreservationVerified: true`. The script re-reads every managed policy and rule, requires the reviewed simulation mode and exact configuration, and only then changes policies to `Enable`. This operator attestation is not independent evidence that the tenant preserved manual labels or classified content correctly. A plan, command-parameter probe, or local fixture run does not establish live tenant behavior. No object is deleted automatically.

## Scanner lab

The scanner add-on is isolated from the Microsoft 365 service-side policies. Its pinned bootstrap verifies installer SHA-256 and Microsoft signatures, persists restart state, uses a dedicated local scanner service account, retrieves the app credential from Key Vault through the VM identity, and seeds only an empty dedicated share with a pinned synthetic corpus. It leaves enforcement, content labeling, relabeling, and default-label enforcement off. A completed discovery scan is not enforcement readiness: scanner label-condition mapping and manual-label behavior have no verified writer in the supported cmdlet surface and remain explicitly blocked.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fgithub.com%2Fx3nc0n%2Fpurview-ip-as-code%2Freleases%2Fdownload%2Fv1.0.0%2Fazuredeploy.json)

The button is pinned to the immutable `v1.0.0` release asset, not branch content or a mutable `latest` URL. The release workflow publishes the ARM template, bootstrap script, and fixture archive only after approval by the protected `scanner-release-approval` environment; those URLs remain unavailable until that review completes. Replace the remaining placeholders in [`extensions/scanner/infra/scanner.lab.parameters.example.json`](extensions/scanner/infra/scanner.lab.parameters.example.json) with approved installer URLs, tenant values, and SHA-256 values from the released `SHA256SUMS.txt` before deployment. The lab has no public RDP/SMB endpoint and uses a dedicated storage-account key only for synthetic demo data. A licensed delegated scanner identity, approved app registration and consent, Azure RBAC, network reachability, and a verified scanner/client compatibility profile remain operator prerequisites. See [`extensions/scanner/README.md`](extensions/scanner/README.md) before deployment.

No Azure resources are deployed by CI. The `deploy-demo` workflow is manually dispatched from the default branch and requires the `scanner-demo-approval` GitHub environment, an Azure OIDC identity, and an operator-supplied ARM-parameters JSON secret. This repository's environment requires review by the configured repository owner and is restricted to `main`; the release environment separately gates public assets to reviewed `v*` tags. Verify both protections before use. Forks must configure equivalent rules. The deployment workflow targets an already-existing resource group and never creates one.

## Safety and scope

- The scanner and service-side auto-labeling are separate adapters. Scanner mappings are capability-checked against the installed `PurviewInformationProtection` module; unsupported detector, threshold, or label-priority behavior blocks setup.
- The scanner's content-scan job starts with enforcement off. Relabeling behavior is not silently enabled to paper over manual-label conflicts; see the manual-label limitations in [`docs/protection-gaps.md`](docs/protection-gaps.md).
- Custom XML compilation and local synthetic tests do not prove Microsoft Purview has accepted a SIT package or observed the expected confidence/count.
- The overlay intentionally has placeholder-only values. Never commit tenant IDs, real group IDs, app secrets, certificates, tokens, or operational inventories.
- Content labels complement SharePoint/OneDrive permissions, identity governance, and storage ACLs; they do not replace them.

Read [`docs/prerequisites.md`](docs/prerequisites.md), [`docs/operations.md`](docs/operations.md), [`docs/detection-rationale.md`](docs/detection-rationale.md), [`docs/protection-gaps.md`](docs/protection-gaps.md), and [`docs/nerc-cip-scope.md`](docs/nerc-cip-scope.md) before connecting a tenant.
