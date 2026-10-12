# Purview Information Protection as code

Version-controlled Microsoft Purview sensitivity labels, a separately managed BCSI and PII detection example, and an optional private Azure Files lab for the Microsoft Purview Information Protection scanner.

> **Demonstration only.** This repository does not certify NERC CIP compliance, determine whether information is legally BCSI, decide whether an incident is reportable, or promise production detection accuracy. Validate every detector and protection outcome with your organization and a non-production tenant.

## What is included

- JSON definitions and JSON Schema validation for labels, policy families, detection rules, and a placeholder tenant overlay.
- A deterministic UTF-8 custom sensitive-information-type (SIT) XML compiler with stable, declared entity identifiers.
- A PowerShell module and commands for offline validation, plan generation, drift reporting, and fail-closed tenant-operation gates.
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
Connect-IPPSSession
$plan = Get-PurviewDeploymentPlan -EnvironmentPath ./config/environments/demo.example.json
Invoke-PurviewDeployment -EnvironmentPath ./config/environments/demo.example.json
# A real, tenant-configured apply currently fails closed before any mutation.
# Drift export requires a configured environment, initialized inventory, and read-only tenant session.
```

`Invoke-PurviewDeployment` returns a plan unless `-Apply` is explicitly supplied. **Live service-side apply currently fails closed before tenant mutation** because publishing-policy and independent auto-label-rule reconciliation, stable custom-SIT ownership recovery, and label-priority behavior checks are not verified. `Enable-PurviewAutoLabeling` is likewise blocked. This is intentional: the current repository does not claim that a plan or cmdlet-parameter probe proves tenant behavior. No object is deleted automatically.

## Scanner lab

The scanner add-on is isolated from the Microsoft 365 service-side policies. Its pinned bootstrap verifies installer SHA-256 and Microsoft signatures, persists restart state, uses a dedicated local scanner service account, retrieves the app credential from Key Vault through the VM identity, and seeds only an empty dedicated share with a pinned synthetic corpus. It leaves enforcement, content labeling, relabeling, and default-label enforcement off. A completed discovery scan is not enforcement readiness: scanner label-condition mapping and manual-label behavior have no verified writer in the supported cmdlet surface and remain explicitly blocked.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fgithub.com%2Fx3nc0n%2Fpurview-ip-as-code%2Freleases%2Flatest%2Fdownload%2Fazuredeploy.json)

The button intentionally uses a public release artifact, not branch content. Push a reviewed `v*` tag and approve the protected `scanner-release-approval` environment to publish a release containing the ARM template, bootstrap script, and fixture archive. Replace every placeholder in [`extensions/scanner/infra/scanner.lab.parameters.example.json`](extensions/scanner/infra/scanner.lab.parameters.example.json) with an approved installer URI and verified SHA-256 before deployment. The lab has no public RDP/SMB endpoint and uses a dedicated storage-account key only for synthetic demo data. A licensed delegated scanner identity, approved app registration and consent, Azure RBAC, network reachability, and a verified scanner/client compatibility profile remain operator prerequisites. See [`extensions/scanner/README.md`](extensions/scanner/README.md) before deployment.

No Azure resources are deployed by CI. The `deploy-demo` workflow is manually dispatched from the default branch and requires the `scanner-demo-approval` GitHub environment, an Azure OIDC identity, and an operator-supplied ARM-parameters JSON secret. This repository's environment requires review by the configured repository owner and is restricted to `main`; the release environment separately gates public assets to reviewed `v*` tags. Verify both protections before use. Forks must configure equivalent rules. The deployment workflow targets an already-existing resource group and never creates one.

## Safety and scope

- The scanner and service-side auto-labeling are separate adapters. Scanner mappings are capability-checked against the installed `PurviewInformationProtection` module; unsupported detector, threshold, or label-priority behavior blocks setup.
- The scanner's content-scan job starts with enforcement off. Relabeling behavior is not silently enabled to paper over manual-label conflicts; see the manual-label limitations in [`docs/protection-gaps.md`](docs/protection-gaps.md).
- Custom XML compilation and local synthetic tests do not prove Microsoft Purview has accepted a SIT package or observed the expected confidence/count.
- The overlay intentionally has placeholder-only values. Never commit tenant IDs, real group IDs, app secrets, certificates, tokens, or operational inventories.
- Content labels complement SharePoint/OneDrive permissions, identity governance, and storage ACLs; they do not replace them.

Read [`docs/prerequisites.md`](docs/prerequisites.md), [`docs/operations.md`](docs/operations.md), [`docs/detection-rationale.md`](docs/detection-rationale.md), [`docs/protection-gaps.md`](docs/protection-gaps.md), and [`docs/nerc-cip-scope.md`](docs/nerc-cip-scope.md) before connecting a tenant.
