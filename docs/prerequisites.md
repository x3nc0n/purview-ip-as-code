# Prerequisites

## Offline development

- PowerShell 7.4 or newer, Pester 6.2.0, and PSScriptAnalyzer 1.25.0.
- Python 3 with dependencies from `requirements-dev.txt`.
- Azure CLI with Bicep installed for compiling `extensions/scanner/infra/main.bicep`.
- Windows is required for executing the scanner bootstrap. Unit and fixture checks do not require a tenant.

## Service-side Purview work

Use an explicitly configured, non-production tenant overlay with a detected modern label scheme, email-enabled Entra security groups, and explicit SharePoint, OneDrive, and/or Exchange locations. Open both Exchange Online PowerShell (for read-only organization/recipient identity checks) and Security & Compliance PowerShell sessions. Verify licensing, administrative roles, Security & Compliance cmdlet versions, custom SIT support, classification semantics, label ordering, guest behavior, and existing content effects before considering any service-side changes. Apply can reconcile labels, custom SIT packages, and simulation-mode auto-label policies; label publishing is blocked because the public cmdlet does not expose the configured recipient audience.

Never put real tenant/group/app identifiers, operational inventories, passwords, app secrets, certificates, or tokens in a committed overlay.

## Scanner Azure lab

- An existing Azure resource group and a human-authorized target subscription/region. This repository does not deploy resources automatically.
- A licensed delegated Entra user and tenant-approved app registration/consent compatible with the exact installed scanner client. The template cannot create or consent a tenant application.
- A protected deployment identity scoped to the existing resource group and the reviewed GitHub environment, with permission to assign Key Vault Secrets User to the VM identity at the vault scope. No storage-key role is required.
- An existing Purview portal scanner cluster, an assigned discovery-only content scan job, and local repository `C:\PurviewScannerDemo\fixtures`. Supply the exact cluster name in `scannerClusterName`; ARM does not create it. Keep online configuration enabled unless deliberately testing disconnected mode.
- A supported scanner Windows Server Desktop Experience VM size, outbound HTTPS for pinned downloads/Microsoft services, and private Key Vault DNS reachability. The beta does not mount Azure Files.
- Approved SQL Express, Visual C++ x64 runtime, and Information Protection client URLs with exact SHA-256 values. The bootstrap also verifies each executable has a valid Microsoft Authenticode signature.
- A unique released bootstrap script and fixture archive URL and their exact hashes. The release workflow publishes these public assets.
- An ARM parameter JSON document stored only as the `SCANNER_LAB_PARAMETERS_JSON` secret in the protected `scanner-demo-approval` GitHub environment, or supplied directly in the Deploy to Azure form. Protect the secret and verify every URI/hash before use.
- The `scanner-demo-approval` environment configured with required human reviewers and a `main`-only deployment branch policy, plus `scanner-release-approval` with required human reviewers and a `v*` tag policy. This repository has owner review configured for both; forks must create equivalent protection because a YAML `environment` declaration alone does not create approval rules.

The lab uses billable Azure resources. Estimate VM, disk, storage, Key Vault, private endpoint, and data-processing charges in the target region before deployment. The [beta notes](../CHANGELOG.md) document a limited lab deployment; they are not a guarantee of quota, pricing, licensing, connectivity or classification in another environment.
