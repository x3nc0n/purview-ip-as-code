# Private scanner demo

This optional lab deploys an isolated Windows scanner host and a private Azure Files share containing only the released synthetic fixture corpus. It is not a production scanner deployment and does not label content.

## Before deploying

1. Read [`../../docs/prerequisites.md`](../../docs/prerequisites.md), [`../../docs/operations.md`](../../docs/operations.md), and [`../../docs/protection-gaps.md`](../../docs/protection-gaps.md).
2. Push a reviewed `v*` tag and approve the protected `scanner-release-approval` environment. The release workflow builds `azuredeploy.json`, `Invoke-LabBootstrap.ps1`, `demo-content.zip`, and SHA-256 sums. The Deploy to Azure button points to the latest public release; do not use it until the release has been reviewed.
3. Obtain the official, approved version-pinned SQL Express and Microsoft Information Protection client installers, and independently record their SHA-256 values. Bootstrap verifies both the expected hash and Microsoft's Authenticode signature.
4. Prepare a licensed delegated Entra identity and app registration with the exact tenant consent/permissions required by the selected client. Tenant identity, licensing, app registration, admin consent, and certificate/app-secret issuance are not provisioned by ARM.
5. Verify that `scanner-demo-approval` requires human review and restricts deployments to `main`, and that `scanner-release-approval` requires human review for `v*` tags. This repository has an owner reviewer configured for both. For a fork, recreate those rules. Add `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, and the complete deployment parameter document as environment secrets/variables as appropriate. The workflow uses an existing resource group; it never creates one.
6. Review the template's scoped Storage Account Key Operator and Key Vault Secrets User grants, region-specific costs, egress, retention, recovery, and exact teardown target.

The standalone scanner bootstrap runs in 64-bit Windows PowerShell 5.1 to match the legacy scanner client. Offline repository authoring and tests use PowerShell 7.4 or newer.

For portal deployment, use the public **Deploy to Azure** button in the root README and supply a reviewed parameter file based on [`infra/scanner.lab.parameters.example.json`](infra/scanner.lab.parameters.example.json). Use release URLs and hashes that identify exact reviewed artifacts; the sample file is not deployable as-is.

## Bootstrap behavior

The Custom Script Extension verifies the release bootstrap SHA-256. The script validates pinned HTTPS downloads, package hashes, Microsoft signatures, Windows Server Desktop Experience, and installed runtime cmdlet parameters. Installer exit code 3010 schedules a LocalSystem startup continuation. Scanner app credentials are fetched from private Key Vault using the VM's user-assigned managed identity. The credentialed scanner service account configures its own profile, stores the storage key in Windows Credential Manager, verifies private SMB/DNS access, and seeds only an empty dedicated fixture folder with an exact release marker.

The script refuses to overwrite unknown share contents or silently reset a service-account password. Recovery state contains only booleans, counts, paths, timestamps, and sanitized diagnostic codes. See `C:\ProgramData\PurviewIPAsCode\readiness.json` on the VM.

## Discovery-only stop

The scanner content-scan configuration is explicitly:

```text
Enforce Off
DiscoverInformationTypes All
EnableDlp On
LabelFilesByContent Off
RelabelFiles Off
EnforceDefaultLabel Off
```

Bootstrap requires an observed, completed scanner cycle and then records `discoveryComplete=true`, `enforcementEnabled=false`, `scannerLabelConditionsSupported=false`, and `readyForEnforcement=false`. The scan is bounded to 90 minutes. A completed discovery run does not prove all fixtures matched; retain the manifest and compare scanner results manually without exporting document contents.

`scripts/Enable-ScannerProtection.ps1` is deliberately fail-closed. The documented cmdlet surface does not provide a verified label-condition adapter, and approval alone cannot change that. Do not edit scanner settings to enable enforcement or relabeling as a workaround.

## Network and cost

The template creates a dedicated VNet, VM and private-endpoint subnets, private DNS for Azure Files and Key Vault, private endpoints, a dedicated storage account/share, a vault, and a non-Core Windows Server VM. It creates no public IP, RDP rule, or public SMB endpoint. HTTPS egress is required for package acquisition and Microsoft services. Azure Files uses SMB3.1.1 over the private endpoint and shared-key authentication for synthetic fixtures only.

Compute, managed disk, Azure Files, private endpoints, Key Vault, and data processing incur region-specific charges. Estimate current pricing and quotas in the intended subscription before approving deployment; this repo does not make a cost estimate or verify quota. Keep the lab short-lived.

## Teardown

After the scan, preserve the sanitized readiness report and delete only the dedicated lab resource group after verifying its exact contents and name. Do not assume Key Vault secrets are immediately purged: soft-delete retention and purge protection are enabled. Follow organizational recovery and purge procedures; no cleanup workflow deletes resources automatically.

## Policy-restricted subscriptions (lab note)

When the subscription blocks storage shared-key auth and public access, the bootstrap seeds a local repository (C:\PurviewScannerDemo) instead of mounting Azure Files, configures the scanner offline, and runs the service-context worker as an elevated scheduled task. The template adds an NSG to the private-endpoint subnet, disables shared-key access, and passes the managed identity client ID to the VM. Reuse of a purge-protected Key Vault name requires a new labName; redeploy over an existing VNet requires deleting the resource group.

