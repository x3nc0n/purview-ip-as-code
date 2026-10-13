# Private scanner demo (beta)

This add-on deploys a private Windows scanner VM, SQL Express, Key Vault, managed identity, and an Azure Files account/share. **The beta scans a local synthetic repository, not Azure Files.** Shared-key storage access is disabled; configuring identity-based SMB is outside this add-on. No production content or enforcement is supported.

## Create the portal cluster and job first

In Microsoft Purview, open **Settings > Information Protection > Information protection scanner**. You need tenant permissions that expose this page; it is not the Data Map scanning UI.

1. Create a **cluster** and record its exact name. The tested lab uses `Az-Demo`. Set `scannerClusterName` in the ARM parameters to the same value; installing the scanner does not create the portal cluster.
2. Create a **content scan job**, assign it to that cluster, select manual scheduling and discovery of all information types, and explicitly disable enforcement, content-based labeling, relabeling, and default-label enforcement.
3. Add repository `C:\PurviewScannerDemo\fixtures` to that job. This is a path on the scanner VM, not the operator workstation. Assigning a cluster without a job/repository does not make the node scan.
4. Deploy with `scannerConfigurationMode=Online` (the default). The node connects using its configured cluster and authentication; confirm it appears under **Nodes** after the service starts and configuration propagates.

The cluster/job are Microsoft 365 configuration and are **not created by ARM**. Online configuration reads the portal job. `Set-ScannerContentScan` and `Add-ScannerRepository` are for explicitly selected `Offline` configuration; offline mode is not a substitute for portal cluster registration.

## Connect an already installed node

Do not uninstall the scanner or redeploy the VM just to change cluster membership. In elevated **64-bit Windows PowerShell 5.1 on the node**, use:

```powershell
$credential = Get-Credential "$env:COMPUTERNAME\PurviewScannerSvc"
.\Connect-ScannerCluster.ps1 -ClusterName 'Az-Demo' -ServiceUserCredentials $credential
Get-ScannerConfiguration
Get-Service MIPScanner
```

The helper calls `Set-ScannerDatabase -Cluster` with the existing SQL instance and service credentials, switches `Set-ScannerConfiguration -OnlineConfiguration On`, restarts the scanner, and verifies the resulting configuration. It leaves the old SQL database intact; do not delete it before reviewing retention and recovery. Existing authentication must remain valid. The helper resets discovery readiness because a previous offline scan does not validate the new cluster.

Expect `Cluster: Az-Demo`, `OnlineConfiguration: On`, database `AIPScannerUL_Az-Demo`, and a running `MIPScanner` service. Confirm the node in the portal separately: local configuration alone does not prove cloud registration or job assignment.

After the assigned job has propagated, in an elevated service-account session:

```powershell
Get-ScannerContentScan
Get-ScannerRepository
Start-Scan
Get-ScanStatus
```

Keep every enforcement/labeling switch off. If repositories are empty or the content-scan switches are blank, finish assigning the portal job; do not force offline mode to hide the problem. The helper does not start a scan or modify the portal job.

## Deployment prerequisites

- Read [prerequisites](../../docs/prerequisites.md), [operations](../../docs/operations.md), and [protection gaps](../../docs/protection-gaps.md).
- Use an existing authorized resource group and approved region. Review costs, quotas, network egress and tenant permissions.
- Prepare a licensed delegated Entra user and an approved scanner app with admin consent. The tested app uses Azure Rights Management `Content.DelegatedReader` and `Content.DelegatedWriter`, and Microsoft Information Protection Sync Service `UnifiedPolicy.Tenant.Read` application permissions. Verify these against the selected client and Microsoft's current scanner requirements.
- Supply an app secret through a protected parameter store. ARM stores it in private Key Vault. Only the VM's explicitly selected user-assigned identity receives Key Vault Secrets User access. There is no storage-key operator grant.
- Obtain approved SQL Express, Purview Information Protection client, and Visual C++ x64 redistributable URLs and SHA-256 hashes. The sample pins VC++ 14.44.35211; its vendor URL is mutable, but a changed hash fails closed. The bootstrap also verifies Microsoft's Authenticode signatures.
- Use the `v1.0.0-beta.1` assets and hashes from `SHA256SUMS.txt`; replace every placeholder in [the sample parameters](infra/scanner.lab.parameters.example.json). Templates from earlier lab releases do not include the cluster/runtime contract and cannot be mixed with the beta bootstrap.
- GitHub deployment requires OIDC and the protected `scanner-demo-approval` environment. Tag-built releases use `scanner-release-approval`. Administrators must configure required reviewers and branch/tag restrictions; YAML alone does not enforce review.

## Bootstrap and readiness

The Custom Script Extension verifies the bootstrap hash. Bootstrap validates package hashes/signatures, Windows Server Desktop Experience and installed runtime cmdlet parameters; installer exit code 3010 schedules a LocalSystem restart continuation. It installs SQL Express, the current pinned VC++ runtime, and the client, then installs or reconnects the scanner to the supplied cluster.

An elevated scheduled worker configures authentication in the dedicated service account's profile using `Set-Authentication -OnBehalfOf`. Administrator membership added by bootstrap is temporary and removed in cleanup. The protected state directory contains the machine-DPAPI service password; do not export it.

The pinned archive seeds an empty local fixture directory. Its marker and manifest live outside the scanned folder. Unknown or mismatched contents fail closed. Fixture archives are deterministic and contain only `generated/` and `fixtures.json`, not ARM files.

Online bootstrap requires an assigned discovery-only portal job and the exact repository. Offline mode creates its own local job with:

```text
Enforce Off
DiscoverInformationTypes All
EnableDlp On
LabelFilesByContent Off
RelabelFiles Off
EnforceDefaultLabel Off
```

Within 90 minutes, bootstrap requires an idle node **and fresh summary/detailed reports covering every fixture with zero failures**. An idle node or elapsed timer alone never sets `discoveryComplete=true`. Reports remain under the service account's `%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`; worker output and `readiness.json` remain under `C:\ProgramData\PurviewIPAsCode`.

Readiness keeps provisioning, software, authentication, seeding and discovery separate. Successful discovery clears stale failure codes but leaves enforcement and enforcement readiness false. Compare sensitive-information-type results against the fixture manifest separately; a completed scan does not prove expected detections. `Enable-ScannerProtection.ps1` remains deliberately fail-closed.

## Network, recovery and teardown

Both subnets have an NSG. Storage and Key Vault use private endpoints/DNS and disable public access. There is no public IP or inbound RDP/SMB rule. Outbound HTTPS is needed for approved packages and Microsoft services. The Azure Files share is provisioned but not mounted or populated by this bootstrap.

Subnets are declared inline to preserve them on VNet redeployment; do not delete a resource group merely to update the scanner. Review ARM what-if before changes. A deleted purge-protected Key Vault name cannot simply be reused: recover it according to organizational procedures or choose a new `labName`.

After an extension failure, inspect worker output, readiness, and local scanner events before retrying the verified bootstrap. Correcting the node via Run Command does not retroactively change a failed ARM deployment record. Preserve sanitized evidence and then delete only the exact dedicated resource group after confirming it contains no unrelated resources. Compute, disks, private endpoints, storage and Key Vault remain billable until teardown.

Reference: [Set-ScannerDatabase](https://learn.microsoft.com/powershell/module/purviewinformationprotection/set-scannerdatabase?view=azureipps).
