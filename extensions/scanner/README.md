# Private scanner demo (beta)

This add-on deploys a private Windows scanner VM, SQL Express, Key Vault, managed identity, and an Azure Files account/share. **Published beta.1 scans local synthetic fixtures, not Azure Files.** Current source includes optional IaaS AD DS/private Azure Files discovery and an explicitly approved portal-managed lab labeling path; neither changes immutable beta assets. Shared-key storage access stays disabled. Production enforcement is not supported.

## Create the portal cluster and job first

In Microsoft Purview, open **Settings > Information Protection > Information protection scanner**. You need tenant permissions that expose this page; it is not the Data Map scanning UI.

1. Create a **cluster** and record its exact name. The tested lab uses `Az-Demo`. Set `scannerClusterName` in the ARM parameters to the same value; installing the scanner does not create the portal cluster.
2. Create a **content scan job**, assign it to that cluster, select manual scheduling and discovery of all information types, enable content-based labeling, and explicitly disable enforcement, relabeling, and default-label enforcement.
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

Keep enforcement Off and content-based labeling On for discovery. Inspect effective repository settings as well as job settings: online jobs can expose null job-level defaults while repositories contain resolved settings. Do not force offline mode to hide a configuration problem. The helper does not start a scan or modify the portal job.

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
EnableDlp Off
LabelFilesByContent On
RelabelFiles Off
EnforceDefaultLabel Off
```

Within 90 minutes, bootstrap requires an idle node **and fresh summary/detailed reports covering every fixture with zero failures**. An idle node or elapsed timer alone never sets `discoveryComplete=true`. Reports remain under the service account's `%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`; worker output and `readiness.json` remain under `C:\ProgramData\PurviewIPAsCode`.

Readiness keeps provisioning, software, authentication, seeding and discovery separate. Successful discovery clears stale failure codes but leaves enforcement and enforcement readiness false. Compare sensitive-information-type results against the fixture manifest separately; a completed scan does not prove expected detections. `Enable-ScannerProtection.ps1` requires explicit approval tied to native detection evidence, exact repository/cluster and `-Apply`; the online worker independently checks effective configuration, ACLs and actual write access.

## Demonstrating protected-file access

`Test-ScannerLabelWrites.ps1` confirms persisted labels and RMS-protection flags,
not whether specific people can open or are denied. BES grants its configured
group `VIEW, EDIT, PRINT, EXPORT`; protection owners and authorized RMS super
users can have independent access, and `EXPORT` permits removing protection.
An empty BES group therefore does not mean every user is denied.

Keep the AD scanner service identity (SMB/NTFS access), delegated cloud MIP
identity (labeling/protection), VM managed identity (Key Vault/FilesREST), and
test readers distinct. Do not infer Rights Management ownership from a Windows
file owner or service logon. Inspect the protected file's actual owner/issuer.
The SharePoint/OneDrive service auto-label path is different: its last-modifier
account becomes the protection owner/issuer, so the administrator who uploaded
those cloud examples is not a valid denied-reader account.

Follow the [BES access test matrix](../../docs/operations.md#access-test-matrix):
one approved BES member and one nonmember, both with repository access and
neither an owner/issuer nor RMS super user, using separate signed-in sessions.
Global Administrator alone is not a decryption bypass. Content explorer cannot
preview encrypted content, so a portal preview failure is not a denial test.
The private-files reset does not reset cloud samples or remove owner rights.

## Connect an existing Azure Files account privately

`infra\connect-existing-files.bicep` is a separate, incremental connection template.
It adds a dedicated `file` private endpoint in the scanner's existing endpoint
subnet and a DNS zone group referencing the existing scanner-linked
`privatelink.file.core.windows.net` zone. It does not redeploy the VM, VNet,
storage account or bootstrap, change storage access settings, or peer networks.
The endpoint connects to the account, not just one share; share permissions still
control access. A private endpoint has ongoing charges.

```powershell
az deployment group what-if --subscription <subscription-id> --resource-group <scanner-resource-group> --template-file .\extensions\scanner\infra\connect-existing-files.bicep --parameters location=<scanner-region> storageAccountId=<existing-account-id> privateEndpointSubnetId=<scanner-endpoint-subnet-id> filePrivateDnsZoneId=<scanner-linked-zone-id> privateEndpointName=<dedicated-endpoint-name>
# After reviewing an additive-only plan, use the same parameters with:
az deployment group create --mode Incremental --subscription <subscription-id> --resource-group <scanner-resource-group> --template-file .\extensions\scanner\infra\connect-existing-files.bicep --parameters location=<scanner-region> storageAccountId=<existing-account-id> privateEndpointSubnetId=<scanner-endpoint-subnet-id> filePrivateDnsZoneId=<scanner-linked-zone-id> privateEndpointName=<dedicated-endpoint-name>
```

Check that the existing zone is linked to the scanner VNet, its DNS configuration
uses that zone, and its NSG/routes allow TCP 445 to the endpoint. Do not replace a
working zone link or modify a shared VNet unnecessarily. Verify the endpoint
connection is `Approved`, then find its private IP on its managed NIC. On the
scanner VM, run:

```powershell
.\Test-ScannerFileConnectivity.ps1 -StorageAccountName <account-name> -ExpectedPrivateEndpointIp <endpoint-ip>
```

On a repeat what-if, the DNS zone group may show a `Modify` that only removes
provider-generated `etag`, `id`, `type`, or `provisioningState` metadata. Inspect
the delta and ensure the configured zone ID is unchanged; do not add read-only
metadata to the template to silence that preview.

This requires the normal `<account>.file.core.windows.net` hostname to resolve
to the exact private endpoint and verifies TCP 445. Continue using that hostname
in the UNC, not the IP address or `privatelink` hostname. A network-only check
does not mount the share, validate SMB credentials or start a scan. Configure
supported identity-based SMB, share RBAC and filesystem ACLs, and verify access
as the scanner service identity before assigning the UNC to an online content
scan job. A managed identity/token for HTTPS storage access is not automatically
an SMB logon identity. Keep public network and shared-key access disabled.

### Managed-identity SMB and the local scanner account

Microsoft now documents [managed-identity SMB for workgroup Windows clients](https://learn.microsoft.com/en-us/azure/storage/files/files-managed-identities).
It requires storage `SMBOAuth` enablement, SMB Kerberos support, the documented
`Storage File Data SMB MI Admin` role, and the `AzFilesSmbMIClient` client.
That role includes write/delete/permission-management powers; it is not a
discovery-only reader grant. Review the scope and privileges before enabling it.
Explicitly select the user-assigned client ID when the VM has multiple identities.

The published client inserts the Kerberos ticket into its process's Windows
logon session. A task running under the same username is not evidence that it
shares the scanner service's session. Its `refresh` command remains running
only for the requested duration (`--expiry` defaults to 86400 seconds); it is not
an automatically installed permanent refresh service.

Run `scripts\Test-ScannerSmbAuthContext.ps1` elevated on a running node to compare
the caller and scanner process logon sessions. It is read-only and explicitly
reports that authentication is not configured. This add-on has no validated
integration to acquire and renew managed-identity tickets in the
`MIPScanner` logon session. Do not claim scanner access from a successful mount
under an administrator, SYSTEM, or separate scheduled task. No service-account
migration, token injection, credential caching or elevated refresh worker is
performed by this preflight. A complete implementation must demonstrate access
from the actual scanner service and survive ticket expiry and service restarts.

## Optional tiny Windows VM and workday scheduling

`infra\tiny-windows-vm.bicep` provisions a standalone Windows Server 2022 Gen2
VM and NIC in an existing private subnet. It does **not** install AD DS, promote
a domain controller, install Cloud Sync, join the scanner to a domain, or
configure Azure Files authentication. Review SKU availability and pin the image
version before deploying. The default B2als_v2 is x64, 2 vCPU / 4 GiB. Its
Standard HDD OS disk remains billable when the VM is deallocated. Before future
AD promotion, design a separate persistent AD database/log disk with host caching
disabled and appropriate backup; the current OS-only VM is not a ready domain controller.

Use `infra\tiny-windows-vm.parameters.example.json` with reviewed values and an
approved secure password source. Its Key Vault reference requires a vault
configured for ARM template deployment and the appropriate deployment permissions;
the template neither creates nor changes that vault. Never commit a password or
operational parameter file. Validate and inspect an incremental ARM what-if
before deployment. No public IP or NSG rule is created; manage the guest using an
authorized private connection or Azure VM Run Command.

Both this template and the current scanner template tag VMs
`start-stop=workday`. A tag alone does not install a scheduler: verify the
existing StartStop deployment's profile, target subscription and start/deallocate
permissions. The tested lab's active profile starts at **13:00 UTC Monday-Friday**
and deallocates at **01:00 UTC Tuesday-Saturday**, with a five-minute evaluator.
These are fixed UTC times, not a daylight-saving-aware local schedule. Disabled
or unavailable schedulers leave VMs running and billable. Merge the tag onto
existing lab VMs without replacing their other tags; do not overwrite unrelated
VMs' schedules. Published beta.1 assets remain unchanged and do not include this
new tag.

For future domain-controller use, scheduled deallocation makes AD/DNS unavailable
outside work hours. Starting scanner and DC VMs together does not guarantee AD/DNS
is ready first; sequence startup and verify service recovery when implementing AD.

## Optional IaaS AD DS and Azure Files discovery

`scripts\Invoke-ScannerAdLab.ps1` runs approved guest stages in elevated
Windows PowerShell 5.1, normally through Azure VM Run Command. This is a
single-controller **lab**, not a production directory or high-availability design.
The default domain is `corp.tiny.local` / `CORP`; neither Entra Connect nor Cloud
Sync is installed. `CORP\PurviewScannerSvc` is an AD-local identity with a separate
password, not a synchronized copy of the delegated Microsoft 365 user.

Review the operations before running each stage; promotion and domain join require
reboots. The tiny VM template alone does not perform them:

1. Deploy `infra\ad-data-disk.bicep` incrementally after validation/what-if, then attach the dedicated 32 GiB disk at LUN 0 with **host caching None**. `Promote` accepts only that disk and places NTDS/logs/SYSVOL on `F:`. Do not reuse a disk with other data.
2. Run `Prepare` on both VMs. It returns public encryption certificates, never private keys. Run `Promote` on the controller, reboot, then `Directory` with the scanner's public certificate. The latter configures Azure DNS forwarding, creates the non-administrative scanner identity, and returns its credential encrypted for the scanner.
3. Set only the scanner NIC's DNS to the controller's private IP, reboot, and run `Join` with a CMS-encrypted domain-administrator credential addressed to the scanner certificate. Reboot and confirm the secure channel. Domain administrators must not be used as the scanner service account.
4. Generate a storage **Kerberos** key and deliver it in a CMS envelope to `StorageIdentity` on the controller. This creates the `azfilesdemo` AD computer/SPN with AES-256. Apply its returned domain GUID/SIDs and computer-account metadata to Azure Files AD DS authentication. Keep public networking/shared-key data access disabled and the default share permission `StorageFileDataSmbShareReader`. This Reader default permits AD-only identities; NTFS ACLs restrict which identities actually read the files.
5. Use the operator helper below for ACL bootstrap, then `Migrate` with the encrypted service envelope. It preserves the cluster/database, changes the scanner service account, backs up imported configuration, and explicitly replaces the **local** job with offline/manual discovery of this UNC. This does not delete a portal job or any files. `Authenticate` uses the selected VM managed identity only to retrieve the approved app secret from Key Vault, then runs `Set-Authentication -OnBehalfOf` in a temporary elevated worker under the qualified domain account. This creates the correct domain profile and configures authentication for the service logon, not just the interactive worker. Use the dedicated scanner app registration, not an Exchange administration app.
6. Run `StartDiscovery`. Its service-account worker checks every fixture ACL, reads every file, verifies write denial, starts the actual scanner service, and requires a completed, fresh summary plus detailed reports covering every UNC file with zero failures. An already active cycle is rejected; only explicitly supplied `StopExistingScan=On` cancels it before a reset scan. Cancellation may take several configuration-poll cycles. Temporary local administrator membership used for scanner management is removed in `finally`; it is not an Azure Files administrative grant.

Use the normal file hostname, not its private IP:

```text
\\stscannerdemod12f.file.core.windows.net\scanner-demo\fixtures
```

The `Az-Demo` portal cluster must already exist. The approved offline lab job is
local configuration; it does not populate an empty online portal job. To return
to online configuration, first assign a discovery-only portal job and this UNC
repository, then deliberately switch modes. Content inspection
(`LabelFilesByContent On`) is enabled, but enforcement, relabeling and default
label enforcement remain Off. `Enforce Off` prevents label writes. DLP evaluation
remains Off unless an on-premises scanner DLP policy is configured.

The earlier General-only lab report was not a content-detection success:
`LabelFilesByContent Off` disabled inspection. Use `DiscoverInformationTypes All`
with content inspection On, then inspect the detailed report's `Information Type
Name` and `Condition Name` columns. A proposed `Applied Label` in a discovery
report is not a label written to disk. Cloud Exchange/SharePoint/OneDrive
auto-label policies do not supply scanner label conditions; those conditions
must be configured and independently validated before enforcement approval.

### Bootstrap restrictive NTFS permissions without storage keys

An SMB Elevated Contributor share permission does not override an existing NTFS
DACL. The operator helper uses private **FilesREST OAuth backup semantics** with
a temporary `Storage File Data Privileged Contributor` grant to the scanner VM's
selected managed identity. The grant uses
`.../fileServices/default/fileshares/<share>`: `fileshares`, **not** the ARM
management resource's `shares` spelling. See
[OAuth authorization](https://learn.microsoft.com/azure/storage/files/authorize-oauth-rest).

```powershell
.\extensions\scanner\scripts\Set-ScannerAdLabFilePermissions.ps1 `
    -SubscriptionId '<subscription-id>' `
    -StorageResourceGroup '<existing-demo-storage-resource-group>' `
    -ScannerResourceGroup '<scanner-resource-group>' `
    -ScannerVmName '<domain-joined-scanner-vm>' `
    -StorageAccountName 'stscannerdemod12f' -ShareName 'scanner-demo' `
    -IdentityClientId '<scanner-uami-client-id>' `
    -IdentityPrincipalId '<scanner-uami-object-id>'
```

The helper preserves existing grants and removes only its new assignment in
`finally`, including on guest failure. RBAC propagation can delay authorization;
failure is surfaced, not accepted as successful setup. The guest backs up original
SDDL once, retains a validated path inventory for retries, and applies protected
ACLs to the share root and every fixture: scanner Read/Execute, Domain Admins and
SYSTEM Full Control, no broad Users/Authenticated Users grant. It preserves file
attributes/timestamps and does not enable public networking or shared-key access.
Do not leave temporary privileged roles behind after an interrupted operation.

### Credentials, evidence, and recovery

Restricted state is under `C:\ProgramData\PurviewIPAsCode-AdLab`, with access only
for SYSTEM/local administrators. Transported credentials are CMS encrypted to
nonexportable receiver certificates; stored service/DSRM passwords are
machine-DPAPI protected. Do not print/export credentials, place them in command
lines, or copy token caches between Windows profiles. Keep an approved recovery
backup of the controller and its AD data disk: loss of the VM/DPAPI context can
make these lab secrets unrecoverable. No backup service is installed by this
workflow.

`scan-result.json` records the exact UNC, service identity, fresh reports, file
coverage and read-only checks. Reports are in the domain service account's
`%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports`. `Stage=Status` surfaces the worker
log/result. Successful discovery is **not** validation of expected sensitive
information types; compare detections with the fixture manifest separately.
Migration invalidates the previous bootstrap `readiness.json` discovery result.
Only successful report-backed discovery updates it with the new domain account,
UNC, report paths and read-only checks. `PersistDiscovery` can repeat that
publication from protected evidence after checking the current service identity and
report freshness; it does not run a scan. `VerifyDiscovery` repeats service-account
ACL/read/no-write and completed-report checks against the recorded scan request
without triggering another scan. Readiness records the completed scan outcome,
not a guessed current cluster status. An old local-repository report must not
be treated as proof of a new UNC scan.

The workday schedule still shuts down both lab VMs; DNS/domain services are
unavailable while the controller is deallocated. After startup, verify AD DNS and
the scanner secure channel before restarting `MIPScanner` and requesting a scan.
Do not restore broad share write access merely to work around startup/authentication
failures. Retain the old local service identity and database until recovery is
reviewed.

## Network, recovery and teardown

Both subnets have an NSG. Storage and Key Vault use private endpoints/DNS and disable public access. There is no public IP or inbound RDP/SMB rule. Outbound HTTPS is needed for approved packages and Microsoft services. The Azure Files share is provisioned but not mounted or populated by this bootstrap.

Subnets are declared inline to preserve them on VNet redeployment; do not delete a resource group merely to update the scanner. Review ARM what-if before changes. A deleted purge-protected Key Vault name cannot simply be reused: recover it according to organizational procedures or choose a new `labName`.

After an extension failure, inspect worker output, readiness, and local scanner events before retrying the verified bootstrap. Correcting the node via Run Command does not retroactively change a failed ARM deployment record. Preserve sanitized evidence and then delete only the exact dedicated resource group after confirming it contains no unrelated resources. Compute, disks, private endpoints, storage and Key Vault remain billable until teardown.

Reference: [Set-ScannerDatabase](https://learn.microsoft.com/powershell/module/purviewinformationprotection/set-scannerdatabase?view=azureipps).
