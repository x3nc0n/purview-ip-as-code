# Operations and recovery

## Tenant-wide Microsoft 365 discovery simulations

The `diax18655663` lab overlay explicitly uses `All` for SharePoint, OneDrive and
Exchange locations. The scope setting alone does not enable enforcement. Teams channel documents are
covered through their backing SharePoint sites, including separate channel sites;
Teams chat messages are not covered by these file-labeling policies.

After connecting to Exchange Online and Security & Compliance PowerShell in the
configured tenant, use the inventory-owned simulation restart helper:

```powershell
.\scripts\Start-CloudDiscoverySimulation.ps1 `
  -EnvironmentPath config\environments\diax18655663.json `
  -BackupPath .purview-state\cloud-discovery-before.xml
# Review the plan, then repeat with -Apply. Use a fresh backup path for each run.
```

The helper verifies tenant identity, policy GUIDs/names and simulation-only mode,
rejects scheduled automatic enforcement and file-location exclusions, backs up
live policies, reconciles configured workloads to `All`, reads back scopes and
requests fresh simulations with `StartSimulation=$true`. A successful request
is not proof of completed scanning or matching documents. On a partial failure,
inspect the backup and live policies before retrying with a new backup path.

In Purview, open **Information Protection > Policies > Auto-labeling policies**,
select a `Purview IP as code` policy and inspect its simulation results and
matched items. Allow service-side indexing and simulation processing; results
are asynchronous and can take days. Content explorer classification can lag
separately. Simulation does not apply labels or guarantee immediate Activity
explorer events. Exchange rules evaluate email in transit; restarting a
simulation is not an on-demand historical scan of every mailbox. There is no
single universal scan covering all Microsoft 365 asset types.

### Lab enforcement enabled on 2026-10-15

At the operator's explicit request to apply labels immediately, all four
inventory-owned policies were switched to `Mode=Enable`. Read-back confirmed
`OverwriteLabel=False` and tenant-wide locations for each configured workload;
all 15 managed rules matched source before completing activation. Policy names
still contain `(simulation)` for stable ownership matching: inspect **Mode**,
not the display name, to determine whether enforcement is active.

This was an explicitly authorized lab activation, not approval of completed
simulation results. Simulation completion and runtime manual-label preservation
were not attested or fabricated. The normal approval-record activation helper
and its safeguards remain unchanged. The private inventory now records `Enable`
so subsequent reconciliation preserves enforcement. The simulation-restart
helper intentionally refuses these active policies.

BCSI matches target Highly Confidential/BES; 1-199 SSN matches target
Confidential/Internal Only; 200+ SSN file matches target Highly
Confidential/Internal Only. Exchange 200+ retains Recipients Only / Do Not
Forward. Matching files are processed asynchronously after policy distribution;
activation read-back is not proof that the newly uploaded files already have
persisted labels. Distribution was still Pending at activation. Benign no-match
files should remain unlabeled. No blanket label was applied to the uploaded batch.

For historical SharePoint/OneDrive content, use **Information Protection >
Classifiers > On-demand classification**. Review scope, classifiers, file dates
and estimated charges, then select **Start classification** after estimation.
This is not a simulation restart: refreshed classifications can trigger active
labeling policies. Teams channel files are covered through SharePoint, not
Teams chat messages or historical Exchange mail. Treat ODC results, persisted
labels, encryption and user access as separate evidence.

## BES access demo: owner rights and denial tests

### Who can open a protected file?

The BES label's fixed grant is the overlay's `bes-authorized` mail-enabled
security group with `VIEW, EDIT, PRINT, EXPORT`. It is not a guarantee that every
nonmember is denied: the **Rights Management owner/issuer** and authorized RMS
super users have independent rights. For SharePoint/OneDrive service-side
auto-labeling, Microsoft assigns owner/issuer to the account that last modified
the file when protection is applied. This is not the site's owner, its group
owner, the Windows file owner or simply whoever starts ODC.

The administrator uploaded the cloud demo batch. A 2026-10-16 membership check
found the BES group empty and the administrator absent from its transitive
membership; the live label action had `disableautomaticownerrights=False`.
That administrator opening a sample is consistent with protection-owner access,
not proof of a group-access failure. The particular cloud file's encryption and
owner metadata were not independently verified by that check. Membership and
effective rights can change; recheck them for each demo. The adapter does not
explicitly manage `DisableAutomaticOwnerRights`; inspect live settings rather
than assuming a source-controlled value for that switch.

Global Administrator status alone does not grant automatic decryption. RMS
super-user configuration is a separate, privileged recovery mechanism; do not
enable it or change group membership merely to make a test pass. A group grant
also does not provide a SharePoint link or SMB read permission. Repository
authorization and Rights Management authorization are separate gates.

`EXPORT` permits an authorized BES recipient to remove protection; these are
editable demo permissions, not a view-only or non-exportable design. Do not
promise prevention of copying, printing or redistribution. Removing a user
from the group is not a deterministic immediate-revocation test because cached
use licenses, offline rights and existing unprotected copies can affect results.

### Before presenting the demo

Record the exact file URL, label GUID, encryption state, protection owner/issuer,
last modifier, group membership, client identity and test time in private
evidence. Last-modifier metadata is context, not proof of protection ownership
after later edits. Use a supported client/protection inspection method to
confirm the file's own protection state; label configuration alone is not enough.
These read-only commands inspect group grants and live label actions after
connecting to the target tenant's Exchange Online and Security & Compliance:

```powershell
$environment = Get-Content -LiteralPath 'config\environments\<tenant>.json' -Raw | ConvertFrom-Json
$inventory = Get-Content -LiteralPath '<private-managed-inventory.json>' -Raw | ConvertFrom-Json
$group = $environment.groups | Where-Object key -eq 'bes-authorized'
Get-DistributionGroupMember -Identity $group.email -ResultSize Unlimited |
    Select-Object DisplayName, PrimarySmtpAddress, RecipientType
$bes = Get-Label -Identity $inventory.labels.'highly-confidential-bes'
$bes.LabelActions | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object Type -eq 'encrypt' | Select-Object -ExpandProperty Settings
```

Group output shows direct members; resolve nested membership separately through
Entra transitive membership. An empty group is not a usable allowed-reader setup.
Review intended demo users with the operator before changing membership. Inspect
`disabled`, `rightsdefinitions` and `disableautomaticownerrights` in label
actions: individual `Encryption*` properties can be blank even when the serialized
encryption action is configured. Do not interpret those blanks as encryption Off.

### Access test matrix

Use distinct, already-approved test accounts and the same protected document.
Both reader accounts must have baseline access to the library/share; otherwise
a storage-layer denial does not prove encryption enforcement. Neither reader
may be the protection owner/issuer or an RMS super user. Do not use the uploader
as the denied reader. Run each reader in a separate signed-in browser profile
or clean supported Office client session and confirm the active account.

| Identity | Expected result | What it demonstrates |
| --- | --- | --- |
| Uploader/last modifier, confirmed as protection owner | Can open despite no BES membership when owner rights apply | Owner exception, not a group test |
| BES member, not protection owner or RMS super user | Can open with the configured rights after propagation | Positive group access |
| Nonmember, not protection owner or RMS super user | Cannot decrypt/open protected content despite baseline repository access | Negative encryption access |

First establish detection and persisted BES labeling/encryption; then attempt
both reader opens. Record the actual result/error, not just the expected result.
If an unauthorized open succeeds, check that the client opened the protected
copy, not a pristine local fixture, and inspect owner/issuer, nested groups,
explicit grants, RMS super-user status and cached sessions/licenses. If the
allowed reader fails, distinguish repository permissions, membership propagation,
client/network/Conditional Access failures and encryption authorization.
Do not weaken protection or clear shared token caches to conceal a failure.

`Test-ScannerLabelWrites.ps1` verifies label/protection metadata on the private
scanner corpus; it does **not** perform this reader-access matrix. Scanner SMB
access uses the AD service identity, while MIP protection uses the configured
delegated cloud authentication context. Do not infer protection ownership from
the NTFS owner, scanner Windows service account or Azure managed identity.
Recheck identity-specific rights for scanner-protected files separately.

`Reset-ScannerDemoFiles.ps1` only restores the private Azure Files fixtures. It
does not reset the cloud demo batch, remove cloud labels or revoke owner rights.
Recreating a cloud sample under the same uploader can recreate the same ownership
exception. Active cloud policies can label new samples asynchronously.

### Purview visibility is not a reader-access test

Classifiers show definitions and matches, not a grant to decrypt. Content
Explorer List Viewer and Content Viewer are separate roles; Global Administrator
alone does not establish those viewing permissions. Content explorer cannot
preview encrypted documents. A preview failure therefore does not establish
that the BES group denied a user, and a classifier match does not prove a label
or encryption was applied. Use the source file in a supported client for the
reader tests, without removing protection to enable portal preview.

References: [service-side auto-labeling and last-modifier ownership](https://learn.microsoft.com/en-us/purview/apply-sensitivity-label-automatically),
[Rights Management owner/issuer and usage rights](https://learn.microsoft.com/en-us/purview/rights-management-usage-rights#rights-management-issuer-and-rights-management-owner),
[RMS super users](https://learn.microsoft.com/en-us/purview/encryption-super-users),
and [Content explorer permissions and encrypted previews](https://learn.microsoft.com/en-us/purview/data-classification-content-explorer).

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
PII and manual-label behavior were not established by that discovery run.
Use `-EvidencePath` on the verifier to retain its JSON beside the protected
guest scan reports. The lab retains
`C:\ProgramData\PurviewIPAsCode-AdLab\bcsi-native-evidence.json`.

## Online lab labeling

Online configuration, enforcement and audit reporting are independent settings.
`OnlineConfiguration On` downloads the job from Purview; `Enforce On` permits
label/protection writes. Local configuration does **not** disable cloud audit.
Activity explorer receives scanner discovery and labeling events in either mode.

In **Settings > Information Protection > Information protection scanner**, use
the existing `Az-Demo` cluster and `demo-scan` job. Keep **Manual** scheduling,
all information types, content-based labeling On, recommended-as-automatic Off,
DLP Off, relabel Off, downgrade Off, default-label enforcement Off and default
label **None**. The only repository must be
`\\stscannerdemod12f.file.core.windows.net\scanner-demo\fixtures`.
Repository settings must resolve to these same values; do not assume blank
job-level PowerShell properties mean disabled repository settings.

On the scanner, run `Invoke-ScannerAdLab.ps1 -Stage Online` to switch the
existing cluster to portal-managed configuration and detailed reporting.
Keep portal enforcement Off while refreshing policy and preparing access.
The ACL administration wrapper `Set-ScannerAdLabFilePermissions.ps1` defaults
to `-FileAccess ReadOnly`; the explicitly authorized lab labeling path uses
`-FileAccess Modify`. It keeps the share-root scanner ACE read/execute and
grants Modify only to fixtures and their files. SYSTEM/domain administrators
retain FullControl; unrelated principals are not added.

The unsynchronized AD scanner identity cannot receive an Entra share-role
assignment. The wrapper therefore uses default SMB Contributor authorization,
which is **storage-account-wide**, while restrictive NTFS ACLs limit actual
write access. It refuses accounts containing any other share. This is a
dedicated lab arrangement, not a general-purpose storage-account policy.
Temporary privileged FilesREST grants are still removed after ACL setup.

`Set-ScannerPublishingSettings.ps1` is a plan-first, certificate-authenticated
launcher with explicit tenant and existing publishing-policy GUID checks.
`-Apply` backs up that policy and sets `EnableAudit=True` and
`PFileSupportedExtensions=[".txt"]`, preserving its audience and other settings.
TXT needs this scanner setting to support encryption in addition to native
Office/PDF protection. Protected TXT filenames can become `.ptxt`. Scanner SIT
matches are sent automatically; `LogMatchedContent` is not required for scanner
reporting. Do not broaden the pilot audience to fix a distribution error.
An operator can retry service-reported synchronization timeouts with
`Set-LabelPolicy -Identity <existing-policy-guid> -RetryDistribution`.

After propagation, run `RefreshPolicy` with enforcement Off, enable enforcement
in the **portal**, and wait for downloaded repository settings to reflect On.
`Enable-ScannerProtection.ps1` does not edit the portal job. It runs an explicitly
approved enforcement scan only with `-Apply`, native nine-positive discovery
evidence and an approval JSON naming `approved=true`, `approvedBy`,
`discoveryRunId` (the evidence's `ScanEndedAtUtc`), `cluster`, and `repository`.
Keep the approval and all reports private. Deploy it beside
`Invoke-ScannerAdLab.ps1` on the scanner before invoking it.

`Invoke-ScannerAdLab.ps1 -Stage StartEnforcement` provides the same strict
online/scope/configuration/ACL gates for an already-approved operator run.
It tests real SMB write access under the domain account, starts a full scan,
requires fresh successful coverage of every input file and saves
`enforcement-result.json` and `enforcement-file-status.json` in the protected
lab state directory. `VerifyEnforcement` can recover verification after a
completed scan if the administration request was interrupted.
`Test-ScannerLabelWrites.ps1 -BesLabelId <inventory BES GUID>` independently
requires the nine positive formats to have both a matching report label and
persisted `Get-FileStatus` BES metadata with Rights Management protection.
Discovery proposal counts are never accepted as label writes. Relabel/downgrade
Off is a configuration safeguard, not proof that every manual-label scenario
has been tested. It does not remove protection-owner rights or test whether a
nonmember can decrypt; use the [BES access test matrix](#access-test-matrix).
Production accuracy and clean ARM redeployment remain separate.

## Resetting the private Azure Files demo

### PII fixture correction

The original PII documents were not native high-confidence SSN test data:
`123-45-6789` produced no Microsoft classifier matches even with SSN keywords,
and the documents also lacked the required supporting keywords. Repeating one
replacement value 200 times produced a native count of **one**. The original
PDF writer additionally retained only the first 48 lines.

Generator 1.0.1 uses distinct invented values, each prefixed with **Synthetic
Social Security Number SSN**, and emits all PDF pages. Server-side
`Test-DataClassification` confirmed confidence-85 counts of 1, 199, 200 and 250
for the corrected text. No label threshold or SIT definition was weakened.
These values are invented and not linked to people; plausible SSNs cannot be
guaranteed never issued. Local tests check distinct counts/context and PDF
content, but native file extraction and actual tiered labels must still be
verified after resetting the share from the corrected commit and rescanning.
The lab did so on 2026-10-15: scan `55d163ef-5120-4c01-8ec2-f8666918c06d`
ended at 15:51:54 UTC with 29 files, **23 labels and encryptions**, zero failures
and six no-match skips. The breakdown was 12 BES, five Confidential / Internal
Only and six Highly Confidential / Internal Only. Persisted file metadata
verified all eleven PII outcomes, including the 1- and 200-record DOCX/PDFs;
BCSI positives and negative controls still passed.
Use `Test-ScannerLabelWrites.ps1` with both `-ConfidentialLabelId` and
`-HighlyConfidentialLabelId` (the inventory's Internal Only GUIDs) to repeat
these assertions; passing only `-BesLabelId` checks BCSI alone.
The Exchange fixture's service-policy expectation is Recipients Only; when
scanned as a file, the 200+ SSN condition instead selects Internal Only.

Run from a repository checkout on your administration machine, signed into Azure
CLI for the lab tenant. The scanner VM must be running, its scan must be idle,
and its job schedule must be Manual. The operator needs VM Run Command access
and permission to create/delete a temporary share-scoped role assignment.

```powershell
# Plan only; no Azure changes:
.\extensions\scanner\scripts\Reset-ScannerDemoFiles.ps1
# Preview the destructive scope:
.\extensions\scanner\scripts\Reset-ScannerDemoFiles.ps1 -Apply -WhatIf
# Reset after reviewing the confirmation:
.\extensions\scanner\scripts\Reset-ScannerDemoFiles.ps1 -Apply
```

Defaults target only
`\\stscannerdemod12f.file.core.windows.net\scanner-demo\fixtures`.
The script deletes **all files directly in that directory**, including labeled
or protected copies, and restores 28 pristine documents plus `fixtures.json`
from the checkout's committed HEAD, not potentially labeled working-tree files.
It does not remove labels from existing documents or preserve their edits.
Archive anything you want to keep before running it. Unexpected subdirectories
cause a refusal before any deletion; no recursive share/account clearing occurs.
The share, directory, inherited ACLs, private networking and snapshots are not
deleted or reconfigured.

The reset executes FilesREST inside the scanner VM using its managed identity,
temporarily granting only share-scoped privileged contributor access if needed.
Only a grant created by this invocation is removed in `finally`; existing
grants are untouched. No storage keys, public access, scanner-account elevation,
or new SMB write permission are used. The worker stops the idle scanner during
replacement, verifies every restored file byte-for-byte, invalidates old
discovery readiness, archives the previous current scan/BCSI evidence, and
restarts the service even if replacement fails. Failure can leave a partial
corpus; fix the reported error and rerun the reset. Do not start a demo scan
until the reset reports success.

The reset does not start a scan, change management mode or enable enforcement.
It is compatible with a portal-managed **Manual** job; a continuously scheduled
job is refused so that restored files remain unlabeled until requested.
For the approved online demo, run `StartEnforcement` after reset; for the
read-only offline workflow, use `StartDiscovery`. The helper supplies the
service-account context and resets the file scan cache. Old dated reports
remain historical evidence, not observations of the restored files.

## Viewing BCSI matches

In Purview, **Information Protection > Classifiers > Sensitive info types**
shows the three BCSI definitions; select one and use **Test** with a synthetic
fixture to exercise that SIT. This is not an inventory of files scanned on
Azure Files. For file-level cloud metadata, open
[Activity explorer](https://purview.microsoft.com/informationprotection/dataclassification/activityexplorer)
and set the date range around the scan. Filter for **File discovered** and
**Sensitivity label applied**, device `pipascodelab-sc.corp.tiny.local`,
application **Microsoft Purview Information Protection Scanner**, or the BES
label. Scanner events can appear under **Endpoint devices** rather than an
Azure Files location. Open an event to inspect the UNC, user/application,
sensitive-information IDs/counts/confidence, label and protection metadata.
Discovery events do not prove a label was written. Audit ingestion is not
instantaneous; retain scan timestamps and distinguish pending labeling events
from already ingested discoveries. Scanner summaries are also visible under
the portal's content scan job; those are not a per-file content inventory.
Do not expect Azure Files documents automatically to populate Content explorer.

For immediate native evidence, review the service account's
`%LOCALAPPDATA%\Microsoft\MSIP\Scanner\Reports\DetailedReport_*.csv` on the scanner
VM. Filter **Information Type Name** for BCSI and inspect **File Name** and
**Applied Label ID**. In discovery, the applied-label column is a proposal,
not a label write. See [Microsoft's scanner reporting instructions](https://learn.microsoft.com/en-us/purview/deploy-scanner-manage#run-a-discovery-cycle-and-view-reports-for-the-scanner).

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

Published beta.1 scans local fixtures, not Azure Files, and remains unchanged. Current source includes an optional private IaaS AD DS/Azure Files lab workflow with encrypted credentials, a domain scanner identity and keyless ACL setup. The optional offline discovery migration is separate from portal configuration;
use the online lab transition above for actual portal-managed labeling. Migration invalidates old readiness; fresh UNC reports, restrictive ACLs, service-account read access and write denial are required before publishing completed discovery. Expected SIT detections and enforcement remain separate, unvalidated outcomes. See [scanner operations](../extensions/scanner/README.md) for the staged workflow, cluster migration, workday startup limitations and exact commands.

The Azure deployment workflow requires a manual dispatch, an existing resource group, OIDC, environment credentials, and human approval. Tear down only after preserving the readiness report and reviewing resource contents. Delete the resource group only after confirming the exact name, no retained lab data, and no unrelated resources. Soft delete and purge protection mean the Key Vault may remain recoverable after resource deletion; follow the organization's retention and purge controls.
