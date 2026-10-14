# Release notes

## Unreleased

- Adds source-defined label-level automatic SSN tiers and OR-based BCSI conditions, with inventory-backed deployment, private backups, semantic read-back checks and drift reporting. Preserves the separate Exchange Do Not Forward service policy.
- Adds Groups & sites scopes, private Confidential containers with existing-guest SharePoint sharing, and private Highly Confidential/BES containers with guests and external sharing blocked. Preserves existing extra scopes and low-tier container settings; no existing site or team is relabeled.
- Adds saved certificate-authenticated PowerShell deployment and label synchronization; deployment credentials remain outside the repository and GitHub.

- Corrects scanner discovery to enable content inspection (`LabelFilesByContent On`) while retaining `Enforce Off`; the previous Off setting bypassed inspection and produced General-only proposals. Disables DLP evaluation by default until an on-premises scanner DLP policy exists. Discovery guards accept explicit runtime booleans but reject missing enforcement or disabled inspection.
- Keeps completed AD scan evidence bounded by reading summary text as a plain CLR string, avoiding Windows PowerShell provider metadata serialization.
- Adds supported scanner policy-cache refresh through the qualified domain worker, native BCSI report assertions and persisted evidence. Resets file scan state separately from downloaded label policy.
- Corrects the access-procedure detector's title-case primary match in SIT package 1.0.0.1 and removes the local runner's implicit case-insensitive override. Uses explicit noninteractive confirmation for package updates inside guarded write blocks.
- The private AD-authenticated Azure Files lab scan on 2026-10-14 at 23:09 UTC read all 29 fixtures with zero failures: 12 reported BCSI matches and BES proposals. All nine detector/format positives (three SITs in TXT, DOCX and PDF) and four negative controls passed native report checks. Enforcement remains Off, access remains write-denied, and no labels were written. PII detections, manual-label preservation and actual enforcement remain unvalidated.
- Adds an optional `corp.tiny.local` IaaS AD DS lab workflow with a dedicated uncached AD data disk, encrypted credential transport, AES-256 Azure Files authentication, domain scanner-account migration, and explicitly offline/manual discovery. No Entra Connect or Cloud Sync is installed.
- Bootstraps restrictive Azure Files ACLs through keyless FilesREST with a temporary share-scoped privileged grant and cleanup. Discovery requires service-account read/no-write checks, validated ACLs and fresh reports covering every UNC fixture; expected SIT detections remain a separate validation.
- Adds an optional private, unpromoted tiny Windows VM template and `start-stop=workday` tags for new lab VMs. Documents existing-scheduler prerequisites and domain-controller disk/startup requirements; beta.1 assets remain unchanged.
- Adds a read-only scanner SMB logon-session diagnostic. Documents current managed-identity SMB support and the unimplemented scanner-service ticket refresh integration; does not claim a successful administrative mount grants scanner access.
- Adds a standalone private endpoint/DNS connection template for an existing Azure Files account and exact-IP DNS/TCP 445 verification on the scanner VM. This does not configure SMB authentication or alter beta release assets.
- Consolidates nine service-side auto-label policies into four, preserving configured locations, SSN 1-199/200+ tiers, BES precedence, and Exchange Do Not Forward. Each policy still applies one fixed label. Purview requires single-workload rules; all three configured workloads produce 15 rules within those four policies.
- Adds multi-workload definitions and a guarded, backup-first retirement helper for inventory-owned legacy simulation policies. Normal apply remains non-destructive; activation remains separately gated.
- The published `v1.0.0-beta.1` tag and assets remain unchanged.

## v1.0.0-beta.1

First beta of the repository and scanner add-on. Not production-ready.

- Includes the live-tenant label/SIT/auto-label simulation reconciliation fixes developed during lab deployment. Publishing remains a manual operation outside the adapter's supported audience contract; auto-label activation remains separately gated.
- Requires an explicit existing Purview portal cluster and defaults to online configuration. Portal cluster/job creation is a prerequisite, not an ARM side effect. `Connect-ScannerCluster.ps1` reconnects an installed node without reinstalling the VM.
- Adds the pinned Microsoft VC++ runtime prerequisite, managed-identity client selection, role-assignment dependencies, temporary elevated service worker, NSGs on both subnets, and inline subnet declarations for redeployment.
- Disables storage shared-key access and removes the unused storage-key operator grant. Azure Files infrastructure is provisioned, but beta discovery reads local fixtures.
- Requires fresh, successful summary/detailed reports covering every fixture before declaring discovery complete; idle status alone is insufficient. Clears stale failure diagnostics only after successful discovery.
- Produces deterministic fixture ZIPs and hash-pinned release assets. Prerelease tags are published as GitHub prereleases.

### Lab evidence and limitations

The initial disconnected lab scanned 30 files (28 synthetic documents plus the manifest and marker) with zero failures and no labeling/protection changes. All were classified as General; expected sensitive-information detections were **not validated**, and the cause was not established. The beta stores metadata outside the scanned directory.

The existing node was subsequently configured for cluster `Az-Demo`, online configuration, and database `AIPScannerUL_Az-Demo`. Local configuration and a running service were confirmed. Portal node visibility and a new online scan require an assigned discovery-only job and repository; the cluster initially returned no repositories. Previous offline reports do not validate that online job.

The original ARM deployment record failed during bootstrap; later node recovery does not retroactively change that record. No clean end-to-end redeployment of this beta is claimed. Enforcement, scanner label-condition mapping, identity-based Azure Files SMB, manual-label preservation, tenant propagation, and production accuracy remain outside the verified beta outcome.
