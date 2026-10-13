# Release notes

## Unreleased

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
