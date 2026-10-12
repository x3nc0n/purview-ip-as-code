# Architecture

## Source of truth

`config/labels.json`, `config/publishing-policies.json`, `config/detection.json`, and `config/auto-labeling-policies.json` are the canonical definitions. JSON Schema and semantic PowerShell validation run offline. The custom BCSI sensitive-information types are compiled deterministically to UTF-8 XML with stable declared IDs. The XML is a package input, not proof that a tenant accepted or evaluated the rules.

Service-side detection is deliberately split into independent families. The BCSI family requires an 85-confidence match from one of three contextual custom detectors and targets only Highly Confidential / BES. The PII family uses the built-in US SSN type with per-item occurrence thresholds and does not depend on, exclude, or escalate with BCSI. If several labels qualify, the intended BCSI target is the highest-priority label; actual Purview rule and label ordering must be demonstrated in a test tenant.

The optional scanner is a separate discovery-only adapter. Its resource-group Bicep modules create a private VNet, private DNS, Azure Files private endpoint and dedicated share, Key Vault private endpoint, user-assigned managed identity, and non-Core Windows Server VM. The VM has no public IP. A protected custom-script extension verifies the released bootstrap hash; bootstrap checks pinned installer hashes and Microsoft Authenticode signatures, resumes safely after installer restart codes, and records distinct readiness fields. Scanner rules that set sensitivity labels are intentionally not written.

## Trust and mutation boundaries

- Pull-request CI runs offline schema, fixture, PowerShell, XML, and Bicep checks; it has read-only repository permissions and no Azure or Purview credential.
- Service-side apply returns a plan by default. Explicit `-Apply` currently stops before tenant writes because the complete publishing-policy/rule adapter is not implemented and verified.
- Scanner Azure deployment is never part of CI. The workflow is manual, defaults to an existing resource group, uses OIDC, and is gated by a GitHub environment that repository administrators must configure with required reviewers.
- Scanner app credentials are submitted as a secure Bicep parameter and stored in Key Vault. The VM identity can read the secret and retrieve the dedicated storage-account key. The key is retained only in the scanner service account's Windows Credential Manager profile; no key or app secret is written to bootstrap parameters or readiness output.
- The template secures storage and Key Vault behind private endpoints, disables public network access, and creates no public RDP/SMB endpoint. Outbound HTTPS is allowed for pinned vendor packages and Microsoft service connectivity.

See [scanner operations](../extensions/scanner/README.md), [protection gaps](protection-gaps.md), and [prerequisites](prerequisites.md) for operator-facing limitations.
