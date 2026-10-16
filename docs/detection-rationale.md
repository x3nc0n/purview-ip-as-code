# Detection rationale and test corpus

## BCSI contextual detectors

Three custom regex-based sensitive information types (SITs), not trainable AI
classifiers, cover a BCSI designation, network/security configuration, and access
procedures. Each has 65, 75, and 85 confidence patterns; the high-confidence
policy uses only 85. The network and access patterns require supporting evidence
within bounded 300-character proximity. The explicit 85 pattern is different:
its structured marker alone is sufficient. The local test harness checks these
deterministic fixtures only; it does not execute Microsoft's classifier.

| SIT | Required at confidence 85 |
| --- | --- |
| BCSI Explicit Designation | `BCSI: INTERNAL DEMO DESIGNATION`, permitting `:` or `=` or `-` and flexible whitespace. No supporting handling statement is required at 85. |
| BCSI Network and Security Configuration | Address beginning `192.0.2.`, `198.51.100.` or `203.0.113.`; nearby `BES`, `ESP` or `EACMS`; `firewall`, `subnet`, `topology`, `gateway` or `ACL`; and `deny`, `allow`, `ingress`, `egress` or `VLAN`. |
| BCSI Access and Security Procedures | `operator access procedure` or `access control procedure`; nearby `BES`, `ESP` or `EACMS`; `badge`, `MFA`, `authentication`, `authorization` or `jump host`; and a match for `review\w*`, `approve\w*`, `revoke\w*`, `audit\w*` or `two-person`. |

The exact expressions and case behavior are in `config\detection.json`. These
are deliberately narrow demonstration rules, not general BCSI recognition:
the explicit marker is invented and the network rule only covers documentation
address ranges. The demo disclaimer does not suppress matches.

For example, the cloud sample ending `b1-5-designation.docx` contains:

```text
BCSI: INTERNAL DEMO DESIGNATION
Handling: BES Cyber System Information
```

The first line alone meets the 85 pattern. The second line is supporting
evidence for its separate 75 pattern, not an additional 85 requirement. The
filename does not cause detection. There is no inference of real infrastructure
or legal BCSI status.

Every high-confidence BCSI match targets Highly Confidential / BES. No separate "high impact" detector exists, no BCSI rule depends on SSN results, and no policy excludes a simultaneous BCSI/PII match.

A SIT result is not a persisted label or an access-control result. Active
policies can apply BES and encryption; simulation only reports proposed
outcomes. Purview cannot preview encrypted content in Content explorer. Use the
[BES access runbook](operations.md#bes-access-demo-owner-rights-and-denial-tests)
to distinguish detection, protection-owner access and group-based reader tests.

The access-procedure primary expression explicitly uses `(?i)` so title-case
headings such as "Operator access procedure" match. Package version 1.0.0.1
corrects this mismatch. The local runner no longer implicitly makes every regex
case-insensitive: intended case behavior must be declared in the expression
exported to Purview, not supplied only by the test harness.

## PII counts

The fictional US SSN example counts occurrences in each individual file or Exchange item, not unique people, a mailbox, a site, a time window, or an incident. For SharePoint, OneDrive, and Exchange, 1–199 occurrences target Confidential / Internal Only. At 200 or more, files target Highly Confidential / Internal Only and Exchange targets Highly Confidential / Recipients Only with Do Not Forward. Zero occurrences do not match either PII policy. These values are training examples, not legal thresholds or Microsoft service guarantees.

`demo/generators/generate_fixtures.py` creates synthetic Office/PDF/text fixtures for contextual BCSI positives, controls, PII counts at 0, 1, 198, 199, 200, 201, and 250, duplicate occurrences, and mixed matches. Each manifest entry records intended categories, occurrence counts, and hashes. The corpus contains no actual credentials, customer data, or operational details. Re-run `scripts/Invoke-DetectionTests.ps1` for local-only fixture checks.

## Limitations

Regex fixture success does not establish SIT compilation acceptance, Purview confidence semantics, per-item counts, service propagation, rule OR/priority behavior, OCR behavior, or scanner matching. Confirm all of those in a licensed non-production tenant with reviewed synthetic content before any enforcement.
