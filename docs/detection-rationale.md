# Detection rationale and test corpus

## BCSI contextual detectors

Three custom detectors cover a BCSI designation, network/security configuration, and access procedures. Each has 65, 75, and 85 confidence patterns; the high-confidence policy uses only 85. A short token, hostname, port, or procedure phrase alone is not sufficient: contextual regexes use bounded 300-character proximity and supporting evidence. The local test harness checks these deterministic fixtures only; it does not execute Microsoft's classifier.

Every high-confidence BCSI match targets Highly Confidential / BES. No separate "high impact" detector exists, no BCSI rule depends on SSN results, and no policy excludes a simultaneous BCSI/PII match.

## PII counts

The fictional US SSN example counts occurrences in each individual file or Exchange item, not unique people, a mailbox, a site, a time window, or an incident. For SharePoint, OneDrive, and Exchange, 1–199 occurrences target Confidential / Internal Only. At 200 or more, files target Highly Confidential / Internal Only and Exchange targets Highly Confidential / Recipients Only with Do Not Forward. Zero occurrences do not match either PII policy. These values are training examples, not legal thresholds or Microsoft service guarantees.

`demo/generators/generate_fixtures.py` creates synthetic Office/PDF/text fixtures for contextual BCSI positives, controls, PII counts at 0, 1, 198, 199, 200, 201, and 250, duplicate occurrences, and mixed matches. Each manifest entry records intended categories, occurrence counts, and hashes. The corpus contains no actual credentials, customer data, or operational details. Re-run `scripts/Invoke-DetectionTests.ps1` for local-only fixture checks.

## Limitations

Regex fixture success does not establish SIT compilation acceptance, Purview confidence semantics, per-item counts, service propagation, rule OR/priority behavior, OCR behavior, or scanner matching. Confirm all of those in a licensed non-production tenant with reviewed synthetic content before any enforcement.
