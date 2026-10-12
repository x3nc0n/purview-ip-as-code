# Protection gaps and non-goals

- No service-side deployment or scanner label enforcement is currently enabled by this repository.
- Scanner discovery is not equivalent to applying labels. The documented scanner cmdlet surface available to this project does not expose a verified writer for the BCSI/PII condition-to-label mapping. Bootstrap records `scannerLabelConditionsSupported=false` and never changes that setting to true.
- The service adapter does not yet reconcile publishing-policy audiences, independent auto-label policies/rules, full stable SIT package ownership, or label priority. `-Apply` is blocked before any live write.
- The scanner does not prove whether manual labels are preserved, overridden, downgraded, or protected from relabeling. `Enable-ScannerProtection.ps1` blocks activation even if a generic approval record exists.
- A label, encryption setting, `Do Not Forward`, or scanner does not replace access control, DLP response, identity governance, incident procedures, backups, or engineering controls. Recipients can photograph, copy, retype, or otherwise disclose viewed information.
- Tenant licensing, app-registration consent, delegated identity entitlements, Purview client compatibility, scan classification accuracy, and live cloud prerequisites remain unverified.
- Custom regexes and the synthetic fixture runner are illustrative, not certified detectors. Counts are fictional and count repeated SSN occurrences rather than distinct persons.
- The example makes no NERC CIP compliance determination and does not identify all forms of BCSI. Organizations must have qualified personnel determine applicability, classification, retention, and incident response.

Do not enable automatic labeling, scanner enforcement, relabeling, or broad tenant scopes until the unsupported mappings and behavior have been implemented, independently reviewed, tested against synthetic edge cases, and explicitly approved.
