# Operations and recovery

## Local checks

Run the commands in the root README. `Test-Configuration.ps1` validates contracts; `Build-RulePackage.ps1` compiles the custom SIT XML; `Invoke-DetectionTests.ps1` evaluates only the local fixture expectations; and `Get-DeploymentPlan.ps1` renders intended operations. CI does not authenticate to Microsoft 365 or Azure.

## Service-side adapter

`Invoke-PurviewDeployment` is plan-only by default. Its `-Apply` path intentionally fails before tenant mutation until publishing-policy and independent auto-label-rule reconciliation, ownership recovery, and label-priority verification are complete. `Enable-AutoLabeling.ps1` remains blocked even with an approval file. Do not work around these gates by calling ad hoc cmdlets from CI or by treating the plan as evidence of deployment.

Drift reporting requires a connected, read-only-capable Security & Compliance session and an explicit tenant-scoped inventory. At present it covers only inventoried labels; it does not infer publishing-policy or auto-label-rule ownership from display names. `Get-DriftReport.ps1` returns a PowerShell object and can write JSON to a file when `-OutputPath` is supplied.

## Scanner states

The bootstrap writes `C:\ProgramData\PurviewIPAsCode\readiness.json`, containing separate `azureProvisioned`, `softwareInstalled`, `tenantConnected`, `demoContentSeeded`, `discoveryComplete`, `enforcementEnabled`, `scannerLabelConditionsSupported`, and `readyForEnforcement` fields. A `diagnosticCode` identifies the failed stage without copying secret values or scanned content. Readiness is never inferred from VM provisioning alone.

The scanner's intended content-scan settings are explicitly `Enforce Off`, `LabelFilesByContent Off`, `RelabelFiles Off`, and `EnforceDefaultLabel Off`; its scan is a bounded discovery run on synthetic fixtures. The bootstrap fails if runtime cmdlet parameters or status fields differ from the verified contract, the app authentication is unsupported, private SMB/DNS checks fail, a package hash/signature is wrong, content destination is nonempty/unowned, or no actual scan completes. Inspect Windows event logs and scanner logs locally; do not copy document content or credentials into issues/logs.

The Azure deployment workflow requires a manual dispatch, an existing resource group, OIDC, environment credentials, and human approval. Tear down only after preserving the readiness report and reviewing resource contents. Delete the resource group only after confirming the exact name, no retained lab data, and no unrelated resources. Soft delete and purge protection mean the Key Vault may remain recoverable after resource deletion; follow the organization's retention and purge controls.
