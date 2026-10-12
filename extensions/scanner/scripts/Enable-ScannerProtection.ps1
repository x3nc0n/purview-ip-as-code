[CmdletBinding()]
param(
    [string]$ReadinessPath = 'C:\ProgramData\PurviewIPAsCode\readiness.json',
    [Parameter(Mandatory)][string]$ApprovalRecordPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$readiness = Get-Content -LiteralPath $ReadinessPath -Raw -Encoding utf8 | ConvertFrom-Json
if (-not $readiness.discoveryComplete) {
    throw 'Protection activation is blocked until an actual scanner discovery cycle completes.'
}
if (-not $readiness.scannerLabelConditionsSupported) {
    throw 'Protection activation is blocked: no verified label-level BCSI/PII condition adapter is available. Enforcement and relabeling were not changed.'
}
if (-not (Test-Path -LiteralPath $ApprovalRecordPath -PathType Leaf)) {
    throw 'Protection activation requires a reviewed, explicit approval record.'
}
$approval = Get-Content -LiteralPath $ApprovalRecordPath -Raw -Encoding utf8 | ConvertFrom-Json
if ($approval.approved -ne $true -or -not $approval.approvedBy -or -not $approval.discoveryRunId) {
    throw 'Approval record must contain approved=true, approvedBy, and discoveryRunId.'
}
throw 'Activation remains blocked until manual-label preservation, allowed relabel behavior, and protection outcomes are demonstrated with tenant evidence.'
