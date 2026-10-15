[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ReadinessPath = 'C:\ProgramData\PurviewIPAsCode\readiness.json',
    [Parameter(Mandatory)][string]$ApprovalRecordPath,
    [string]$DetectionEvidencePath = 'C:\ProgramData\PurviewIPAsCode-AdLab\bcsi-native-evidence.json',
    [string]$ClusterName = 'Az-Demo',
    [ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName = 'stscannerdemod12f',
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$ShareName = 'scanner-demo',
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$readiness = Get-Content -LiteralPath $ReadinessPath -Raw -Encoding utf8 | ConvertFrom-Json
$repository = "\\$StorageAccountName.file.core.windows.net\$ShareName\fixtures"
if ([string]$readiness.repositoryPath -ine $repository) {
    throw 'Readiness belongs to a different fixture repository.'
}
if (-not (Test-Path -LiteralPath $ApprovalRecordPath -PathType Leaf)) {
    throw 'Protection activation requires a reviewed, explicit approval record.'
}
$approval = Get-Content -LiteralPath $ApprovalRecordPath -Raw -Encoding utf8 | ConvertFrom-Json
if ($approval.approved -ne $true -or -not $approval.approvedBy -or -not $approval.discoveryRunId) {
    throw 'Approval record must contain approved=true, approvedBy, and discoveryRunId.'
}
$evidence = [IO.File]::ReadAllText($DetectionEvidencePath) | ConvertFrom-Json
if ($evidence.BcsiDetectionsValidated -ne $true -or $evidence.BcsiPositiveCount -ne 9 -or
    $evidence.EnforcementEnabled -ne $false -or
    [string]$approval.discoveryRunId -ne [string]$evidence.ScanEndedAtUtc -or
    [string]$approval.repository -ine $repository -or [string]$approval.cluster -cne $ClusterName) {
    throw 'Approval must name this cluster/repository and the verified nine-positive native discovery evidence.'
}
if ($Apply -and $PSCmdlet.ShouldProcess($repository, 'Run the approved portal-managed labeling job; keep manual-label preservation and relabel/downgrade gates')) {
    & (Join-Path $PSScriptRoot 'Invoke-ScannerAdLab.ps1') -Stage StartEnforcement -ClusterName $ClusterName -StorageAccountName $StorageAccountName -ShareName $ShareName
}
else {
    [pscustomobject]@{ Repository=$repository; Cluster=$ClusterName; ApprovedDiscovery=$approval.discoveryRunId; Applied=$false }
}
