[CmdletBinding()]
param(
    [string]$ScanResultPath = 'C:\ProgramData\PurviewIPAsCode-AdLab\enforcement-result.json',
    [Parameter(Mandatory)][guid]$BesLabelId,
    [guid]$ConfidentialLabelId,
    [guid]$HighlyConfidentialLabelId,
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSBoundParameters.ContainsKey('ConfidentialLabelId') -ne $PSBoundParameters.ContainsKey('HighlyConfidentialLabelId')) {
    throw 'Supply both Internal Only label IDs to verify PII tiers.'
}
$result = [IO.File]::ReadAllText($ScanResultPath) | ConvertFrom-Json
if ($result.EnforcementEnabled -ne $true -or $result.ScannerWriteDenied -ne $false -or
    $result.RestrictiveAclsValidated -ne $true) {
    throw 'A writable, ACL-verified enforcement scan is required, not discovery proposals.'
}
$rows = @(Import-Csv -LiteralPath $result.DetailedReportPath)
$invalid = @($rows | Where-Object {
    $_.Status -ne 'Success' -and -not ($_.Status -eq 'Skipped' -and
        $_.Comment -eq 'No label or action to apply' -and -not $_.'Applied Label ID')
})
if ($rows.Count -ne $result.FixtureCount -or $invalid.Count) {
    throw 'The enforcement report must cover every fixture successfully.'
}
$statuses = [IO.File]::ReadAllText($result.FileStatusPath) | ConvertFrom-Json
$observations = foreach ($base in 'bcsi-explicit', 'bcsi-network', 'bcsi-access') {
    foreach ($extension in 'txt', 'docx', 'pdf') {
        $name = "$base.$extension"
        $report = @($rows | Where-Object { [IO.Path]::GetFileName($_.'File Name') -eq $name })
        $pattern = if ($extension -eq 'txt') {
            '^' + [regex]::Escape($base) + '\.(?:txt|ptxt|txt\.pfile|pfile)$'
        } else { '^' + [regex]::Escape($name) + '$' }
        $status = @($statuses | Where-Object { [IO.Path]::GetFileName($_.FileName) -match $pattern })
        if ($report.Count -ne 1 -or $status.Count -ne 1) { throw "Missing unique report and persisted file metadata for '$name'." }
        $persistedId = if ($status[0].SubLabelId -and [guid]$status[0].SubLabelId -ne [guid]::Empty) {
            [string]$status[0].SubLabelId
        } else { [string]$status[0].MainLabelId }
        if ($status[0].IsLabeled -ne $true -or $status[0].IsRMSProtected -ne $true -or
            $persistedId -ne [string]$BesLabelId -or [string]$report[0].'Applied Label ID' -ne [string]$BesLabelId) {
            throw "File '$name' does not confirm actual persisted BES labeling and Rights Management protection."
        }
        [pscustomobject]@{ Fixture=$name; ActualFile=$status[0].FileName; LabelId=$persistedId; IsProtected=$true }
    }
}
$persistedBes = @($statuses | Where-Object { $_.IsLabeled -eq $true -and $_.IsRMSProtected -eq $true -and [string]$_.SubLabelId -eq [string]$BesLabelId })
$reportedBes = @($rows | Where-Object { [string]$_.'Applied Label ID' -eq [string]$BesLabelId })
if ($persistedBes.Count -ne $reportedBes.Count) { throw 'Persisted protected BES count differs from the enforcement report.' }
foreach ($name in 'control-public-standard.txt', 'control-isolated-address.txt', 'control-generic-scada.txt', 'control-generic-credential.txt') {
    $control = @($statuses | Where-Object { [IO.Path]::GetFileName($_.FileName) -eq $name })
    if ($control.Count -ne 1 -or [string]$control[0].SubLabelId -eq [string]$BesLabelId) {
        throw "BCSI negative control '$name' is missing or incorrectly labeled BES."
    }
}
$pii = @()
if ($PSBoundParameters.ContainsKey('ConfidentialLabelId')) {
    $pii = @(foreach ($fixture in @(
        @{ Name='pii-spo-1'; Id=$ConfidentialLabelId; Formats=@('txt','docx','pdf') }
        @{ Name='pii-spo-198'; Id=$ConfidentialLabelId; Formats=@('txt') }
        @{ Name='pii-spo-199'; Id=$ConfidentialLabelId; Formats=@('txt') }
        @{ Name='pii-spo-200'; Id=$HighlyConfidentialLabelId; Formats=@('txt','docx','pdf') }
        @{ Name='pii-spo-201'; Id=$HighlyConfidentialLabelId; Formats=@('txt') }
        @{ Name='pii-spo-250'; Id=$HighlyConfidentialLabelId; Formats=@('txt') }
        @{ Name='pii-exchange-200'; Id=$HighlyConfidentialLabelId; Formats=@('txt') }
    )) {
        foreach ($extension in $fixture.Formats) {
            $name = "$($fixture.Name).$extension"
            $actual = if ($extension -eq 'txt') { "$($fixture.Name).ptxt" } else { $name }
            $report = @($rows | Where-Object { [IO.Path]::GetFileName($_.'File Name') -eq $name })
            $status = @($statuses | Where-Object { [IO.Path]::GetFileName($_.FileName) -eq $actual })
            if ($report.Count -ne 1 -or $status.Count -ne 1 -or $report[0].Status -ne 'Success' -or
                [string]$report[0].'Applied Label ID' -ne [string]$fixture.Id -or
                [string]$status[0].SubLabelId -ne [string]$fixture.Id -or
                $status[0].IsLabeled -ne $true -or $status[0].IsRMSProtected -ne $true) {
                throw "PII fixture '$name' does not confirm its expected persisted Internal Only tier and protection."
            }
            [pscustomobject]@{ Fixture=$name; ActualFile=$status[0].FileName; LabelId=[string]$fixture.Id; IsProtected=$true }
        }
    })
}
$evidence = [pscustomobject]@{
    ScanEndedAtUtc=$result.ScanEndedAtUtc; Repository=$result.Repository
    ReportRowCount=$rows.Count; BesWritesValidated=$observations.Count
    PersistedBesProtectedCount=$persistedBes.Count; NegativeControlsValidated=4
    PiiWritesValidated=$pii.Count; PiiObservations=$pii
    LabelWritesValidated=$true; Observations=@($observations)
}
$json = $evidence | ConvertTo-Json -Depth 5
if ($EvidencePath) { [IO.File]::WriteAllText($EvidencePath, $json) }
$json
