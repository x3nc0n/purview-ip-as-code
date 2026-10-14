[CmdletBinding()]
param(
    [string]$ScanResultPath = 'C:\ProgramData\PurviewIPAsCode-AdLab\scan-result.json',
    [Parameter(Mandatory)][guid]$BesLabelId,
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
$result = [IO.File]::ReadAllText($ScanResultPath) | ConvertFrom-Json
if ($result.EnforcementEnabled -ne $false -or $result.ScannerWriteDenied -ne $true) {
    throw 'Detection verification expects the approved read-only discovery run.'
}
$rows = @(Import-Csv -LiteralPath $result.DetailedReportPath)
if ($rows.Count -ne $result.FixtureCount -or @($rows | Where-Object Status -ne 'Success').Count -gt 0) {
    throw 'The detailed report does not cover all fixtures successfully.'
}
$observations = foreach ($fixture in @(
    @{ Name = 'bcsi-explicit'; Sit = 'BCSI Explicit Designation' }
    @{ Name = 'bcsi-network'; Sit = 'BCSI Network and Security Configuration' }
    @{ Name = 'bcsi-access'; Sit = 'BCSI Access and Security Procedures' }
)) {
    foreach ($extension in @('txt', 'docx', 'pdf')) {
        $name = "$($fixture.Name).$extension"
        $row = @($rows | Where-Object { [IO.Path]::GetFileName($_.'File Name') -eq $name })
        if ($row.Count -ne 1) { throw "Expected exactly one report row for '$name'." }
        [pscustomobject]@{
            Fixture = $name
            ExpectedInformationType = $fixture.Sit
            InformationType = [string]$row[0].'Information Type Name'
            Condition = [string]$row[0].'Condition Name'
            ProposedLabel = [string]$row[0].'Applied Label'
            ProposedLabelId = [string]$row[0].'Applied Label ID'
            Matched = ([string]$row[0].'Information Type Name' -like "*$($fixture.Sit)*" -and
                [string]$row[0].'Applied Label ID' -eq [string]$BesLabelId)
        }
    }
}
$evidence = [pscustomobject]@{
    ScanEndedAtUtc = $result.ScanEndedAtUtc
    ReportRowCount = $rows.Count
    BcsiPositiveCount = @($observations | Where-Object Matched).Count
    BcsiExpectedCount = $observations.Count
    BcsiDetectionsValidated = (@($observations | Where-Object { -not $_.Matched }).Count -eq 0)
    EnforcementEnabled = $false
    LabelWritesValidated = $false
    Observations = @($observations)
}
$json = $evidence | ConvertTo-Json -Depth 5
if ($EvidencePath) { [IO.File]::WriteAllText($EvidencePath, $json) }
$json
if (-not $evidence.BcsiDetectionsValidated) {
    throw 'Expected BCSI native SIT detections and BES proposals were not observed for every positive fixture.'
}
