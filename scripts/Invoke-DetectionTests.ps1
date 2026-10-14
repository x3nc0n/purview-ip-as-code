[CmdletBinding()]
param([string]$ManifestPath = 'demo\manifests\fixtures.json')

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = if ([System.IO.Path]::IsPathRooted($ManifestPath)) { $ManifestPath } else { Join-Path $root $ManifestPath }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json
$detection = Get-Content -LiteralPath (Join-Path $root 'config\detection.json') -Raw -Encoding utf8 | ConvertFrom-Json
$failures = [System.Collections.Generic.List[string]]::new()
$results = foreach ($fixture in $manifest.fixtures) {
    $textPath = Join-Path $root $fixture.extractedTextPath
    $text = Get-Content -LiteralPath $textPath -Raw -Encoding utf8
    $matchedDetector = $null
    $matchedConfidence = 0
    foreach ($detector in $detection.detectors) {
        foreach ($pattern in $detector.patterns | Sort-Object confidence -Descending) {
            $primaryMatches = [regex]::Matches($text, $pattern.primaryRegex, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if ($primaryMatches.Count -eq 0) { continue }
            $satisfied = $true
            foreach ($support in $pattern.supportRegexes) {
                $nearby = $false
                foreach ($primary in $primaryMatches) {
                    $start = [Math]::Max(0, $primary.Index - 300)
                    $length = [Math]::Min($text.Length - $start, $primary.Length + 600)
                    if ([regex]::IsMatch($text.Substring($start, $length), $support, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
                        $nearby = $true
                        break
                    }
                }
                if (-not $nearby) {
                    $satisfied = $false
                    break
                }
            }
            if ($satisfied) {
                $matchedDetector = $detector.key
                $matchedConfidence = [int]$pattern.confidence
                break
            }
        }
        if ($matchedDetector) { break }
    }
    $ssnCount = [regex]::Matches($text, '\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b').Count
    $actualLabel = 'none'
    if ($matchedConfidence -ge 85) {
        $actualLabel = 'highly-confidential-bes'
    }
    elseif ($ssnCount -gt 0 -and $ssnCount -lt 200) {
        $actualLabel = 'confidential-internal'
    }
    elseif ($ssnCount -ge 200) {
        $actualLabel = if ($fixture.workload -eq 'Exchange') { 'highly-confidential-recipients' } else { 'highly-confidential-internal' }
    }
    if ($fixture.expectedLabel -ne $actualLabel) {
        $failures.Add("$($fixture.id): expected $($fixture.expectedLabel), got $actualLabel")
    }
    if ($fixture.expectedSsnOccurrences -ne $ssnCount) {
        $failures.Add("$($fixture.id): expected $($fixture.expectedSsnOccurrences) local SSN-like occurrences, got $ssnCount")
    }
    [pscustomobject]@{
        Id = $fixture.id
        Detector = $matchedDetector
        Confidence = $matchedConfidence
        LocalSsnOccurrences = $ssnCount
        ExpectedLabel = $fixture.expectedLabel
        LocalLabel = $actualLabel
        PurviewObservation = $fixture.observedPurviewCount
        Status = if ($fixture.expectedLabel -eq $actualLabel -and $fixture.expectedSsnOccurrences -eq $ssnCount) { 'Pass' } else { 'Fail' }
    }
}
$results | Format-Table -AutoSize
Write-Warning 'These are local fixture-pattern checks, not observed Microsoft Purview SIT confidence or occurrence counts.'
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
